package com.r2b.app;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.List;
import java.util.Locale;

/**
 * 工具执行器：把 tools/call 真正跑出结果。
 *
 * 之前 tools/call 只转发给 Python 后端，而安卓上没有 Python，
 * 于是所有调用都返回"本端只提供工具表"——这就是"MCP 是个壳"的根因。
 *
 * 这里改为本机真实实现：
 *   - APK / DEX / ELF 解析走 NativeAnalyzer（纯 Java，零依赖，不崩）
 *   - blutter 走 exec（libblutter_*.so 是 PIE 可执行文件，不是共享库）
 *   - radare2 走 JNI 桥（libr2aibridge.so），失败则明确降级
 *   - unidbg 是 JVM jar，安卓是 ART，跑不了，明确标注不可用
 */
public final class ToolExecutor {

    private static final String TAG = "R2B_Tool";

    private final Context ctx;
    private volatile String currentApk;   // 当前选中的 APK
    private transient TermuxExecutor termux;

    public ToolExecutor(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    /** Termux 通道（懒加载，装了才用）。 */
    public synchronized TermuxExecutor termux() {
        if (termux == null) termux = new TermuxExecutor(ctx);
        return termux;
    }

    public void setCurrentApk(String p) { currentApk = p; }
    public String getCurrentApk() { return currentApk; }

    /** 引擎根目录（EngineUnpacker 释放的位置）。 */
    public static File engineRoot(Context c) {
        File f = new File(c.getFilesDir(), "engine");
        if (!f.exists()) f.mkdirs();
        return f;
    }

    /** 工作缓存目录。 */
    public File workDir() {
        File f = new File(ctx.getCacheDir(), "r2b_work");
        if (!f.exists()) f.mkdirs();
        return f;
    }

    /**
     * 执行工具。返回 JSON 字符串（MCP content.text 的内容体）。
     * 永远不抛异常：任何失败都变成带 error 字段的 JSON，便于前端展示。
     */
    public String execute(String name, JSONObject args) {
        long t0 = System.currentTimeMillis();
        Log.i(TAG, "执行工具: " + name + " 参数: " + args);
        JSONObject out = new JSONObject();
        try {
            out.put("tool", name);
            dispatch(name, args == null ? new JSONObject() : args, out);
        } catch (Exception e) {
            Log.e(TAG, "工具 " + name + " 异常", e);
            try {
                out.put("error", typeName(e) + ": " + e.getMessage());
            } catch (Exception ignored) {}
        }
        try {
            out.put("elapsed_ms", System.currentTimeMillis() - t0);
        } catch (Exception ignored) {}
        return out.toString();
    }

    private static String typeName(Throwable t) {
        String n = t.getClass().getName();
        return n.substring(n.lastIndexOf('.') + 1);
    }

    private static String opt(JSONObject a, String... keys) {
        for (String k : keys) {
            String v = a.optString(k, null);
            if (v != null && v.length() > 0) return v;
        }
        return null;
    }

    private void dispatch(String name, JSONObject a, JSONObject out) throws Exception {
        String n = name == null ? "" : name;

        // ---------- APK ----------
        if (n.equals("Apk_Open") || n.equals("Apk_Info") || n.equals("Apk_List")) {
            File apk = resolveApk(a);
            NativeAnalyzer.ApkInfo info = NativeAnalyzer.openApk(apk);
            if (info.error != null) { out.put("error", info.error); return; }
            out.put("path", info.path);
            out.put("size_bytes", info.size);
            out.put("size_mb", round(info.size / 1048576.0));
            out.put("entry_count", info.entries.size());
            out.put("dex_count", info.dexes.size());
            out.put("so_count", info.libs.size());
            out.put("archs", new JSONArray(info.archs));
            out.put("stack", detectStack(info));
            JSONArray libs = new JSONArray();
            for (String s : info.libs) libs.put(s);
            out.put("libs", libs);
            JSONArray dexes = new JSONArray();
            for (String s : info.dexes) dexes.put(s);
            out.put("dexes", dexes);
            return;
        }

        if (n.equals("Apk_Extract") || n.equals("Apk_Extract_Entry")) {
            File apk = resolveApk(a);
            String entry = opt(a, "entry", "entry_name", "path", "name");
            if (entry == null) { out.put("error", "缺少 entry 参数"); return; }
            File f = NativeAnalyzer.extractEntry(apk, entry, workDir());
            if (f == null) { out.put("error", "APK 中没有该条目: " + entry); return; }
            out.put("extracted_to", f.getAbsolutePath());
            out.put("size_bytes", f.length());
            return;
        }

        // ---------- Flutter / Blutter ----------
        if (n.startsWith("Blutter_")) {
            blutter(n, a, out);
            return;
        }

        // ---------- Unity / Il2Cpp ----------
        if (n.equals("Il2Cpp_Analyze") || n.equals("Il2Cpp_Dump")) {
            il2cpp(a, out);
            return;
        }

        // ---------- DEX ----------
        if (n.equals("Dex_Strings") || n.equals("Apk_Strings")) {
            dexStrings(a, out);
            return;
        }

        // ---------- radare2 ----------
        if (n.startsWith("R2_")) {
            r2(n, a, out);
            return;
        }

        // ---------- 文件系统 ----------
        if (n.equals("Os_List_Dir") || n.equals("Os_ListDir")) {
            String p = opt(a, "path", "dir", "directory");
            if (p == null) p = ctx.getFilesDir().getAbsolutePath();
            File dir = new File(p);
            if (!dir.exists()) { out.put("error", "目录不存在: " + p); return; }
            JSONArray arr = new JSONArray();
            File[] fs = dir.listFiles();
            if (fs != null) {
                for (File f : fs) {
                    JSONObject o = new JSONObject();
                    o.put("name", f.getName());
                    o.put("is_dir", f.isDirectory());
                    o.put("size", f.length());
                    arr.put(o);
                }
            }
            out.put("path", p);
            out.put("entries", arr);
            return;
        }

        if (n.equals("Os_File_Read") || n.equals("Os_Read_File")) {
            String p = opt(a, "path", "file");
            if (p == null) { out.put("error", "缺少 path"); return; }
            File f = new File(p);
            if (!f.isFile()) { out.put("error", "不是文件: " + p); return; }
            int limit = a.optInt("limit", 20000);
            byte[] d = NativeAnalyzer.readAll(f);
            int len = Math.min(d.length, limit);
            out.put("path", p);
            out.put("size", d.length);
            out.put("content", new String(d, 0, len, "UTF-8"));
            out.put("truncated", d.length > limit);
            return;
        }

        if (n.equals("Shell_Command") || n.equals("Os_Shell_Command")) {
            // 安卓上真的能执行 shell（受应用沙箱权限限制）
            String cmd = opt(a, "command", "cmd");
            if (cmd == null) { out.put("error", "缺少 command"); return; }
            Process pr = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            java.io.InputStream is = pr.getInputStream();
            java.io.InputStream es = pr.getErrorStream();
            String so = readStream(is, 20000);
            String se = readStream(es, 4000);
            int code = pr.waitFor();
            out.put("command", cmd);
            out.put("exit_code", code);
            out.put("stdout", so);
            out.put("stderr", se);
            out.put("executed", true);
            return;
        }

        // ---------- 引擎状态 ----------
        if (n.equals("Engine_Status") || n.equals("Engine_Inventory") || n.equals("Engine_Probe")) {
            engineStatus(out);
            return;
        }

        // ---------- 兜底 ----------
        out.put("error", "工具 " + n + " 尚未在本机实现");
        out.put("hint", hintFor(n));
        out.put("implemented", implementedList());
    }

    private String hintFor(String n) {
        if (n.startsWith("Ub_")) {
            return "Unidbg 是 JVM jar，安卓运行时是 ART，无法直接执行；"
                    + "请在桌面端 Python 后端使用，或改用 Frida 动态方案。";
        }
        if (n.startsWith("Fr_")) {
            return "Frida 需要 root 权限启动 frida-server；"
                    + "无 root 时本端只能生成 JS 脚本供你在桌面端注入。";
        }
        if (n.startsWith("R2_")) {
            return "radare2 通过 JNI 桥 libr2aibridge.so 接入，需先确认引擎已释放且架构匹配。";
        }
        if (n.startsWith("Pentest_")) {
            return "渗透类工具多数依赖 mitmproxy / 抓包能力，安卓端需配合 VPN 服务或桌面端。";
        }
        return "该工具需要桌面端 Python 后端或额外运行环境。";
    }

    private JSONArray implementedList() {
        return new JSONArray()
                .put("Apk_Open").put("Apk_Info").put("Apk_Extract")
                .put("Blutter_Analyze").put("Blutter_Strings").put("Blutter_Functions")
                .put("Blutter_Classes").put("Blutter_Info")
                .put("Il2Cpp_Analyze").put("Dex_Strings")
                .put("Os_List_Dir").put("Os_File_Read").put("Shell_Command")
                .put("Engine_Status");
    }

    // ---------- APK 解析 ----------

    private File resolveApk(JSONObject a) throws Exception {
        String p = opt(a, "apk_path", "apk", "path", "file", "file_path");
        if (p == null) p = currentApk;
        if (p == null) throw new Exception("未指定 APK，且当前没有已选择的文件");
        File f = new File(p);
        if (!f.exists()) {
            // 可能是 content:// 或 primary: 前缀，尝试常见下载目录
            File alt = tryResolve(p);
            if (alt == null || !alt.exists()) throw new Exception("文件不存在: " + p);
            f = alt;
        }
        return f;
    }

    private File tryResolve(String p) {
        String name = p;
        if (name.startsWith("primary:")) name = name.substring(8);
        int i = name.lastIndexOf('/');
        if (i >= 0) name = name.substring(i + 1);
        File[] dirs = {
            new File("/sdcard/Download"),
            new File("/sdcard/Downloads"),
            android.os.Environment.getExternalStoragePublicDirectory(
                    android.os.Environment.DIRECTORY_DOWNLOADS),
            new File("/sdcard"),
            ctx.getFilesDir(),
        };
        for (File d : dirs) {
            if (d == null) continue;
            File c = new File(d, name);
            if (c.exists()) return c;
        }
        return null;
    }

    private String detectStack(NativeAnalyzer.ApkInfo info) {
        if (info.hasFlutter) return "Flutter (Dart AOT)";
        if (info.hasIl2Cpp) return "Unity (IL2CPP)";
        if (info.hasReactNative) return "React Native";
        if (!info.dexes.isEmpty()) return "Java/Kotlin (DEX)";
        return "未知";
    }

    private static double round(double v) {
        return Math.round(v * 100) / 100.0;
    }

    // ---------- Flutter ----------

    private void blutter(String n, JSONObject a, JSONObject out) throws Exception {
        File apk = resolveApk(a);
        NativeAnalyzer.ApkInfo info = NativeAnalyzer.openApk(apk);

        // 找 libapp.so（Flutter 主逻辑都在里面）
        String libEntry = null;
        for (String s : info.libs) {
            if (s.endsWith("libapp.so")) { libEntry = s; break; }
        }
        if (libEntry == null && info.hasFlutter) {
            for (String s : info.libs) {
                if (s.contains("arm64") && s.endsWith(".so")) { libEntry = s; break; }
            }
        }
        if (libEntry == null) {
            out.put("error", "该 APK 不是 Flutter 应用（未找到 libapp.so）");
            out.put("stack", detectStack(info));
            return;
        }

        File so = NativeAnalyzer.extractEntry(apk, libEntry, workDir());
        if (so == null) { out.put("error", "提取失败: " + libEntry); return; }
        NativeAnalyzer.ElfInfo elf = NativeAnalyzer.parseElf(so);
        if (elf.error != null) { out.put("error", elf.error); return; }

        out.put("lib", libEntry);
        out.put("arch", elf.arch);
        out.put("is_pie", elf.isPie);
        out.put("stack", "Flutter (Dart AOT)");

        // 优先 Termux：真实 blutter 产出完整的 asm/pp.txt/objs.txt
        TermuxExecutor tx = termux();
        if (tx.usable()) {
            File outDir = new File(workDir(), "blutter_out");
            if (!outDir.exists()) outDir.mkdirs();
            String bcmd = blutterTermuxCmd(a.optString("dart_version", null),
                    so.getAbsolutePath(), outDir);
            TermuxExecutor.Result r = tx.run(bcmd, 300000);
            if (r.ok && r.exitCode == 0) {
                JSONObject parsed = BlutterOutput.parse(outDir);
                out.put("engine", "blutter (Termux, 真实)");
                out.put("heuristic", false);
                out.put("exit_code", r.exitCode);
                out.put("output_dir", outDir.getAbsolutePath());
                if (parsed != null) {
                    java.util.Iterator<String> it = parsed.keys();
                    while (it.hasNext()) {
                        String k = it.next();
                        out.put(k, parsed.opt(k));
                    }
                }
                if (r.stdout != null && r.stdout.length() > 0) {
                    out.put("stdout", r.stdout.substring(0, Math.min(4000, r.stdout.length())));
                }
                return;
            }
            out.put("termux_blutter_failed", r.error != null ? r.error : ("exit=" + r.exitCode));
            if (r.stdout != null && r.stdout.length() > 0) {
                out.put("partial_output", r.stdout.substring(0, Math.min(2000, r.stdout.length())));
            }
        }

        // 其次：本地 exec（libblutter_*.so 是 PIE 可执行文件）
        File real = blutterBinary(a.optString("dart_version", null));
        boolean usedReal = false;
        if (real != null) {
            File outDir = new File(workDir(), "blutter_out");
            if (!outDir.exists()) outDir.mkdirs();
            try {
                Process pr = Runtime.getRuntime().exec(new String[]{
                        real.getAbsolutePath(), "-i", so.getAbsolutePath(),
                        "-o", outDir.getAbsolutePath()});
                String se = readStream(pr.getErrorStream(), 4000);
                int code = pr.waitFor();
                if (code == 0) {
                    out.put("engine", "blutter (真实)");
                    out.put("output_dir", outDir.getAbsolutePath());
                    out.put("heuristic", false);
                    usedReal = true;
                } else {
                    out.put("blutter_exit_code", code);
                    out.put("blutter_stderr", se);
                }
            } catch (Exception e) {
                out.put("blutter_error", e.getMessage());
            }
        }

        if (!usedReal) {
            out.put("engine", "内置 ELF 解析");
            out.put("heuristic", true);
            out.put("note", "未找到可用 blutter 可执行文件，改用内置解析；"
                    + "完整类结构需桌面端真实 blutter");
        }

        // 内置解析结果（Dart 符号通常带类名前缀）
        List<NativeAnalyzer.Sym> syms = elf.symbols;
        JSONArray funcs = new JSONArray();
        int fl = a.optInt("limit", 200);
        int cnt = 0;
        for (NativeAnalyzer.Sym s : syms) {
            if ("FUNC".equals(s.type) && s.size > 0) {
                JSONObject o = new JSONObject();
                o.put("name", s.name);
                o.put("addr", s.addr);
                o.put("size", s.size);
                funcs.put(o);
                if (++cnt >= fl) break;
            }
        }
        out.put("function_count", syms.size());
        out.put("functions", funcs);

        if (n.equals("Blutter_Strings")) {
            int lim = a.optInt("limit", 300);
            JSONArray arr = new JSONArray();
            for (NativeAnalyzer.Str s : elf.strings) {
                JSONObject o = new JSONObject();
                o.put("value", s.value);
                o.put("offset", s.offset);
                arr.put(o);
                if (arr.length() >= lim) break;
            }
            out.put("strings", arr);
            return;
        }

        if (n.equals("Blutter_Functions")) return;

        if (n.equals("Blutter_Classes")) {
            // Dart AOT 快照里类名靠函数符号前缀推断
            JSONArray cls = new JSONArray();
            java.util.Set<String> seen = new java.util.LinkedHashSet<String>();
            for (NativeAnalyzer.Sym s : syms) {
                String cn = guessDartClass(s.name);
                if (cn != null && seen.add(cn)) {
                    cls.put(cn);
                    if (cls.length() >= a.optInt("limit", 200)) break;
                }
            }
            out.put("classes", cls);
            out.put("note", "Dart AOT 快照不含完整类元数据，类名为符号前缀推断（启发式）");
            return;
        }

        // Blutter_Analyze / 默认：给概览 + 敏感串
        out.put("section_count", elf.sections.size());
        out.put("string_count", elf.strings.size());
        List<NativeAnalyzer.Str> interesting =
                NativeAnalyzer.interestingStrings(elf.strings, 100);
        JSONArray arr = new JSONArray();
        for (NativeAnalyzer.Str s : interesting) {
            JSONObject o = new JSONObject();
            o.put("value", s.value);
            o.put("offset", s.offset);
            arr.put(o);
        }
        out.put("interesting_strings", arr);
    }

    private static String guessDartClass(String sym) {
        if (sym == null) return null;
        // Dart AOT 常见形态：Class.method 或 _ClassName@xx
        int dot = sym.indexOf('.');
        if (dot > 0) {
            String c = sym.substring(0, dot);
            if (c.matches("[A-Za-z_$][A-Za-z0-9_$]*")) return c;
        }
        if (sym.startsWith("_")) {
            int at = sym.indexOf('@');
            String c = at > 0 ? sym.substring(1, at) : sym.substring(1);
            if (c.matches("[A-Za-z_$][A-Za-z0-9_$]*")) return c;
        }
        return null;
    }

    /** 拼 Termux 里的 blutter 命令：优先已装的 blutter，其次用释放出来的 PIE。 */
    private String blutterTermuxCmd(String dartVer, String soPath, File outDir) {
        String exe = "blutter";
        File local = blutterBinary(dartVer);
        if (local != null) {
            exe = "'" + local.getAbsolutePath() + "'";
        }
        return "if ! command -v blutter >/dev/null 2>&1; then "
                + "EXE=" + exe + "; else EXE=blutter; fi; "
                + "$EXE -i '" + soPath + "' -o '" + outDir.getAbsolutePath() + "'";
    }

    private static String defaultR2Cmd(String tool) {
        switch (tool) {
            case "R2_Analyze": return "aaa";
            case "R2_Functions": return "afl";
            case "R2_Strings": return "iz";
            case "R2_Info": return "iI";
            case "R2_Sections": return "iS";
            case "R2_Symbols": return "is";
            case "R2_Imports": return "ii";
            case "R2_Disassemble": return "pdf";
            default: return "?V";
        }
    }

    /** 找可用的 blutter 可执行文件（按 Dart 版本匹配，名义是 .so 实为 PIE）。 */
    private File blutterBinary(String dartVer) {
        File dir = new File(engineRoot(ctx), "blutter");
        if (!dir.isDirectory()) return null;
        File[] fs = dir.listFiles();
        if (fs == null) return null;
        if (dartVer != null && dartVer.length() > 0) {
            String want = "libblutter_" + dartVer.replace('.', '_');
            for (File f : fs) {
                if (f.getName().equals(want + ".so")) return f;
            }
        }
        // 没指定版本：挑体积最大的（通常是最全的新版）
        File best = null;
        for (File f : fs) {
            if (!f.getName().startsWith("libblutter")) continue;
            if (best == null || f.length() > best.length()) best = f;
        }
        return best;
    }

    // ---------- Unity ----------

    private void il2cpp(JSONObject a, JSONObject out) throws Exception {
        File apk = resolveApk(a);
        NativeAnalyzer.ApkInfo info = NativeAnalyzer.openApk(apk);
        String entry = null;
        for (String s : info.libs) {
            if (s.endsWith("libil2cpp.so")) { entry = s; break; }
        }
        if (entry == null) { out.put("error", "未找到 libil2cpp.so（非 Unity IL2CPP 应用）"); return; }
        File so = NativeAnalyzer.extractEntry(apk, entry, workDir());
        if (so == null) { out.put("error", "提取失败"); return; }
        NativeAnalyzer.ElfInfo elf = NativeAnalyzer.parseElf(so);
        if (elf.error != null) { out.put("error", elf.error); return; }
        out.put("lib", entry);
        out.put("arch", elf.arch);
        out.put("stack", "Unity (IL2CPP)");
        out.put("symbol_count", elf.symbols.size());
        out.put("string_count", elf.strings.size());
        JSONArray arr = new JSONArray();
        int lim = a.optInt("limit", 200);
        for (NativeAnalyzer.Sym s : elf.symbols) {
            if (s.name.contains("il2cpp") || s.name.contains("Assembly")) {
                JSONObject o = new JSONObject();
                o.put("name", s.name);
                o.put("addr", s.addr);
                arr.put(o);
                if (arr.length() >= lim) break;
            }
        }
        out.put("il2cpp_symbols", arr);
        out.put("note", "完整类结构需解析 global-metadata.dat，本端为 ELF 符号级结果");
    }

    // ---------- DEX ----------

    private void dexStrings(JSONObject a, JSONObject out) throws Exception {
        File apk = resolveApk(a);
        NativeAnalyzer.ApkInfo info = NativeAnalyzer.openApk(apk);
        if (info.dexes.isEmpty()) { out.put("error", "APK 中没有 dex"); return; }
        String want = opt(a, "dex", "entry");
        String entry = want != null ? want : info.dexes.get(0);
        File dex = NativeAnalyzer.extractEntry(apk, entry, workDir());
        if (dex == null) { out.put("error", "提取失败: " + entry); return; }
        NativeAnalyzer.DexInfo di = NativeAnalyzer.parseDex(dex);
        if (di.error != null) { out.put("error", di.error); return; }
        out.put("dex", entry);
        out.put("version", di.version);
        out.put("string_count", di.strings.size());
        out.put("type_count", di.typeNames.size());
        int lim = a.optInt("limit", 200);
        JSONArray arr = new JSONArray();
        for (String s : di.strings) {
            arr.put(s);
            if (arr.length() >= lim) break;
        }
        out.put("strings", arr);
        JSONArray cls = new JSONArray();
        for (String s : di.typeNames) {
            cls.put(s);
            if (cls.length() >= lim) break;
        }
        out.put("classes", cls);
    }

    // ---------- radare2 ----------

    private void r2(String n, JSONObject a, JSONObject out) throws Exception {
        // 优先 Termux：那里能跑真实 radare2，能力远超内置解析
        String cmd = opt(a, "command", "cmd");
        String target = opt(a, "so", "path", "file", "apk_path");
        if (target == null) target = currentApk;
        TermuxExecutor tx = termux();
        if (tx.usable() && target != null) {
            String realCmd = cmd != null ? cmd : defaultR2Cmd(n);
            String full = "r2 -q -c '" + realCmd.replace("'", "'\''") + "' '" + target + "'";
            TermuxExecutor.Result r = tx.run(full, 60000);
            if (r.ok) {
                out.put("engine", "radare2 (Termux)");
                out.put("heuristic", false);
                out.put("exit_code", r.exitCode);
                out.put("command", full);
                out.put("output", r.stdout);
                return;
            }
            out.put("termux_error", r.error);
            if (r.stdout != null && r.stdout.length() > 0) {
                out.put("partial_output", r.stdout);
            }
        }

        // 降级：JNI 桥（com.r2aibridge.R2Core），签名不可考，
        // 任何一步失败都降级，绝不让它把进程带崩。
        try {
            Class<?> c = Class.forName("com.r2aibridge.R2Core");
            java.lang.reflect.Method init = c.getMethod("initR2Core");
            java.lang.reflect.Method exec = c.getMethod("executeCommand", String.class);
            Object inst = c.newInstance();
            Object r = init.invoke(inst);
            out.put("bridge_init", String.valueOf(r));
            String cmd = opt(a, "command", "cmd");
            if (cmd == null) cmd = "?V";
            Object res = exec.invoke(inst, cmd);
            out.put("command", cmd);
            out.put("result", String.valueOf(res));
            out.put("engine", "radare2 (JNI 桥)");
            out.put("heuristic", false);
            return;
        } catch (ClassNotFoundException e) {
            out.put("error", "未打包 radare2 JNI 桥（com.r2aibridge.R2Core 不存在）");
        } catch (NoSuchMethodException e) {
            out.put("error", "JNI 桥方法签名不匹配: " + e.getMessage());
            out.put("hint", "libr2aibridge.so 的 native 方法与 Java 声明不一致，"
                    + "需要按其真实签名调整 com.r2aibridge.R2Core 声明");
        } catch (Throwable t) {
            out.put("error", "radare2 调用失败: " + typeName(t) + ": " + t.getMessage());
        }
        out.put("engine", "radare2 (不可用)");
        out.put("note", "R2_* 工具需要 radare2 引擎；可用替代：Apk_Open / Blutter_Analyze / Dex_Strings");
    }

    // ---------- 引擎状态 ----------

    private void engineStatus(JSONObject out) throws Exception {
        File root = engineRoot(ctx);
        JSONObject eng = new JSONObject();
        File[] dirs = root.listFiles();
        if (dirs != null) {
            for (File d : dirs) {
                if (!d.isDirectory()) continue;
                File[] fs = d.listFiles();
                int cnt = fs == null ? 0 : fs.length;
                long sum = 0;
                if (fs != null) for (File f : fs) sum += f.length();
                JSONObject o = new JSONObject();
                o.put("files", cnt);
                o.put("mb", round(sum / 1048576.0));
                o.put("ready", cnt > 0);
                eng.put(d.getName(), o);
            }
        }
        out.put("engines", eng);
        out.put("engine_root", root.getAbsolutePath());
        TermuxExecutor tx = termux();
        JSONObject t = new JSONObject();
        t.put("installed", tx.installed());
        t.put("has_permission", tx.hasPermission());
        t.put("usable", tx.usable());
        if (tx.usable()) t.put("probe", tx.probe());
        out.put("termux", t);
        out.put("unpacked", new File(root, ".unpacked").exists());
        out.put("current_apk", currentApk);
        out.put("abi", android.os.Build.SUPPORTED_ABIS.length > 0
                ? android.os.Build.SUPPORTED_ABIS[0] : "unknown");
    }

    // ---------- 工具 ----------

    private static String readStream(java.io.InputStream is, int limit) throws Exception {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r, total = 0;
        while ((r = is.read(buf)) > 0) {
            bo.write(buf, 0, r);
            total += r;
            if (total >= limit) break;
        }
        is.close();
        return new String(bo.toByteArray(), "UTF-8");
    }
}
