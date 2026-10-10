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

        // ---------- Frida 双通道 / 补丁会话 ----------
        if (n.startsWith("Frida_Channel")) { fridaChannel(a, out); return; }
        if (n.startsWith("Patch_Session")) { patchSession(a, out); return; }
        if (n.startsWith("Ub_")) { unidbg(n, a, out); return; }
        if (n.startsWith("Capstone_") || n.startsWith("Disasm_")) { capstone(n, a, out); return; }

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
        // R2_Version 特殊处理：直接返回启动自检时拿到的版本串，
        // 不再进 native。它之前一调用就崩进程（5051 随即拒绝连接），
        // 版本信息是静态的，没必要冒险。
        if (n.equals("R2_Version")) {
            String v = Radare2Bridge.cachedVersion();
            if (v != null) {
                out.put("engine", "radare2 (内置 JNI 桥)");
                out.put("version", v);
                out.put("source", "启动自检缓存（未调用 native）");
                return;
            }
        }
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
            return "unidbg 走 ART + unicorn2（libunicorn.so + libunicorn_java.so + "
                    + "d8 转出的 dex），不需要 JVM；若不可用通常是缺 unicorn 库或 dex。";
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

    /**
     * Capstone 独立反汇编：直接对裸字节/文件偏移反汇编，
     * 不用先建 r2 会话（那段流程对"就想知道这几字节是什么指令"太重）。
     */
    private void capstone(String n, JSONObject a, JSONObject out) throws Exception {
        if (!CapstoneJni.load(ctx)) {
            out.put("engine", "capstone (不可用)");
            out.put("error", CapstoneJni.lastError());
            out.put("hint", "需要 libcapstone.so；若要走 JNI 桥还需 libdisassembler.so");
            return;
        }
        String path = opt(a, "so", "path", "file", "bin");
        String hex = opt(a, "hex", "bytes", "code");
        byte[] code = null;

        if (hex != null && !hex.isEmpty()) {
            code = parseHex(hex);
            if (code == null) { out.put("error", "hex 格式不对（示例: 5F2403D5）"); return; }
        } else if (path != null) {
            File f = new File(path);
            if (!f.isFile()) { out.put("error", "文件不存在: " + path); return; }
            long off = 0;
            String os = opt(a, "offset", "off");
            if (os != null) {
                try {
                    off = os.startsWith("0x") ? Long.parseLong(os.substring(2), 16)
                            : Long.parseLong(os);
                } catch (NumberFormatException ignored) {}
            }
            int len = 256;
            String ls = opt(a, "length", "size", "len");
            if (ls != null) { try { len = Integer.parseInt(ls); } catch (Exception ignored) {} }
            code = readBytes(f, off, len);
            if (code == null) { out.put("error", "读取失败"); return; }
        } else {
            out.put("engine", "capstone");
            out.put("status", CapstoneJni.describe(ctx));
            out.put("usage", "传 hex=<十六进制> 或 so=<文件路径>+offset+length");
            return;
        }

        long addr = 0;
        String as = opt(a, "addr", "address", "base");
        if (as != null) {
            try {
                addr = as.startsWith("0x") ? Long.parseLong(as.substring(2), 16)
                        : Long.parseLong(as);
            } catch (NumberFormatException ignored) {}
        }
        int arch = CapstoneJni.ARCH_ARM64;
        String archS = opt(a, "arch");
        if (archS != null) {
            String v = archS.toLowerCase();
            if (v.contains("arm64") || v.contains("aarch64")) arch = CapstoneJni.ARCH_ARM64;
            else if (v.contains("x86") || v.contains("intel")) arch = CapstoneJni.ARCH_X86;
            else if (v.contains("arm")) arch = CapstoneJni.ARCH_ARM;
        }
        int mode = arch == CapstoneJni.ARCH_ARM64 ? CapstoneJni.MODE_LITTLE_ENDIAN
                : CapstoneJni.MODE_32;
        int count = 0;
        String cs = opt(a, "count", "limit");
        if (cs != null) { try { count = Integer.parseInt(cs); } catch (Exception ignored) {} }

        List<CapstoneJni.Insn> list = CapstoneJni.disasm(code, addr, arch, mode, count);
        out.put("engine", "capstone (JNI)");
        out.put("arch", arch);
        out.put("count", list.size());
        JSONArray arr = new JSONArray();
        for (CapstoneJni.Insn in : list) {
            JSONObject o = new JSONObject();
            o.put("address", "0x" + Long.toHexString(in.address));
            o.put("mnemonic", in.mnemonic);
            o.put("operands", in.operands);
            arr.put(o);
        }
        out.put("insns", arr);
        if (list.isEmpty()) {
            out.put("hint", "反汇编结果为空：可能是桥签名不匹配，"
                    + "或该架构未被 capstone 启用");
        }
    }

    /** 解析十六进制串，允许空格/冒号分隔。 */
    private static byte[] parseHex(String s) {
        if (s == null) return null;
        String clean = s.replaceAll("[\\s:,\\-]", "");
        if (clean.length() == 0 || clean.length() % 2 != 0) return null;
        try {
            byte[] out = new byte[clean.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 从文件读一段。 */
    private static byte[] readBytes(File f, long off, int len) {
        try {
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r");
            if (off >= raf.length()) { raf.close(); return new byte[0]; }
            int n = (int) Math.min(len, raf.length() - off);
            byte[] b = new byte[n];
            raf.seek(off);
            raf.readFully(b);
            raf.close();
            return b;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * unidbg 模拟执行。
     * 全部走反射——编译期不依赖 unidbg，缺库或 API 变动都不会让主程序崩。
     */
    private void unidbg(String n, JSONObject a, JSONObject out) throws Exception {
        if (!UnidbgEngine.load(ctx)) {
            out.put("engine", "unidbg (不可用)");
            out.put("error", UnidbgEngine.lastError());
            out.put("hint", "需要 libunicorn.so + libunicorn_java.so，"
                    + "以及 assets/engine/unidbg/ 下的 dex（构建期由 d8 从 jar 转出）");
            out.put("heuristic", false);
            return;
        }
        if (n.endsWith("_Status") || n.endsWith("_Env") || n.endsWith("_Capabilities")) {
            out.put("engine", "unidbg (ART + unicorn2)");
            out.put("capabilities", UnidbgEngine.capabilities(ctx));
            out.put("heuristic", false);
            return;
        }
        String target = opt(a, "so", "path", "file", "lib");
        if (target == null) {
            out.put("error", "需要 so 路径");
            out.put("capabilities", UnidbgEngine.capabilities(ctx));
            return;
        }
        File so = new File(target);
        if (!so.isFile()) { out.put("error", "文件不存在: " + target); return; }

        boolean is64 = true;
        try {
            byte[] hdr = new byte[8];
            java.io.FileInputStream fi = new java.io.FileInputStream(so);
            fi.read(hdr); fi.close();
            // ELF class: 1=32bit 2=64bit
            if (hdr[4] == 1) is64 = false;
        } catch (Exception ignored) {}

        String apkPath = opt(a, "apk", "apk_path");
        if (apkPath == null) apkPath = currentApk;
        UnidbgEngine.Session sess = UnidbgEngine.open(
                is64, opt(a, "process", "process_name"),
                apkPath == null ? null : new File(apkPath));

        if (sess.error != null) {
            out.put("error", sess.error);
            return;
        }
        try {
            Object mod = UnidbgEngine.loadLibrary(sess, so, true);
            if (mod == null) {
                out.put("error", "加载 so 失败（可能缺少依赖库或架构不匹配）");
                out.put("is64", is64);
                return;
            }
            sess.module = mod;
            out.put("session_id", sess.id);
            out.put("is64", is64);
            out.put("engine", "unidbg (ART + unicorn2)");
            out.put("heuristic", false);

            String sym = opt(a, "symbol", "sym", "name");
            if (sym != null) {
                out.put("call_result", UnidbgEngine.callSymbol(sess, mod, sym));
            } else {
                String addr = opt(a, "addr", "offset", "address");
                if (addr != null) {
                    try {
                        long off = addr.startsWith("0x") || addr.startsWith("0X")
                                ? Long.parseLong(addr.substring(2), 16)
                                : Long.parseLong(addr);
                        out.put("call_result", UnidbgEngine.callAddress(sess, mod, off));
                    } catch (NumberFormatException e) {
                        out.put("error", "地址格式不对: " + addr);
                    }
                } else {
                    int limit = 100;
                    try { limit = Integer.parseInt(String.valueOf(opt(a, "limit"))); }
                    catch (Exception ignored) {}
                    out.put("symbols", UnidbgEngine.listSymbols(mod, limit));
                }
            }
        } finally {
            // 模拟执行吃内存，用完立即释放，不常驻
            UnidbgEngine.close(sess);
            out.put("closed", true);
        }
    }

    /** Frida 双通道：探测 / 拉起 / 生成脚本 / 生成 gadget 配置。 */
    private void fridaChannel(JSONObject a, JSONObject out) throws Exception {
        String act = opt(a, "action");
        if (act == null) act = "status";
        if ("status".equals(act) || "capabilities".equals(act)) {
            FridaChannel.Status st = FridaChannel.probe(ctx);
            out.put("rooted", st.rooted);
            out.put("server_binary_found", st.serverBinaryFound);
            out.put("server_running", st.serverRunning);
            out.put("gadget_available", st.gadgetAvailable);
            out.put("mode", st.mode);
            out.put("detail", st.detail);
            if (st.serverPath != null) out.put("server_path", st.serverPath);
            if (st.gadgetPath != null) out.put("gadget_path", st.gadgetPath);
            if (st.error != null) out.put("error", st.error);
            out.put("rpc_supported", false);
            out.put("rpc_note", "与 frida-server 的 RPC 走私有二进制协议，"
                    + "本版仅提供探测/拉起/脚本生成，不伪装为已支持");
            return;
        }
        if ("start".equals(act)) {
            out.put("result", FridaChannel.start(ctx));
            out.put("running", FridaChannel.probe(ctx).serverRunning);
            return;
        }
        if ("script".equals(act)) {
            String js = FridaChannel.buildHookScript(opt(a, "module"),
                    opt(a, "addr", "offset"), opt(a, "tag"));
            File dir = new File(ctx.getFilesDir(), "frida");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, "hook_" + System.currentTimeMillis() + ".js");
            java.io.FileOutputStream os = new java.io.FileOutputStream(f);
            os.write(js.getBytes("UTF-8"));
            os.close();
            out.put("script_path", f.getAbsolutePath());
            out.put("script", js);
            return;
        }
        if ("gadget_config".equals(act)) {
            File cfg = FridaChannel.writeGadgetConfig(ctx, opt(a, "script", "script_path"));
            if (cfg == null) out.put("error", "写 gadget 配置失败");
            else out.put("config_path", cfg.getAbsolutePath());
            return;
        }
        out.put("error", "未知 action: " + act);
        out.put("available", new JSONArray(java.util.Arrays.asList(
                "status", "capabilities", "start", "script", "gadget_config")));
    }

    /** 补丁编辑会话：open / commit / undo / redo / rollback / apply / audit / list。 */
    private void patchSession(JSONObject a, JSONObject out) throws Exception {
        String act = opt(a, "action");
        if (act == null) act = "list";
        if ("list".equals(act)) {
            out.put("sessions", new JSONArray(PatchSession.list(ctx)));
            return;
        }
        String sid = opt(a, "session", "session_id", "id");
        if ("open".equals(act)) {
            String target = opt(a, "target", "path", "file", "so");
            if (target == null) target = currentApk;
            if (target == null) { out.put("error", "需要 target"); return; }
            putInfo(out, PatchSession.open(ctx, target, opt(a, "note")));
            return;
        }
        if (sid == null) { out.put("error", "需要 session"); return; }
        PatchSession.Info info;
        if ("commit".equals(act)) {
            String src = opt(a, "file", "content", "path");
            if (src == null) { out.put("error", "需要 file（新内容路径）"); return; }
            putInfo(out, PatchSession.commit(ctx, sid, new File(src), opt(a, "note")));
            return;
        } else if ("undo".equals(act))      info = PatchSession.undo(ctx, sid);
        else if ("redo".equals(act))        info = PatchSession.redo(ctx, sid);
        else if ("rollback".equals(act))    info = PatchSession.rollback(ctx, sid);
        else if ("apply".equals(act)) {
            String t = opt(a, "target", "path");
            if (t == null) { out.put("error", "需要 target"); return; }
            out.put("result", PatchSession.apply(ctx, sid, t));
            putInfo(out, PatchSession.load(ctx, sid));
            return;
        } else if ("status".equals(act) || "audit".equals(act)) {
            putInfo(out, PatchSession.load(ctx, sid));
            return;
        } else {
            out.put("error", "未知 action: " + act);
            out.put("available", new JSONArray(java.util.Arrays.asList(
                    "list", "open", "commit", "undo", "redo",
                    "rollback", "apply", "audit", "status")));
            return;
        }
        PatchSession.persistVersion(info);
        putInfo(out, info);
    }

    private static void putInfo(JSONObject out, PatchSession.Info info) throws Exception {
        if (info.error != null) out.put("error", info.error);
        if (info.id != null) out.put("session_id", info.id);
        if (info.workDir != null) out.put("work_dir", info.workDir.getAbsolutePath());
        out.put("version", info.version);
        out.put("max_version", info.maxVersion);
        if (info.targetName != null) out.put("target", info.targetName);
        File cur = info.workDir == null ? null : new File(info.workDir, "v" + info.version);
        if (cur != null && cur.exists()) out.put("current_file", cur.getAbsolutePath());
        out.put("audit", new JSONArray(info.audit));
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
        String cmd = opt(a, "command", "cmd");
        String target = opt(a, "so", "path", "file", "apk_path");
        if (target == null) target = currentApk;

        // 1) 主路径：内置 radare2（JNI 桥 + 23 个 libr_*.so），不依赖任何外部 App
        Radare2Bridge.LoadReport rep = Radare2Bridge.load(ctx);
        if (rep.ok) {
            if (target != null && new File(target).isFile()) {
                String opened = Radare2Bridge.open(target);
                out.put("open_result", opened);
            }
            // 命令来源优先级：
            //   1. 调用方显式传的 command/cmd
            //   2. R2Commands 映射表（覆盖 94 个 R2_* 工具）
            //   3. defaultR2Cmd 兜底
            String realCmd = cmd;
            if (realCmd == null || realCmd.trim().isEmpty()) {
                String arg = opt(a, "arg", "keyword", "kw", "addr", "address", "offset", "expr");
                String mapped = R2Commands.commandFor(n, arg);
                realCmd = (mapped != null && !mapped.trim().isEmpty())
                        ? mapped : defaultR2Cmd(n);
            }
            String res = Radare2Bridge.cmd(realCmd);
            out.put("engine", "radare2 (内置 JNI 桥)");
            out.put("heuristic", false);
            out.put("command", realCmd);
            out.put("output", res);
            out.put("libs_loaded", rep.loaded.size());
            if (!rep.missing.isEmpty()) {
                out.put("libs_missing", new JSONArray(rep.missing));
            }
            return;
        }

        // 2) 降级 A：Termux（若用户装了并授权）
        TermuxExecutor tx = termux();
        if (tx.usable() && target != null) {
            String realCmd = cmd;
            if (realCmd == null || realCmd.trim().isEmpty()) {
                String arg = opt(a, "arg", "keyword", "kw", "addr", "address", "offset", "expr");
                String mapped = R2Commands.commandFor(n, arg);
                realCmd = (mapped != null && !mapped.trim().isEmpty())
                        ? mapped : defaultR2Cmd(n);
            }
            String full = "r2 -q -c '" + realCmd.replace("'", "'\\''") + "' '" + target + "'";
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
        }

        // 3) 降级 B：内置 ELF 解析（只能给符号/字符串，没有反汇编）
        out.put("engine", "内置 ELF 解析（非 radare2）");
        out.put("heuristic", true);
        out.put("error", "radare2 不可用: "
                + (rep.error != null ? rep.error : "未知原因"));
        out.put("hint", "需要 files/engine/radare2/ 下的 23 个 libr_*.so "
                + "+ libr2aibridge.so，且设备须为 arm64");
        if (target != null && new File(target).isFile()) {
            try {
                NativeAnalyzer.ElfInfo elf = NativeAnalyzer.parseElf(new File(target));
                if (elf.error == null) {
                    out.put("arch", elf.arch);
                    out.put("symbol_count", elf.symbols.size());
                    out.put("string_count", elf.strings.size());
                }
            } catch (Exception ignored) {}
        }
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
