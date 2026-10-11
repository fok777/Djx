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

    /**
     * 大结果外置存储。工具输出超过阈值时把全文存这里返回 blob_id，
     * 客户端再用 Blob_Read 分页取回——避免长输出被直接截断丢失。
     */
    private static final java.util.Map<String, String> BLOBS =
            new java.util.LinkedHashMap<String, String>() {
                protected boolean removeEldestEntry(
                        java.util.Map.Entry<String, String> e) {
                    return size() > 32;   // 只留最近 32 份，防内存膨胀
                }
            };
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

        // ---------- Frida ----------
        // 55 个 Fr_* 工具统一走"生成 JS → 投递执行"。
        // 有 root + frida-server 就能真跑；否则返回脚本供手工注入，
        // 不伪装成功。
        if (n.startsWith("Fr_")) { frida(n, a, out); return; }
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
        // ---------- Nav (23) ----------
        // 导航/图类工具底层就是 radare2 的 ag* 命令族，直接转过去
        if (n.startsWith("Nav_")) {
            String op = EngineCommands.opFor(n);
            out.put("engine", "radare2 (内置 JNI 桥)");
            out.put("op", op);
            if (op == null) { out.put("error", "未知 Nav 工具: " + n); return; }
            if (op.startsWith("guide:")) {
                out.put("guide", "反混淆通用步骤：1) afl 找函数 → 2) pdf 看控制流 "
                        + "→ 3) axt/axf 追引用 → 4) 定位分发器 → 5) 还原真实分支");
                return;
            }
            String cmd = op.substring(3);
            String arg = opt(a, "addr", "address", "keyword", "kw", "name", "bytes", "value");
            if (cmd.contains("%s")) {
                cmd = cmd.replace("%s", arg == null ? "" : arg.trim());
            } else if (arg != null && !arg.trim().isEmpty()) {
                cmd = cmd + " @ " + arg.trim();
            }
            if (!Radare2Bridge.load(ctx).ok) {
                out.put("error", "radare2 不可用: " + Radare2Bridge.status());
                return;
            }
            out.put("command", cmd);
            out.put("output", Radare2Bridge.cmd(cmd));
            out.put("heuristic", false);
            return;
        }

        // ---------- Pentest (12) ----------
        // 渗透类落到字符串/符号关键词扫描，不依赖 mitmproxy 等外部服务
        if (n.startsWith("Pentest_")) {
            String op = EngineCommands.opFor(n);
            out.put("engine", "内置扫描");
            out.put("op", op);
            if (op == null) { out.put("error", "未知 Pentest 工具: " + n); return; }
            String kwSet = op.substring(5);
            File tgt = null;
            String tp = opt(a, "so", "path", "file", "apk_path", "target");
            if (tp != null) tgt = new File(tp);
            if (tgt == null || !tgt.isFile()) {
                out.put("error", "需要有效的 so / apk 路径");
                return;
            }
            NativeAnalyzer.ElfInfo ei = NativeAnalyzer.parseElf(tgt);
            if (ei == null || ei.error != null) {
                out.put("error", "解析失败: " + (ei == null ? "null" : ei.error));
                return;
            }
            String[] keys = keywordsFor(kwSet);
            JSONArray arr = new JSONArray();
            for (NativeAnalyzer.Str st : ei.strings) {
                String v = st.value.toLowerCase();
                for (String k : keys) {
                    if (v.contains(k)) {
                        JSONObject o = new JSONObject();
                        o.put("category", k); o.put("value", st.value);
                        o.put("offset", st.offset);
                        arr.put(o);
                        break;
                    }
                }
                if (arr.length() >= 300) break;
            }
            for (NativeAnalyzer.Sym sy : ei.symbols) {
                String v = sy.name.toLowerCase();
                for (String k : keys) {
                    if (v.contains(k)) {
                        JSONObject o = new JSONObject();
                        o.put("category", k); o.put("symbol", sy.name);
                        o.put("addr", sy.addr);
                        arr.put(o);
                        break;
                    }
                }
                if (arr.length() >= 300) break;
            }
            out.put("hits", arr);
            out.put("heuristic", true);
            out.put("note", "关键词命中，需人工复核；真实抓包/绕过需配合 frida 或桌面端");
            return;
        }

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

        // ---------- APK 会话 / 打包 (7) ----------
        if (n.equals("Apk_Version_Info")) {
            String ap = opt(a, "apk_path", "path", "file");
            if (ap == null) ap = currentApk;
            if (ap == null) { out.put("error", "未选择 APK"); return; }
            File f = new File(ap);
            out.put("apk", ap);
            out.put("exists", f.isFile());
            if (f.isFile()) {
                out.put("size", f.length());
                java.util.zip.ZipFile z = null;
                try {
                    z = new java.util.zip.ZipFile(f);
                    int dexs = 0, sos = 0;
                    java.util.Enumeration<? extends java.util.zip.ZipEntry> en = z.entries();
                    while (en.hasMoreElements()) {
                        String nm = en.nextElement().getName();
                        if (nm.endsWith(".dex")) dexs++;
                        else if (nm.endsWith(".so")) sos++;
                    }
                    out.put("dex_count", dexs);
                    out.put("so_count", sos);
                    out.put("entries", z.size());
                } catch (Exception e) {
                    out.put("zip_error", e.getMessage());
                } finally {
                    try { if (z != null) z.close(); } catch (Exception ignored) {}
                }
            }
            return;
        }
        if (n.equals("Apk_Close")) {
            String d = opt(a, "apk_path", "path");
            if (d != null) {
                File f = new File(d);
                if (f.isFile()) out.put("deleted", f.delete());
            }
            out.put("closed", true);
            out.put("note", "内置解析无持久会话；仅清理临时文件");
            return;
        }
        if (n.equals("Apk_Diff")) {
            String p1 = opt(a, "a", "apk1", "path1", "left");
            String p2 = opt(a, "b", "apk2", "path2", "right");
            if (p1 == null) p1 = currentApk;
            if (p1 == null || p2 == null) { out.put("error", "需要两个 APK 路径 (a / b)"); return; }
            java.util.Set<String> s1 = zipNames(new File(p1));
            java.util.Set<String> s2 = zipNames(new File(p2));
            JSONArray only1 = new JSONArray(), only2 = new JSONArray(), both = new JSONArray();
            for (String x : s1) { if (s2.contains(x)) both.put(x); else only1.put(x); }
            for (String x : s2) { if (!s1.contains(x)) only2.put(x); }
            out.put("only_in_a", only1);
            out.put("only_in_b", only2);
            out.put("common_count", both.length());
            return;
        }
        if (n.equals("Apk_Pack")) {
            String src = opt(a, "apk_path", "path", "src");
            if (src == null) src = currentApk;
            String so = opt(a, "so", "replace");
            if (src == null || !new File(src).isFile()) { out.put("error", "需要源 APK"); return; }
            if (so == null || !new File(so).isFile()) { out.put("error", "需要替换用的 so"); return; }
            String entry = opt(a, "entry", "entry_name");
            if (entry == null) entry = new File(so).getName();
            File dst = new File(new File(src).getParentFile(),
                    baseName(src) + "_成品.apk");
            try {
                copyZipReplacing(new File(src), dst, entry, new File(so));
                out.put("output", dst.getAbsolutePath());
                out.put("replaced_entry", entry);
                out.put("note", "未重新签名，安装前需单独签名（如 apksigner）");
            } catch (Exception e) {
                out.put("error", "打包失败: " + e.getMessage());
            }
            return;
        }
        if (n.equals("Apk_Install") || n.equals("Apk_Install_Start")) {
            String ap = opt(a, "apk_path", "path", "file");
            if (ap == null) ap = currentApk;
            if (ap == null || !new File(ap).isFile()) { out.put("error", "需要 APK 路径"); return; }
            try {
                Process pr = Runtime.getRuntime().exec(
                        new String[]{"pm", "install", "-r", ap});
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] b = new byte[4096]; int r;
                java.io.InputStream is = pr.getInputStream();
                while ((r = is.read(b)) > 0) bo.write(b, 0, r);
                int code = pr.waitFor();
                out.put("exit_code", code);
                out.put("output", new String(bo.toByteArray(), "UTF-8"));
                out.put("note", code == 0 ? "安装完成" : "pm install 在非系统应用中通常无权限，需 root 或用 Intent 安装");
            } catch (Exception e) {
                out.put("error", e.getMessage());
            }
            return;
        }
        if (n.equals("Apk_Upload")) {
            String ap = opt(a, "apk_path", "path", "file");
            if (ap == null) ap = currentApk;
            if (ap == null) { out.put("error", "未选择 APK"); return; }
            out.put("upload_id", "local:" + ap);
            out.put("path", ap);
            out.put("note", "本端为直连模式，upload_id 即实际路径，可直接给 Apk_Open 使用");
            return;
        }

        // ---------- Engine 配置 / 资产 (9) ----------
        if (n.equals("Engine_List_Assets")) {
            File root = EngineUnpacker.engineRoot(ctx);
            JSONArray arr = new JSONArray();
            listInto(root, arr, 0);
            out.put("root", root == null ? "" : root.getAbsolutePath());
            out.put("assets", arr);
            return;
        }
        if (n.equals("Engine_R2_Status")) {
            out.put("loaded", Radare2Bridge.isLoaded());
            out.put("status", Radare2Bridge.status());
            out.put("version", Radare2Bridge.cachedVersion());
            java.util.List<String> miss = Radare2Bridge.missingLibs();
            if (miss != null && !miss.isEmpty()) out.put("missing_libs", new JSONArray(miss));
            return;
        }
        if (n.equals("Engine_R2_Deps")) {
            java.util.List<String> miss = Radare2Bridge.missingLibs();
            out.put("missing", miss == null ? new JSONArray() : new JSONArray(miss));
            out.put("ok", miss == null || miss.isEmpty());
            out.put("hint", "radare2 桥依赖全套 libr_*.so，缺任一都可能让调用期 SIGSEGV");
            return;
        }
        if (n.equals("Engine_R2_Lib")) {
            out.put("result", Radare2Bridge.status());
            out.put("reload", Radare2Bridge.load(ctx).ok);
            return;
        }
        if (n.equals("Engine_R2_Cmd")) {
            String c = opt(a, "command", "cmd");
            if (c == null) { out.put("error", "缺少 command"); return; }
            out.put("command", c);
            out.put("output", Radare2Bridge.cmd(c));
            return;
        }
        if (n.equals("Engine_Guide")) {
            out.put("guide", "引擎放 lib/<abi>/ 下（APK 打包时由 build.gradle 自动收编），"
                    + "不要放 assets 再释放到私有目录再 exec —— "
                    + "Android 10+ SELinux 禁止 execve 私有目录文件。"
                    + "命名：radare2 用 libr_*.so + libr2aibridge.so；"
                    + "blutter 用 libblutter_<dart版本>.so；unidbg 用 libunicorn*.so + dex。");
            return;
        }
        if (n.equals("Engine_Fetch_Plan")) {
            String eng = opt(a, "engine", "name");
            out.put("engine", eng);
            out.put("steps", "1) 取对应项目的官方预编译产物（arm64） "
                    + "2) 放进 app/src/main/jniLibs/arm64-v8a/ "
                    + "3) 重新构建；本端不联网，只出步骤不下网");
            return;
        }
        if (n.equals("Engine_Config") || n.equals("Engine_Set")) {
            out.put("config", "内置引擎，无可写调用配置；"
                    + "所有引擎通过 JNI / exec 直接使用，不走外部配置文件");
            return;
        }

        // ---------- Os 文件操作 (4) ----------
        if (n.equals("Os_Stat")) {
            String pth = opt(a, "path", "file");
            if (pth == null) { out.put("error", "缺少 path"); return; }
            File f = new File(pth);
            out.put("path", pth);
            out.put("exists", f.exists());
            if (f.exists()) {
                out.put("is_dir", f.isDirectory());
                out.put("size", f.length());
                out.put("readable", f.canRead());
                out.put("writable", f.canWrite());
                out.put("modified", f.lastModified());
            }
            return;
        }
        if (n.equals("Os_Write_File")) {
            String pth = opt(a, "path", "file");
            String content = opt(a, "content", "text", "data");
            if (pth == null || content == null) { out.put("error", "缺少 path 或 content"); return; }
            try {
                File f = new File(pth);
                File par = f.getParentFile();
                if (par != null && !par.exists()) par.mkdirs();
                java.io.FileOutputStream os = new java.io.FileOutputStream(f);
                os.write(content.getBytes("UTF-8"));
                os.close();
                out.put("written", f.length());
                out.put("path", f.getAbsolutePath());
            } catch (Exception e) {
                out.put("error", e.getMessage());
            }
            return;
        }
        if (n.equals("Os_Grep")) {
            String pth = opt(a, "path", "file", "dir");
            String pat = opt(a, "pattern", "regex", "keyword", "kw");
            if (pth == null || pat == null) { out.put("error", "缺少 path 或 pattern"); return; }
            JSONArray arr = new JSONArray();
            int lim = a.optInt("limit", 200);
            try {
                java.util.regex.Pattern P = java.util.regex.Pattern.compile(pat);
                grepInto(new File(pth), P, arr, lim, 0);
            } catch (Exception e) {
                out.put("error", "正则错误: " + e.getMessage());
            }
            out.put("hits", arr);
            return;
        }
        if (n.equals("Os_Find")) {
            String dir = opt(a, "path", "dir", "root");
            String glob = opt(a, "pattern", "glob", "keyword", "kw");
            if (dir == null) dir = ctx.getFilesDir().getAbsolutePath();
            JSONArray arr = new JSONArray();
            findInto(new File(dir), glob, arr, a.optInt("limit", 300), 0);
            out.put("files", arr);
            return;
        }

        // ---------- 其余杂项 (14) ----------
        if (n.equals("Read_Logcat")) {
            String tag = opt(a, "tag", "filter");
            int lines = a.optInt("lines", 200);
            try {
                java.util.List<String> cmd = new java.util.ArrayList<String>();
                cmd.add("logcat"); cmd.add("-d"); cmd.add("-t"); cmd.add(String.valueOf(lines));
                if (tag != null) { cmd.add("-s"); cmd.add(tag); }
                Process pr = new ProcessBuilder(cmd).redirectErrorStream(true).start();
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] b = new byte[8192]; int r;
                java.io.InputStream is = pr.getInputStream();
                while ((r = is.read(b)) > 0) bo.write(b, 0, r);
                pr.waitFor();
                out.put("log", new String(bo.toByteArray(), "UTF-8"));
                out.put("note", "Android 4.1+ 只能读本应用自身日志；"
                        + "读其他应用需 READ_LOGS 权限或 root");
            } catch (Exception e) {
                out.put("error", e.getMessage());
            }
            return;
        }
        if (n.equals("Sqlite_Query")) {
            String db = opt(a, "db", "path", "database");
            String sql = opt(a, "sql", "query");
            if (db == null || sql == null) { out.put("error", "缺少 db 或 sql"); return; }
            android.database.sqlite.SQLiteDatabase sd = null;
            try {
                sd = android.database.sqlite.SQLiteDatabase.openDatabase(
                        db, null, android.database.sqlite.SQLiteDatabase.OPEN_READONLY);
                android.database.Cursor c = sd.rawQuery(sql, null);
                JSONArray cols = new JSONArray();
                for (String cn : c.getColumnNames()) cols.put(cn);
                JSONArray rows = new JSONArray();
                int lim = a.optInt("limit", 200);
                while (c.moveToNext() && rows.length() < lim) {
                    JSONObject o = new JSONObject();
                    for (String cn : c.getColumnNames()) {
                        int idx = c.getColumnIndex(cn);
                        o.put(cn, c.getString(idx));
                    }
                    rows.put(o);
                }
                c.close();
                out.put("columns", cols);
                out.put("rows", rows);
            } catch (Exception e) {
                out.put("error", e.getMessage());
            } finally {
                try { if (sd != null) sd.close(); } catch (Exception ignored) {}
            }
            return;
        }
        if (n.equals("Find_Jni_Methods")) {
            String pth = opt(a, "so", "path", "file");
            if (pth == null) { out.put("error", "需要 so 路径"); return; }
            NativeAnalyzer.ElfInfo ei = NativeAnalyzer.parseElf(new File(pth));
            if (ei == null || ei.error != null) {
                out.put("error", "解析失败: " + (ei == null ? "null" : ei.error)); return;
            }
            JSONArray arr = new JSONArray();
            for (NativeAnalyzer.Sym sy : ei.symbols) {
                if (sy.name.startsWith("Java_")) {
                    JSONObject o = new JSONObject();
                    o.put("name", sy.name); o.put("addr", sy.addr);
                    arr.put(o);
                    if (arr.length() >= 500) break;
                }
            }
            out.put("jni_methods", arr);
            return;
        }
        if (n.equals("Scan_Crypto_Signatures")) {
            String pth = opt(a, "so", "path", "file");
            if (pth == null) { out.put("error", "需要 so 路径"); return; }
            NativeAnalyzer.ElfInfo ei = NativeAnalyzer.parseElf(new File(pth));
            if (ei == null || ei.error != null) {
                out.put("error", "解析失败"); return;
            }
            // AES S-box / MD5 / SHA 常量是固定字节，可按符号名 + 字符串双路扫
            JSONArray arr = new JSONArray();
            String[] K = {"aes","des","md5","sha1","sha256","sha512","rsa","hmac",
                    "blowfish","rc4","tea","base64","crypto","cipher","encrypt"};
            for (NativeAnalyzer.Sym sy : ei.symbols) {
                String v = sy.name.toLowerCase();
                for (String k : K) {
                    if (v.contains(k)) {
                        JSONObject o = new JSONObject();
                        o.put("kind", "symbol"); o.put("name", sy.name);
                        o.put("addr", sy.addr); o.put("algo", k);
                        arr.put(o); break;
                    }
                }
                if (arr.length() >= 300) break;
            }
            out.put("crypto_hits", arr);
            out.put("heuristic", true);
            out.put("note", "按符号名匹配，需人工复核常量表确认具体实现");
            return;
        }
        if (n.equals("Apply_Hex_Patch")) {
            String pth = opt(a, "so", "path", "file");
            String off = opt(a, "offset", "addr", "address");
            String hex = opt(a, "bytes", "hex", "value");
            if (pth == null || off == null || hex == null) {
                out.put("error", "需要 path / offset / bytes"); return;
            }
            try {
                long o2 = parseAddr(off);
                byte[] data = parseHex(hex);
                java.io.RandomAccessFile rf = new java.io.RandomAccessFile(pth, "rw");
                rf.seek(o2);
                rf.write(data);
                rf.close();
                out.put("patched", data.length);
                out.put("offset", o2);
            } catch (Exception e) {
                out.put("error", e.getMessage());
            }
            return;
        }
        if (n.equals("Address_Lookup")) {
            String addr = opt(a, "addr", "address", "offset");
            String pth = opt(a, "so", "path", "file");
            if (addr == null) { out.put("error", "需要 addr"); return; }
            long v = parseAddr(addr);
            JSONArray arr = new JSONArray();
            if (pth != null) {
                NativeAnalyzer.ElfInfo ei = NativeAnalyzer.parseElf(new File(pth));
                if (ei != null && ei.error == null) {
                    for (NativeAnalyzer.Sym sy : ei.symbols) {
                        if (v >= sy.addr && v < sy.addr + Math.max(sy.size, 1)) {
                            JSONObject o = new JSONObject();
                            o.put("symbol", sy.name); o.put("addr", sy.addr);
                            o.put("offset_in_symbol", v - sy.addr);
                            arr.put(o);
                        }
                    }
                }
            }
            out.put("addr_input", addr);
            out.put("addr", v);
            out.put("hex", "0x" + Long.toHexString(v));
            out.put("matches", arr);
            return;
        }
        if (n.equals("Rename_Function")) {
            String newName = opt(a, "name", "new_name");
            String addr = opt(a, "addr", "address", "offset");
            if (Radare2Bridge.load(ctx).ok) {
                String c = (addr != null ? ("s " + addr + "; ") : "")
                        + "afn " + (newName == null ? "" : newName);
                out.put("command", c);
                out.put("output", Radare2Bridge.cmd(c));
            } else {
                out.put("error", "radare2 不可用: " + Radare2Bridge.status());
            }
            return;
        }
        if (n.equals("Blob_Read")) {
            String id = opt(a, "blob_id", "id");
            if (id == null || !BLOBS.containsKey(id)) {
                out.put("error", "未知 blob_id: " + id);
                out.put("available", new java.util.ArrayList<String>(BLOBS.keySet()));
                return;
            }
            String full = BLOBS.get(id);
            int off = a.optInt("offset", 0);
            int len = a.optInt("length", 20000);
            if (off >= full.length()) { out.put("content", ""); out.put("eof", true); return; }
            int end = Math.min(full.length(), off + len);
            out.put("content", full.substring(off, end));
            out.put("offset", off);
            out.put("total", full.length());
            out.put("eof", end >= full.length());
            return;
        }
        if (n.equals("File_Download")) {
            String pth = opt(a, "path", "file");
            if (pth == null) { out.put("error", "缺少 path"); return; }
            File f = new File(pth);
            out.put("path", pth);
            out.put("exists", f.isFile());
            out.put("download_url", "http://<设备IP>:5051/file?path=" + pth);
            out.put("note", "需与 MCP 服务同局域网；服务端需开启 /file 端点");
            return;
        }
        if (n.startsWith("Project_")) {
            File dir = new File(ctx.getFilesDir(), "projects");
            if (!dir.exists() && !dir.mkdirs()) dir = ctx.getFilesDir();
            String projName = opt(a, "name", "project", "id");
            if (n.equals("Project_List")) {
                JSONArray arr = new JSONArray();
                File[] fs = dir.listFiles();
                if (fs != null) for (File f : fs) {
                    JSONObject o = new JSONObject();
                    o.put("name", f.getName()); o.put("size", f.length());
                    arr.put(o);
                }
                out.put("projects", arr);
                return;
            }
            if (n.equals("Project_Save") || n.equals("Project_Export")) {
                if (projName == null) { out.put("error", "需要 name"); return; }
                try {
                    File f = new File(dir, projName + ".json");
                    java.io.FileOutputStream os = new java.io.FileOutputStream(f);
                    os.write(a.toString(2).getBytes("UTF-8"));
                    os.close();
                    out.put("saved", f.getAbsolutePath());
                } catch (Exception e) { out.put("error", e.getMessage()); }
                return;
            }
            if (n.equals("Project_Load")) {
                if (projName == null) { out.put("error", "需要 name"); return; }
                File f = new File(dir, projName + ".json");
                if (!f.isFile()) { out.put("error", "项目不存在: " + projName); return; }
                byte[] d = NativeAnalyzer.readAll(f);
                out.put("project", new String(d, "UTF-8"));
                return;
            }
            if (n.equals("Project_Delete")) {
                if (projName == null) { out.put("error", "需要 name"); return; }
                File f = new File(dir, projName + ".json");
                out.put("deleted", f.isFile() && f.delete());
                return;
            }
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

        // 按 op 派生：66 个 Blutter_* 工具落到同一份解析结果的不同切片
        String bOp = EngineCommands.opFor(n);
        if (bOp != null) {
            String kw = opt(a, "keyword", "kw", "query", "q", "name", "class", "method", "type");
            out.put("op", bOp);
            if (bOp.equals("blutter.strings")) {
                int lim = a.optInt("limit", 300);
                JSONArray arr = new JSONArray();
                for (NativeAnalyzer.Str st : elf.strings) {
                    if (kw != null && !st.value.toLowerCase().contains(kw.toLowerCase())) continue;
                    JSONObject o = new JSONObject();
                    o.put("value", st.value); o.put("offset", st.offset);
                    arr.put(o);
                    if (arr.length() >= lim) break;
                }
                out.put("strings", arr);
                return;
            }
            if (bOp.equals("blutter.symbols") || bOp.equals("blutter.imports")) {
                JSONArray arr = new JSONArray();
                int lim = a.optInt("limit", 500);
                for (NativeAnalyzer.Sym sy : elf.symbols) {
                    if (kw != null && !sy.name.toLowerCase().contains(kw.toLowerCase())) continue;
                    JSONObject o = new JSONObject();
                    o.put("name", sy.name); o.put("addr", sy.addr);
                    o.put("size", sy.size); o.put("type", sy.type);
                    arr.put(o);
                    if (arr.length() >= lim) break;
                }
                out.put("symbols", arr);
                return;
            }
            if (bOp.equals("blutter.classes")) {
                JSONArray cls = new JSONArray();
                java.util.Set<String> seen = new java.util.LinkedHashSet<String>();
                int lim = a.optInt("limit", 300);
                for (NativeAnalyzer.Sym sy : syms) {
                    String cn = guessDartClass(sy.name);
                    if (cn == null) continue;
                    if (kw != null && !cn.toLowerCase().contains(kw.toLowerCase())) continue;
                    if (seen.add(cn)) cls.put(cn);
                    if (cls.length() >= lim) break;
                }
                out.put("classes", cls);
                out.put("note", "Dart AOT 快照无完整类元数据，类名为符号前缀推断（启发式）");
                return;
            }
            if (bOp.equals("blutter.class.methods") || bOp.equals("blutter.methods")) {
                JSONArray arr = new JSONArray();
                int lim = a.optInt("limit", 300);
                for (NativeAnalyzer.Sym sy : syms) {
                    String cn = guessDartClass(sy.name);
                    if (kw != null) {
                        if (cn == null || !cn.toLowerCase().contains(kw.toLowerCase())) continue;
                    }
                    if (!"FUNC".equals(sy.type)) continue;
                    JSONObject o = new JSONObject();
                    o.put("name", sy.name); o.put("addr", sy.addr);
                    o.put("size", sy.size); o.put("class", cn);
                    arr.put(o);
                    if (arr.length() >= lim) break;
                }
                out.put("methods", arr);
                return;
            }
            if (bOp.equals("blutter.urls")) {
                JSONArray arr = new JSONArray();
                for (NativeAnalyzer.Str st : elf.strings) {
                    String v = st.value;
                    if (v.startsWith("http://") || v.startsWith("https://")
                            || v.contains("/api/") || v.startsWith("ws://")) {
                        JSONObject o = new JSONObject();
                        o.put("url", v); o.put("offset", st.offset);
                        arr.put(o);
                        if (arr.length() >= 300) break;
                    }
                }
                out.put("urls", arr);
                return;
            }
            if (bOp.equals("blutter.search")) {
                if (kw == null) { out.put("error", "需要 keyword"); return; }
                JSONArray arr = new JSONArray();
                int lim = a.optInt("limit", 200);
                for (NativeAnalyzer.Sym sy : syms) {
                    if (sy.name.toLowerCase().contains(kw.toLowerCase())) {
                        JSONObject o = new JSONObject();
                        o.put("kind", "symbol"); o.put("name", sy.name);
                        o.put("addr", sy.addr);
                        arr.put(o);
                    }
                    if (arr.length() >= lim) break;
                }
                for (NativeAnalyzer.Str st : elf.strings) {
                    if (st.value.toLowerCase().contains(kw.toLowerCase())) {
                        JSONObject o = new JSONObject();
                        o.put("kind", "string"); o.put("value", st.value);
                        o.put("offset", st.offset);
                        arr.put(o);
                    }
                    if (arr.length() >= lim) break;
                }
                out.put("hits", arr);
                return;
            }
            if (bOp.equals("blutter.disasm")) {
                String r = Radare2Bridge.load(ctx).ok
                        ? Radare2Bridge.cmd("pdf @ " + (kw == null ? "entry0" : kw))
                        : null;
                out.put("disasm", r != null ? r : "radare2 不可用");
                return;
            }
            if (bOp.equals("blutter.tor2") || bOp.equals("blutter.tofrida")
                    || bOp.equals("blutter.tounidbg")) {
                JSONArray arr = new JSONArray();
                int lim = a.optInt("limit", 50);
                int c = 0;
                for (NativeAnalyzer.Sym sy : syms) {
                    if (!"FUNC".equals(sy.type)) continue;
                    if (kw != null && !sy.name.toLowerCase().contains(kw.toLowerCase())) continue;
                    JSONObject o = new JSONObject();
                    o.put("symbol", sy.name); o.put("addr", sy.addr);
                    if (bOp.equals("blutter.tor2")) o.put("r2", "s " + sy.addr + "; af; pdf");
                    if (bOp.equals("blutter.tofrida")) o.put("frida", "Interceptor.attach(Module.findBaseAddress(...).add(" + sy.addr + "), {...});");
                    if (bOp.equals("blutter.tounidbg")) o.put("unidbg", "callAddress(module, " + sy.addr + "L)");
                    arr.put(o);
                    if (++c >= lim) break;
                }
                out.put("targets", arr);
                return;
            }
            if (bOp.equals("blutter.version") || bOp.equals("blutter.aot")
                    || bOp.equals("blutter.isolate") || bOp.equals("blutter.vm")
                    || bOp.equals("blutter.lib") || bOp.equals("blutter.package")) {
                out.put("note", "Dart 运行时内部结构，内置解析只能给出符号/字符串层面的推断（启发式）");
                out.put("heuristic", true);
                JSONArray arr = new JSONArray();
                int lim = a.optInt("limit", 100);
                int c = 0;
                for (NativeAnalyzer.Str st : elf.strings) {
                    String v = st.value.toLowerCase();
                    if (v.contains("dart") || v.contains("flutter") || v.contains("isolate")) {
                        JSONObject o = new JSONObject();
                        o.put("value", st.value); o.put("offset", st.offset);
                        arr.put(o);
                        if (++c >= lim) break;
                    }
                }
                out.put("hints", arr);
                return;
            }
            if (bOp.equals("blutter.close") || bOp.equals("blutter.sessions")) {
                out.put("sessions", "内置解析无持久会话");
                return;
            }
            // 其余 op 落到概览
        }

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
            String ce = CapstoneJni.lastCallError();
            if (ce != null) {
                // 把真实签名带出去：改一次 Java 侧声明即可
                out.put("error", ce);
                out.put("hint", "so 为动态注册，签名需完全一致；"
                        + "按上面 UnsatisfiedLinkError 里的签名改 "
                        + "capstone/jni/FastDisassembler 的声明");
                return;
            }

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
    /** 存大结果并返回 blob_id。 */
    static String putBlob(String content) {
        String id = "blob_" + System.currentTimeMillis()
                + "_" + (int) (Math.random() * 1000);
        BLOBS.put(id, content == null ? "" : content);
        return id;
    }

    private java.util.Set<String> zipNames(File f) {
        java.util.Set<String> set = new java.util.LinkedHashSet<String>();
        java.util.zip.ZipFile z = null;
        try {
            z = new java.util.zip.ZipFile(f);
            java.util.Enumeration<? extends java.util.zip.ZipEntry> en = z.entries();
            while (en.hasMoreElements()) set.add(en.nextElement().getName());
        } catch (Exception ignored) {
        } finally {
            try { if (z != null) z.close(); } catch (Exception ignored) {}
        }
        return set;
    }

    private void copyZipReplacing(File src, File dst, String entry, File replace)
            throws Exception {
        java.util.zip.ZipFile z = new java.util.zip.ZipFile(src);
        java.util.zip.ZipOutputStream os =
                new java.util.zip.ZipOutputStream(new java.io.FileOutputStream(dst));
        java.util.Enumeration<? extends java.util.zip.ZipEntry> en = z.entries();
        while (en.hasMoreElements()) {
            java.util.zip.ZipEntry e = en.nextElement();
            os.putNextEntry(new java.util.zip.ZipEntry(e.getName()));
            if (e.getName().equals(entry)) {
                byte[] d = NativeAnalyzer.readAll(replace);
                os.write(d);
            } else if (!e.isDirectory()) {
                java.io.InputStream in = z.getInputStream(e);
                byte[] buf = new byte[65536];
                int rr;
                while ((rr = in.read(buf)) > 0) os.write(buf, 0, rr);
                in.close();
            }
            os.closeEntry();
        }
        os.close();
        z.close();
    }

    private String baseName(String p) {
        String b = new File(p).getName();
        int i = b.lastIndexOf('.');
        return i > 0 ? b.substring(0, i) : b;
    }

    private void listInto(File d, JSONArray arr, int depth) {
        if (d == null || !d.isDirectory() || depth > 3 || arr.length() > 500) return;
        File[] fs = d.listFiles();
        if (fs == null) return;
        for (File f : fs) {
            JSONObject o = new JSONObject();
            try {
                o.put("name", f.getName());
                o.put("dir", f.isDirectory());
                o.put("size", f.length());
            } catch (Exception ignored) {}
            arr.put(o);
            if (f.isDirectory()) listInto(f, arr, depth + 1);
        }
    }

    private void grepInto(File f, java.util.regex.Pattern P,
                          JSONArray arr, int lim, int depth) {
        if (f == null || arr.length() >= lim || depth > 3) return;
        if (f.isDirectory()) {
            File[] fs = f.listFiles();
            if (fs == null) return;
            for (File x : fs) grepInto(x, P, arr, lim, depth + 1);
            return;
        }
        if (f.length() > 8L * 1024 * 1024) return;   // 跳过超大文件
        try {
            byte[] d = NativeAnalyzer.readAll(f);
            String txt = new String(d, "UTF-8");
            String[] lines = txt.split("\n");
            for (int i = 0; i < lines.length && arr.length() < lim; i++) {
                if (P.matcher(lines[i]).find()) {
                    JSONObject o = new JSONObject();
                    o.put("file", f.getAbsolutePath());
                    o.put("line", i + 1);
                    o.put("text", lines[i].length() > 500
                            ? lines[i].substring(0, 500) : lines[i]);
                    arr.put(o);
                }
            }
        } catch (Exception ignored) {}
    }

    private void findInto(File d, String glob, JSONArray arr, int lim, int depth) {
        if (d == null || arr.length() >= lim || depth > 4) return;
        File[] fs = d.listFiles();
        if (fs == null) return;
        String g = glob == null ? null : glob.toLowerCase();
        for (File f : fs) {
            if (f.isDirectory()) { findInto(f, glob, arr, lim, depth + 1); continue; }
            if (g == null || f.getName().toLowerCase().contains(g)) {
                JSONObject o = new JSONObject();
                try {
                    o.put("path", f.getAbsolutePath());
                    o.put("size", f.length());
                } catch (Exception ignored) {}
                arr.put(o);
            }
        }
    }

    /** 地址解析：支持 0x 前缀、十进制、十六进制。 */
    private static long parseAddr(String s) {
        if (s == null) return 0;
        String t = s.trim();
        try {
            if (t.toLowerCase().startsWith("0x")) {
                return Long.parseLong(t.substring(2), 16);
            }
            return Long.parseLong(t);
        } catch (Exception e) {
            try { return Long.parseLong(t, 16); } catch (Exception e2) { return 0; }
        }
    }

    

    /** Pentest 各扫描类别对应的关键词表。 */
    private static String[] keywordsFor(String set) {
        if ("key".equals(set))  return new String[]{"aes", "rsa", "des", "hmac", "secret",
                "private_key", "apikey", "api_key", "encrypt", "cipher"};
        if ("cred".equals(set)) return new String[]{"password", "passwd", "token",
                "credential", "login", "username", "session", "cookie"};
        if ("auth".equals(set)) return new String[]{"auth", "login", "signin", "oauth",
                "bearer", "jwt", "isvip", "ismember", "license"};
        if ("pin".equals(set))  return new String[]{"pin", "certificate", "x509",
                "trustmanager", "sslcontext", "hostnameverifier"};
        if ("ssl".equals(set))  return new String[]{"ssl", "tls", "https", "certificate",
                "pinning", "trustmanager"};
        if ("sign".equals(set)) return new String[]{"sign", "signature", "md5", "sha1",
                "sha256", "hmac", "nonce", "timestamp"};
        if ("url".equals(set))  return new String[]{"http://", "https://", "/api/",
                "endpoint", "graphql", "ws://"};
        if ("c2".equals(set))   return new String[]{"c2", "command", "beacon", "bot",
                "socket", "connect", "remote"};
        if ("server".equals(set)) return new String[]{"server", "host", "domain",
                "port", "nginx", "apache", "cloudflare"};
        return new String[]{"replay", "request", "response", "http"};
    }

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

            // 交给引擎层按工具名执行具体操作（内存/hook/寄存器/回溯…）
            java.util.Map<String, String> ub = new java.util.HashMap<String, String>();
            ub.put("a1", opt(a, "addr", "address", "offset", "size", "length", "len"));
            ub.put("a2", opt(a, "value", "bytes", "hex", "data", "content"));
            ub.put("a3", opt(a, "extra"));
            String r = UnidbgEngine.op(n, sess, ub);
            if (r != null) {
                out.put("result", r);
                out.put("op", n);
                if (r.contains("失败") || r.contains("不可用")) {
                    out.put("heuristic", true);
                    out.put("note", "报错里带『可用方法』清单的，按清单改签名即可修复");
                }
                return;
            }

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
    private void frida(String n, JSONObject a, JSONObject out) throws Exception {
        // 先看是不是设备/会话管理类（Ls/Pull/Push/Rm/Start_Server/...），
        // 这类不该生成 JS 注入脚本，走 shell 或 FridaChannel
        String devOp = FridaScripts.deviceOpFor(n);
        if (devOp != null) { fridaDevice(n, devOp, a, out); return; }

        String script = opt(a, "script", "js", "code");
        if (script == null || script.trim().isEmpty()) {
            String a1 = opt(a, "module", "name", "class", "cls", "addr", "address", "package", "pkg");
            String a2 = opt(a, "size", "length", "len", "method", "symbol", "sym");
            String a3 = opt(a, "bytes", "pattern", "value");
            script = FridaScripts.scriptFor(n, a1, a2, a3);
        }
        FridaChannel.Status st = FridaChannel.probe(ctx);
        out.put("tool", n);
        out.put("frida_ready", st != null && (st.serverRunning || st.gadgetAvailable));
        out.put("rooted", st != null && st.rooted);
        if (script == null || script.trim().isEmpty()) {
            out.put("error", "该 Frida 工具无预设脚本，请通过 script 参数直接传 JS");
            out.put("hint", "Fr_Eval / Fr_Cmd 支持传入任意 JS 直接执行");
            return;
        }
        out.put("script", script);
        String target = opt(a, "target", "pid", "process", "pkg", "package");
        out.put("result", FridaChannel.execScript(ctx, target, script));
    }

    /** Frida 的设备/会话侧操作（不走 JS 注入）。 */
    private void fridaDevice(String n, String op, JSONObject a, JSONObject out)
            throws Exception {
        out.put("tool", n);
        out.put("op", op);
        String arg = opt(a, "path", "file", "target", "pid", "name", "package", "pkg");

        if (op.startsWith("server:")) {
            if (op.equals("server:start")) {
                out.put("result", FridaChannel.start(ctx));
            } else {
                out.put("result", shellOut("killall frida-server 2>/dev/null; "
                        + "pkill -f frida-server 2>/dev/null; echo done"));
            }
            FridaChannel.Status st = FridaChannel.probe(ctx);
            out.put("server_running", st != null && st.serverRunning);
            return;
        }
        if (op.startsWith("session:")) {
            FridaChannel.Status st = FridaChannel.probe(ctx);
            out.put("server_running", st != null && st.serverRunning);
            out.put("gadget_available", st != null && st.gadgetAvailable);
            out.put("rooted", st != null && st.rooted);
            if (op.equals("session:list")) {
                out.put("sessions", "本端为一次性 CLI 调用，无长驻会话池；"
                        + "每次调用即建即销");
                return;
            }
            if (op.equals("session:attach")) {
                out.put("usage", "在调用任意 Fr_* 时传 target（进程名或 pid）即可附加；"
                        + "或传 -p <pid> / -n <name>");
                return;
            }
            if (op.equals("session:spawn")) {
                out.put("usage", "冷启动注入需 frida CLI 的 -f 参数；"
                        + "当前 execScript 走附加模式，spawn 请用 Fr_Eval 配合外部 CLI");
                return;
            }
            if (op.equals("session:loadscript")) {
                String pth = opt(a, "script", "script_path", "path", "file");
                if (pth == null) { out.put("error", "需要 script 路径"); return; }
                File f = new File(pth);
                if (!f.isFile()) { out.put("error", "脚本不存在: " + pth); return; }
                byte[] d = NativeAnalyzer.readAll(f);
                out.put("script_path", pth);
                out.put("result", FridaChannel.execScript(ctx, arg,
                        new String(d, "UTF-8")));
                return;
            }
            out.put("closed", true);
            return;
        }
        // shell: 类
        String cmd = op.substring(6);
        if (cmd.contains("%s")) {
            if (arg == null) { out.put("error", "缺少 path / target"); return; }
            cmd = cmd.replace("%s", arg);
        }
        if (cmd.startsWith("write:")) {
            // Fr_Push：把本地内容写到设备路径
            String dst = cmd.substring(6);
            String content = opt(a, "content", "data", "text");
            if (content == null) { out.put("error", "需要 content"); return; }
            try {
                File f = new File(dst);
                File par = f.getParentFile();
                if (par != null && !par.exists()) par.mkdirs();
                java.io.FileOutputStream os = new java.io.FileOutputStream(f);
                os.write(content.getBytes("UTF-8"));
                os.close();
                out.put("written", dst);
                out.put("size", f.length());
            } catch (Exception e) { out.put("error", e.getMessage()); }
            return;
        }
        out.put("command", cmd);
        out.put("result", shellOut(cmd));
    }

    /** 执行一条 shell 并返回输出（尽量带 root）。 */
    private String shellOut(String cmd) {
        try {
            java.util.List<String> c = new java.util.ArrayList<String>();
            String su = null;
            try {
                java.lang.reflect.Method m = FridaChannel.class
                        .getDeclaredMethod("findSu");
                m.setAccessible(true);
                su = (String) m.invoke(null);
            } catch (Throwable ignored) {}
            if (su != null) { c.add(su); c.add("-c"); }
            c.add("sh"); c.add("-c"); c.add(cmd);
            Process pr = new ProcessBuilder(c).redirectErrorStream(true).start();
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[8192]; int r;
            java.io.InputStream is = pr.getInputStream();
            while ((r = is.read(b)) > 0) bo.write(b, 0, r);
            pr.waitFor();
            return new String(bo.toByteArray(), "UTF-8");
        } catch (Exception e) {
            return "执行失败: " + e.getMessage();
        }
    }

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
