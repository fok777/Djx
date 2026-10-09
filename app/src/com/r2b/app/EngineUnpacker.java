package com.r2b.app;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 引擎资产定位。
 *
 * 关键约束（这是之前一直跑不通的根因）：
 *   Android targetSdk >= 29 起，SELinux 禁止 untrusted_app 对自己应用私有目录
 *   （app_data_file，即 filesDir / cacheDir）里的文件执行 execve()。
 *   这不是 chmod 755 能绕过的——它是 SELinux 策略，不是 Unix 权限位。
 *
 * 所以 blutter 那 23 个 PIE 可执行文件、frida-server 这类要 exec 的二进制，
 * 不能从 assets/ 释放到 filesDir 再执行，那样必然失败。
 * 正确位置是 nativeLibraryDir（/data/app/<pkg>/lib/arm64/），
 * 由系统在安装时提取（需 Manifest 里 android:extractNativeLibs="true"），
 * 那里的 SELinux 标签才允许执行。
 *
 * radare2 的 libr_*.so 是 dlopen（System.load），放 nativeLibraryDir 同样最稳。
 */
public final class EngineUnpacker {

    private static final String TAG = "R2B_Engine";
    private static final String ASSET_PREFIX = "engine/";
    private static final String STAMP = ".unpacked";

    private EngineUnpacker() {}

    /** nativeLibraryDir：可执行引擎的真正位置。 */
    public static File nativeDir(Context c) {
        String p = null;
        try {
            p = c.getApplicationInfo().nativeLibraryDir;
        } catch (Exception ignored) {
        }
        return p != null ? new File(p) : null;
    }

    /** 只读数据目录（jar/js/json），这些不需要执行，放 filesDir 即可。 */
    public static File engineRoot(Context c) {
        File f = new File(c.getFilesDir(), "engine");
        if (!f.exists()) f.mkdirs();
        return f;
    }

    /** 是否已释放过只读数据。 */
    public static boolean isUnpacked(Context c) {
        return new File(engineRoot(c), STAMP).exists();
    }

    /**
     * 找一个可执行文件（blutter / frida-server 等）。
     * 只在 nativeLibraryDir 里找——filesDir 里的 execve 会被 SELinux 拒绝。
     */
    public static File findExecutable(Context c, String name) {
        File nd = nativeDir(c);
        if (nd == null) return null;
        File direct = new File(nd, name);
        if (direct.exists() && direct.canExecute()) return direct;
        File[] fs = nd.listFiles();
        if (fs != null) {
            for (File f : fs) {
                if (f.getName().equals(name) && f.canExecute()) return f;
            }
        }
        return null;
    }

    /** 列出 nativeLibraryDir 里所有 .so（按名字分组给 blutter 用）。 */
    public static List<File> listNativeLibs(Context c, String prefix) {
        List<File> out = new ArrayList<File>();
        File nd = nativeDir(c);
        if (nd == null || !nd.isDirectory()) return out;
        File[] fs = nd.listFiles();
        if (fs == null) return out;
        for (File f : fs) {
            if (f.getName().startsWith(prefix) && f.getName().endsWith(".so")) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * 可执行文件是否真的能跑。
     * 直接试一次 exec（用 -h/--help 之类无害参数），失败就把 stderr 带回来，
     * 这样日志里能一眼看出是 SELinux 拒绝还是别的原因。
     */
    public static String tryExec(File exe, String... args) {
        if (exe == null) return "可执行文件不存在";
        if (!exe.canExecute()) {
            return "不可执行（SELinux 或权限位）: " + exe.getAbsolutePath();
        }
        try {
            List<String> cmd = new ArrayList<String>();
            cmd.add(exe.getAbsolutePath());
            if (args != null) for (String a : args) cmd.add(a);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.directory(exe.getParentFile());
            pb.redirectErrorStream(true);
            // 关键：exec 一个 PIE 可执行文件时，Android linker 只在默认路径
            // （/system/lib64 等）解析 DT_NEEDED，不会自动搜 nativeLibraryDir。
            // 不设 LD_LIBRARY_PATH 就会报
            // "Cannot link executable ... libc++_shared.so not found"。
            String libPath = exe.getParent();
            String oldLd = pb.environment().get("LD_LIBRARY_PATH");
            pb.environment().put("LD_LIBRARY_PATH",
                    oldLd == null || oldLd.isEmpty() ? libPath : libPath + ":" + oldLd);
            Process p = pb.start();
            java.io.InputStream is = p.getInputStream();
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            long total = 0;
            while ((r = is.read(buf)) > 0 && total < 8192) {
                bo.write(buf, 0, r);
                total += r;
            }
            is.close();
            int code = p.waitFor();
            String out = new String(bo.toByteArray(), "UTF-8").trim();
            // CANNOT LINK EXECUTABLE 是 Android linker 的特有报错：
            // 常见原因是缺 libc++_shared.so，或 _Unwind_* 这类
            // 来自 libgcc/libunwind 的符号在目标 ROM 上找不到。
            if (out.contains("CANNOT LINK EXECUTABLE")) {
                String missing = "";
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("cannot locate symbol \\"([^\\"]+)\\"")
                        .matcher(out);
                if (m.find()) missing = m.group(1);
                return "link失败 exit=" + code + " 缺符号=" + (missing.isEmpty() ? "?" : missing)
                        + "\n  已设 LD_LIBRARY_PATH=" + libPath
                        + "\n  该符号通常来自 libc++_shared.so / libunwind；"
                        + "确认 nativeLibraryDir 下有这些库。"
                        + "\n  原始: " + out.replace("\n", " | ");
            }
            return "exit=" + code + " 输出: " + out;
        } catch (Exception e) {
            return "exec 失败: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    /**
     * 列出 nativeLibraryDir 下的库名，用于排查 link 失败。
     * 日志里能一眼看出缺了 libc++_shared.so 还是别的。
     */
    public static String listNativeLibs(Context c) {
        File nd = nativeDir(c);
        if (nd == null || !nd.isDirectory()) return "nativeLibraryDir 不可用";
        File[] fs = nd.listFiles();
        if (fs == null) return "(空)";
        StringBuilder sb = new StringBuilder();
        java.util.List<String> names = new java.util.ArrayList<String>();
        for (File f : fs) names.add(f.getName());
        java.util.Collections.sort(names);
        for (String n : names) sb.append(n).append(' ');
        return sb.toString().trim();
    }

    /** 状态摘要，写进日志。 */
    public static String describe(Context c) {
        StringBuilder sb = new StringBuilder();
        File nd = nativeDir(c);
        sb.append("nativeLibraryDir=").append(nd == null ? "null" : nd.getAbsolutePath());
        if (nd != null && nd.isDirectory()) {
            File[] fs = nd.listFiles();
            int n = fs == null ? 0 : fs.length;
            sb.append("\n  可执行文件 ").append(n).append(" 个");
            int exec = 0;
            if (fs != null) {
                for (File f : fs) {
                    if (f.canExecute()) exec++;
                }
            }
            sb.append("，其中可执行位为真的 ").append(exec).append(" 个");
        }
        sb.append("\n  engineRoot=").append(engineRoot(c).getAbsolutePath());
        return sb.toString();
    }

    /** 释放只读数据（jar/js/json），可执行文件不在这里。 */
    public static int unpackAssets(Context c) {
        File root = engineRoot(c);
        if (isUnpacked(c)) return 0;
        int n = 0;
        try {
            android.content.res.AssetManager am = c.getAssets();
            String[] engines = am.list(ASSET_PREFIX);
            if (engines == null) return 0;
            for (String eng : engines) {
                String[] files = am.list(ASSET_PREFIX + eng);
                if (files == null) continue;
                File d = new File(root, eng);
                if (!d.exists()) d.mkdirs();
                for (String fn : files) {
                    if (fn.startsWith(".")) continue;
                    java.io.InputStream in = null;
                    java.io.FileOutputStream os = null;
                    try {
                        in = am.open(ASSET_PREFIX + eng + "/" + fn);
                        os = new java.io.FileOutputStream(new File(d, fn));
                        byte[] buf = new byte[65536];
                        int r;
                        while ((r = in.read(buf)) > 0) os.write(buf, 0, r);
                        n++;
                    } catch (Exception e) {
                        Log.w(TAG, "释放失败 " + eng + "/" + fn + ": " + e.getMessage());
                    } finally {
                        if (in != null) try { in.close(); } catch (Exception ignored) {}
                        if (os != null) try { os.close(); } catch (Exception ignored) {}
                    }
                }
            }
            new File(root, STAMP).createNewFile();
        } catch (Exception e) {
            Log.e(TAG, "释放异常", e);
        }
        return n;
    }
}
