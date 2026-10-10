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

            // _Unwind_Resume：blutter 全部 23 个版本都引用它，但它的 DT_NEEDED
            // 里没有 libunwind.so——也就是说这个符号原本指望系统 /system/lib64
            // 提供，Android 10+ 已经不再提供，于是报
            // "CANNOT LINK EXECUTABLE ... cannot locate symbol _Unwind_Resume"。
            //
            // 解法：LD_PRELOAD 强制预加载 libcpp.so（它实为 Android 的 libunwind，
            // 导出 18 个 _Unwind_* 含 _Unwind_Resume），符号就进了全局符号表。
            // 不加进 LD_LIBRARY_PATH 是因为 linker 只加载 DT_NEEDED 列出的库，
            // 光放同目录也没用——必须 PRELOAD。
            File unwind = new File(exe.getParentFile(), "libcpp.so");
            if (!unwind.exists()) unwind = new File(exe.getParentFile(), "libunwind.so");
            if (unwind.exists()) {
                pb.environment().put("LD_PRELOAD", unwind.getAbsolutePath());
            }
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
            // exit=139 = 128+SIGSEGV(11)：进程**已经启动并跑起来了**，
            // 只是 blutter 不带参数会直接崩。相比之前的
            // "CANNOT LINK EXECUTABLE"，这恰恰说明链接问题已解决。
            // 不把它当失败，否则会误导排查方向。
            if (code == 139) {
                return "可启动（exit=139 SIGSEGV，无参数调用属预期）\n"
                        + "  LD_LIBRARY_PATH=" + libPath
                        + "\n  LD_PRELOAD=" + pb.environment().get("LD_PRELOAD");
            }
            // CANNOT LINK EXECUTABLE 是 Android linker 的特有报错：
            // 常见原因是缺 libc++_shared.so，或 _Unwind_* 这类
            // 来自 libgcc/libunwind 的符号在目标 ROM 上找不到。
            if (out.contains("CANNOT LINK EXECUTABLE")) {
                String missing = "";
                // 不用正则：避免 Java/正则双重转义出错，直接找符号名
                int k = out.indexOf("cannot locate symbol");
                if (k >= 0) {
                    int s1 = out.indexOf('"', k);
                    if (s1 >= 0) {
                        int s2 = out.indexOf('"', s1 + 1);
                        if (s2 > s1) missing = out.substring(s1 + 1, s2);
                    }
                }
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
