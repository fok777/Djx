package com.r2b.app;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.File;

/**
 * Termux 执行通道。
 *
 * 内置 Java 引擎只能做 ELF / DEX / APK 的静态解析，跑不了真实二进制。
 * 装了 Termux 的话，就能直接执行 radare2、blutter、frida 这些真实工具，
 * 能力远超内置解析。
 *
 * 用的是 Termux 官方的 RUN_COMMAND 接口：
 *   action  com.termux.RUN_COMMAND
 *   class   com.termux / com.termux.app.RunCommandService
 *   需要 <uses-permission android:name="com.termux.permission.RUN_COMMAND"/>
 *   且用户需在 Termux 的 ~/.termux/termux.properties 里
 *   设 allow-external-apps=true（新版 Termux 默认关闭）
 *
 * 输出回收方式：把 stdout/stderr 重定向到共享文件，再轮询读取。
 * 这是最兼容的做法——不依赖 Termux 版本新增的 result 字段。
 */
public final class TermuxExecutor {

    private static final String TAG = "R2B_Termux";
    public static final String TERMUX_PKG = "com.termux";
    public static final String RUN_COMMAND_SERVICE =
            "com.termux.app.RunCommandService";
    public static final String ACTION_RUN = "com.termux.RUN_COMMAND";
    public static final String EXTRA_PATH = "com.termux.RUN_COMMAND_PATH";
    public static final String EXTRA_ARGS = "com.termux.RUN_COMMAND_ARGUMENTS";
    public static final String EXTRA_WORKDIR = "com.termux.RUN_COMMAND_WORKDIR";
    public static final String EXTRA_SERVICE = "com.termux.RUN_COMMAND_SERVICE";
    public static final String EXTRA_PENDING = "com.termux.RUN_COMMAND_PENDING_INTENT";
    public static final String EXTRA_RESULT_DIR = "com.termux.RUN_COMMAND_RESULT_DIRECTORY";
    public static final String EXTRA_RESULT_SUFFIX = "com.termux.RUN_COMMAND_RESULT_FILE_SUFFIX";
    public static final String EXTRA_RESULT_FORMAT = "com.termux.RUN_COMMAND_RESULT_FORMAT";
    public static final String EXTRA_RESULT_ERRORS = "com.termux.RUN_COMMAND_RESULT_ERRORS";
    public static final String EXTRA_RESULT_ERROR_FORMAT =
            "com.termux.RUN_COMMAND_RESULT_ERROR_FORMAT";
    public static final String EXTRA_BACKGROUND = "com.termux.RUN_COMMAND_BACKGROUND";

    public static final String PERMISSION = "com.termux.permission.RUN_COMMAND";

    private final Context ctx;

    public TermuxExecutor(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    /** Termux 是否已安装。 */
    public boolean installed() {
        try {
            PackageManager pm = ctx.getPackageManager();
            pm.getPackageInfo(TERMUX_PKG, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** 是否已拿到 RUN_COMMAND 权限。 */
    public boolean hasPermission() {
        return ctx.checkSelfPermission(PERMISSION) == PackageManager.PERMISSION_GRANTED;
    }

    /** 能否真正用起来：装了 + 有权限。 */
    public boolean usable() {
        return installed() && hasPermission();
    }

    public static class Result {
        public boolean ok;
        public String stdout;
        public String stderr;
        public int exitCode = -1;
        public String error;      // 通道层面的错误（不是命令本身）
    }

    /**
     * 在 Termux 里执行一条 shell 命令并取回输出。
     *
     * @param cmd      要执行的命令（会经 bash -lc 执行，可用 Termux 里的所有包）
     * @param timeoutMs 等待输出文件出现的上限
     */
    public Result run(String cmd, int timeoutMs) {
        Result r = new Result();
        if (!installed()) {
            r.error = "未安装 Termux";
            return r;
        }
        if (!hasPermission()) {
            r.error = "缺少 Termux RUN_COMMAND 权限（com.termux.permission.RUN_COMMAND）。"
                    + "请在系统设置里授予本应用该权限；若 Termux 版本较新，"
                    + "还需在 Termux 中执行 "
                    + "`echo allow-external-apps=true >> ~/.termux/termux.properties`";
            return r;
        }

        File outDir = ctx.getExternalFilesDir(null);
        if (outDir == null) outDir = ctx.getFilesDir();
        if (!outDir.exists()) outDir.mkdirs();
        String tag = "t" + System.currentTimeMillis();
        File out = new File(outDir, tag + ".out");
        try {
            out.createNewFile();
            out.setReadable(true, false);
        } catch (Exception e) {
            r.error = "无法创建输出文件: " + e.getMessage();
            return r;
        }

        // 包一层：把退出码也写进文件，方便判断是否真跑完
        String wrapped = "{\n" + cmd + "\n}; echo \"__EXIT__=$?\" >> " + out.getAbsolutePath();
        String full = "(" + wrapped + ") > " + out.getAbsolutePath() + " 2>&1";

        try {
            Intent i = new Intent();
            i.setClassName(TERMUX_PKG, RUN_COMMAND_SERVICE);
            i.setAction(ACTION_RUN);
            i.putExtra(EXTRA_PATH, "/data/data/com.termux/files/usr/bin/bash");
            i.putExtra(EXTRA_ARGS, new String[]{"-lc", full});
            i.putExtra(EXTRA_WORKDIR, "/data/data/com.termux/files/home");
            i.putExtra(EXTRA_BACKGROUND, false);

            // 新版 Termux 支持把结果写回指定目录，优先用它
            File resDir = new File(outDir, "termux_res");
            if (!resDir.exists()) resDir.mkdirs();
            i.putExtra(EXTRA_RESULT_DIR, resDir.getAbsolutePath());
            i.putExtra(EXTRA_RESULT_SUFFIX, tag);
            i.putExtra(EXTRA_RESULT_FORMAT, "json");
            i.putExtra(EXTRA_RESULT_ERRORS, true);
            i.putExtra(EXTRA_RESULT_ERROR_FORMAT, "yaml");

            int flags = PendingIntent.FLAG_UPDATE_CURRENT
                    | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
            PendingIntent pi = PendingIntent.getActivity(
                    ctx, 0, new Intent(), flags);
            i.putExtra(EXTRA_PENDING, pi);

            if (Build.VERSION.SDK_INT >= 26) {
                ctx.startForegroundService(i);
            } else {
                ctx.startService(i);
            }
        } catch (Exception e) {
            Log.e(TAG, "启动 Termux 失败", e);
            r.error = "启动 Termux 失败: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage();
            return r;
        }

        // 轮询输出文件
        long deadline = System.currentTimeMillis() + timeoutMs;
        String last = "";
        while (System.currentTimeMillis() < deadline) {
            try { Thread.sleep(150); } catch (InterruptedException ie) { break; }
            String txt = readFile(out);
            if (txt == null) continue;
            last = txt;
            if (txt.contains("__EXIT__=")) {
                r.ok = true;
                int p = txt.lastIndexOf("__EXIT__=");
                String after = txt.substring(p + 9).trim();
                try { r.exitCode = Integer.parseInt(after); } catch (Exception ignored) {}
                r.stdout = txt.substring(0, p).trim();
                out.delete();
                return r;
            }
        }
        r.error = "Termux 执行超时（" + timeoutMs + "ms）。"
                + (last.length() > 0 ? " 已读取到的部分输出：\n" + last : " 未读到任何输出。");
        r.stdout = last;
        return r;
    }

    private String readFile(File f) {
        try {
            if (!f.exists()) return null;
            long len = f.length();
            if (len > 4 * 1024 * 1024) return null;  // 太大不读
            byte[] d = new byte[(int) len];
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            int off = 0;
            while (off < d.length) {
                int n = in.read(d, off, d.length - off);
                if (n <= 0) break;
                off += n;
            }
            in.close();
            return new String(d, 0, off, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 探测 Termux 里装了哪些真实引擎。返回 "r2=ok,blutter=miss" 之类的串。
     */
    public String probe() {
        if (!usable()) {
            return installed() ? "Termux 已安装，但缺少 RUN_COMMAND 权限"
                    : "未安装 Termux";
        }
        String script =
            "for c in r2 radare2 rabin2 blutter frida python python3 java unzip; do "
          + "if command -v $c >/dev/null 2>&1; then echo \"$c=ok\"; else echo \"$c=miss\"; fi; "
          + "done";
        Result r = run(script, 15000);
        if (!r.ok) return "探测失败: " + r.error;
        return r.stdout.replace("\n", "  ");
    }
}
