package com.r2b.app;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * 引擎资产释放器。
 *
 * APK 的 assets/engine/ 下打包了 blutter / frida / unidbg / radare2 等引擎
 * （约 190MB）。这些是要被 exec 或 dlopen 的真实二进制，放在 APK 里不能直接执行，
 * 必须在首次启动时释放到私有目录并置可执行位。
 *
 * 目标：/data/data/com.r2b.app/files/engine/<引擎>/<文件>
 *
 * 用版本标记避免每次启动都重拷：释放完写 .unpacked-<版本号> 标记文件，
 * 下次启动若标记存在且资产清单未变，则跳过。
 */
public class EngineUnpacker {

    private static final String TAG = "R2B_Engine";
    private static final String ASSET_PREFIX = "engine/";
    private static final String STAMP = ".unpacked";

    public interface Progress {
        void onProgress(String msg);
    }

    private final Context ctx;
    private final Progress progress;

    public EngineUnpacker(Context ctx, Progress progress) {
        this.ctx = ctx;
        this.progress = progress;
    }

    /** 引擎根目录（私有目录，天然可执行）。 */
    public static File engineRoot(Context ctx) {
        File f = new File(ctx.getFilesDir(), "engine");
        if (!f.exists()) f.mkdirs();
        return f;
    }

    /** 是否已释放过。 */
    public boolean isUnpacked() {
        return new File(engineRoot(ctx), STAMP).exists();
    }

    /**
     * 释放全部引擎资产。已在后台线程调用，不要放主线程。
     * @return 释放的文件数
     */
    public int unpack() throws Exception {
        File root = engineRoot(ctx);
        AssetManager am = ctx.getAssets();
        int n = 0;

        String[] engines = am.list(ASSET_PREFIX);
        if (engines == null || engines.length == 0) {
            Log.w(TAG, "assets/engine/ 为空，跳过释放");
            return 0;
        }
        for (String eng : engines) {
            String[] files = am.list(ASSET_PREFIX + eng);
            if (files == null || files.length == 0) {
                // 可能是文件而非目录
                n += copyOne(am, ASSET_PREFIX + eng, new File(root, eng));
                continue;
            }
            File dir = new File(root, eng);
            if (!dir.exists()) dir.mkdirs();
            for (String fn : files) {
                n += copyOne(am, ASSET_PREFIX + eng + "/" + fn, new File(dir, fn));
            }
        }

        new File(root, STAMP).createNewFile();
        Log.i(TAG, "引擎释放完成，共 " + n + " 个文件 -> " + root);
        return n;
    }

    private int copyOne(AssetManager am, String assetPath, File dst) throws Exception {
        // 体积大，逐个报告进度
        long size = 0;
        try {
            android.content.res.AssetFileDescriptor fd = am.openFd(assetPath);
            size = fd.getLength();
            fd.close();
        } catch (Exception ignored) {
            // 压缩存储时取不到长度，忽略
        }
        if (progress != null) {
            String mb = size > 0 ? String.format(" (%.1f MB)", size / 1048576.0) : "";
            progress.onProgress("释放 " + dst.getName() + mb);
        }

        InputStream is = am.open(assetPath);
        OutputStream os = new FileOutputStream(dst);
        byte[] buf = new byte[65536];
        int r;
        while ((r = is.read(buf)) > 0) os.write(buf, 0, r);
        os.flush();
        os.close();
        is.close();

        // 可执行文件与共享库需要执行位
        String name = dst.getName();
        if (name.endsWith(".so") || name.endsWith(".jar")
                || name.equals("frida-server") || !name.contains(".")) {
            try {
                Runtime.getRuntime().exec(new String[]{"chmod", "755", dst.getAbsolutePath()}).waitFor();
            } catch (Exception ignored) {
                // 部分 ROM 无 chmod 命令，忽略
            }
        }
        return 1;
    }

    /** 统计已释放的引擎，供 UI 显示。 */
    public static String describe(Context ctx) {
        File root = engineRoot(ctx);
        StringBuilder sb = new StringBuilder();
        File[] dirs = root.listFiles();
        if (dirs == null) return "未释放";
        for (File d : dirs) {
            if (!d.isDirectory()) continue;
            File[] fs = d.listFiles();
            int cnt = fs == null ? 0 : fs.length;
            long sum = 0;
            if (fs != null) for (File f : fs) sum += f.length();
            sb.append(d.getName()).append(": ").append(cnt)
              .append(" 个 / ").append(String.format("%.1f", sum / 1048576.0)).append(" MB\n");
        }
        return sb.toString().trim();
    }

    /** 引擎可用性：哪些引擎目录非空。 */
    public static Set<String> available(Context ctx) {
        Set<String> s = new HashSet<String>();
        File root = engineRoot(ctx);
        File[] dirs = root.listFiles();
        if (dirs == null) return s;
        for (File d : dirs) {
            if (!d.isDirectory()) continue;
            File[] fs = d.listFiles();
            if (fs != null && fs.length > 0) s.add(d.getName());
        }
        return s;
    }
}
