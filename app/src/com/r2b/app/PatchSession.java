package com.r2b.app;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 补丁编辑会话：snapshot / undo / redo / rollback / audit。
 *
 * 借鉴 SoMCP 的编辑会话设计。之前的问题很直接：
 * 改坏了就没法回头——原文件被直接覆盖，只能重新解包。
 *
 * 做法：
 *   - 每次修改前先快照原始文件（全量拷贝，简单可靠）
 *   - 修改累加成版本链 v1 → v2 → v3
 *   - undo 回到上一版，redo 前进，rollback 回初版
 *   - audit 列出全部版本与改动原因，可导出
 *
 * 工作目录：files/sessions/<session_id>/
 *   base      原始文件
 *   vN        第 N 次修改后的文件
 *   history   文本记录（时间 / 动作 / 说明）
 */
public final class PatchSession {

    public static class Info {
        public String id;
        public File workDir;
        public int version;          // 当前版本号，0 = 未修改
        public int maxVersion;       // 版本链末端
        public String targetName;
        public List<String> audit = new ArrayList<String>();
        public String error;
    }

    private PatchSession() {}

    private static File root(Context c) {
        File f = new File(c.getFilesDir(), "sessions");
        if (!f.exists()) f.mkdirs();
        return f;
    }

    /** 开一个会话：先把目标文件快照为 base。 */
    public static Info open(Context c, String targetPath, String note) {
        Info info = new Info();
        File src = new File(targetPath);
        if (!src.isFile()) {
            info.error = "目标文件不存在: " + targetPath;
            return info;
        }
        String id = "s" + System.currentTimeMillis();
        File dir = new File(root(c), id);
        if (!dir.exists() && !dir.mkdirs()) {
            info.error = "无法创建会话目录";
            return info;
        }
        info.id = id;
        info.workDir = dir;
        info.targetName = src.getName();
        try {
            copy(src, new File(dir, "base"));
            copy(src, new File(dir, "v0"));
        } catch (Exception e) {
            info.error = "快照失败: " + e.getMessage();
            return info;
        }
        appendHistory(dir, "open " + src.getAbsolutePath() + " | " + str(note));
        info.maxVersion = 0;
        info.version = 0;
        info.audit = readHistory(dir);
        return info;
    }

    /** 提交一次修改：把新内容写成 v(N+1)。 */
    public static Info commit(Context c, String sessionId, File newContent, String note) {
        Info info = load(c, sessionId);
        if (info.error != null) return info;
        int next = info.maxVersion + 1;
        File dst = new File(info.workDir, "v" + next);
        try {
            copy(newContent, dst);
        } catch (Exception e) {
            info.error = "写入 v" + next + " 失败: " + e.getMessage();
            return info;
        }
        appendHistory(info.workDir, "commit v" + next + " | " + str(note));
        return load(c, sessionId);
    }

    /** 撤销：当前版本 -1。 */
    public static Info undo(Context c, String sessionId) {
        Info info = load(c, sessionId);
        if (info.error != null) return info;
        if (info.version <= 0) {
            info.error = "已在最初版本，无法撤销";
            return info;
        }
        info.version--;
        appendHistory(info.workDir, "undo -> v" + info.version);
        return info;
    }

    /** 重做：当前版本 +1（不超过 maxVersion）。 */
    public static Info redo(Context c, String sessionId) {
        Info info = load(c, sessionId);
        if (info.error != null) return info;
        if (info.version >= info.maxVersion) {
            info.error = "已是最新版本，无法重做";
            return info;
        }
        info.version++;
        appendHistory(info.workDir, "redo -> v" + info.version);
        return info;
    }

    /** 回到最初版本。 */
    public static Info rollback(Context c, String sessionId) {
        Info info = load(c, sessionId);
        if (info.error != null) return info;
        info.version = 0;
        appendHistory(info.workDir, "rollback -> v0 (base)");
        return info;
    }

    /** 取当前版本的文件。 */
    public static File current(Context c, String sessionId) {
        Info info = load(c, sessionId);
        if (info.error != null || info.workDir == null) return null;
        File f = new File(info.workDir, "v" + info.version);
        return f.exists() ? f : null;
    }

    /** 把当前版本写回目标路径。 */
    public static String apply(Context c, String sessionId, String targetPath) {
        File cur = current(c, sessionId);
        if (cur == null) return "当前版本不存在";
        try {
            // 写回前先备份目标，避免覆盖后无法恢复
            File t = new File(targetPath);
            if (t.exists()) {
                File bak = new File(t.getAbsolutePath() + ".r2bbak");
                copy(t, bak);
            }
            copy(cur, t);
            Info info = load(c, sessionId);
            if (info.workDir != null) {
                appendHistory(info.workDir, "apply -> " + targetPath);
            }
            return "已写入 " + targetPath + "（原文件备份为 .r2bbak）";
        } catch (Exception e) {
            return "写回失败: " + e.getMessage();
        }
    }

    /** 读取会话状态。 */
    public static Info load(Context c, String sessionId) {
        Info info = new Info();
        File dir = new File(root(c), sessionId);
        if (!dir.isDirectory()) {
            info.error = "会话不存在: " + sessionId;
            return info;
        }
        info.id = sessionId;
        info.workDir = dir;
        int max = 0;
        File[] fs = dir.listFiles();
        if (fs != null) {
            for (File f : fs) {
                String n = f.getName();
                if (n.startsWith("v") && n.length() > 1) {
                    try {
                        int v = Integer.parseInt(n.substring(1));
                        if (v > max) max = v;
                    } catch (NumberFormatException ignored) {}
                }
            }
        }
        info.maxVersion = max;
        info.version = readCurrentVersion(dir, max);
        info.audit = readHistory(dir);
        return info;
    }

    /** 列出所有会话。 */
    public static List<String> list(Context c) {
        List<String> out = new ArrayList<String>();
        File[] fs = root(c).listFiles();
        if (fs == null) return out;
        for (File f : fs) {
            if (f.isDirectory()) out.add(f.getName());
        }
        return out;
    }

    // ---------- 内部 ----------

    private static int readCurrentVersion(File dir, int max) {
        File cur = new File(dir, ".current");
        if (cur.exists()) {
            try {
                byte[] b = new byte[32];
                FileInputStream is = new FileInputStream(cur);
                int n = is.read(b);
                is.close();
                if (n > 0) {
                    int v = Integer.parseInt(new String(b, 0, n, "UTF-8").trim());
                    if (v >= 0 && v <= max) return v;
                }
            } catch (Exception ignored) {}
        }
        return max;
    }

    private static void setCurrentVersion(File dir, int v) {
        try {
            FileOutputStream os = new FileOutputStream(new File(dir, ".current"));
            os.write(String.valueOf(v).getBytes("UTF-8"));
            os.close();
        } catch (Exception ignored) {}
    }

    private static void appendHistory(File dir, String line) {
        try {
            String ts = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new Date());
            FileOutputStream os = new FileOutputStream(new File(dir, "history"), true);
            os.write(("[" + ts + "] " + line + "\n").getBytes("UTF-8"));
            os.close();
        } catch (Exception ignored) {}
    }

    private static List<String> readHistory(File dir) {
        List<String> out = new ArrayList<String>();
        File h = new File(dir, "history");
        if (!h.exists()) return out;
        try {
            FileInputStream is = new FileInputStream(h);
            byte[] b = new byte[(int) h.length()];
            int n = is.read(b);
            is.close();
            if (n > 0) {
                for (String s : new String(b, 0, n, "UTF-8").split("\n")) {
                    if (!s.trim().isEmpty()) out.add(s.trim());
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    private static void copy(File src, File dst) throws Exception {
        FileInputStream is = new FileInputStream(src);
        FileOutputStream os = new FileOutputStream(dst);
        byte[] buf = new byte[65536];
        int n;
        while ((n = is.read(buf)) > 0) os.write(buf, 0, n);
        is.close();
        os.close();
    }

    private static String str(String s) {
        return s == null ? "" : s.replace("\n", " ");
    }

    /** undo/redo/rollback 后需要落盘当前版本号——由调用方触发。 */
    public static void persistVersion(Info info) {
        if (info != null && info.workDir != null) {
            setCurrentVersion(info.workDir, info.version);
        }
    }
}
