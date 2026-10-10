package com.r2b.app;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * radare2 引擎加载器（JNI 桥方式，不需要 Termux）。
 *
 * 参照「Flutter 解析工具 8.0」的做法逆向得出：
 *   它把 23 个 libr_*.so + libcapstone.so + libdemumble.so 一起打进
 *   lib/arm64-v8a/，再通过 libr2aibridge.so 这个 JNI 桥调用。
 *   桥的导出符号是：
 *     Java_com_r2aibridge_R2Core_initR2Core
 *     Java_com_r2aibridge_R2Core_executeCommand
 *     Java_com_r2aibridge_R2Core_openFile
 *     Java_com_r2aibridge_R2Core_closeR2Core
 *     Java_com_r2aibridge_R2Core_testR2
 *   所以 radare2 不是靠 exec 命令行，而是 dlopen 进进程直接调 r_core_*。
 *
 * 关键点：这些 so 之间互相依赖（libr_core 依赖 libr_anal/asm/bin/io/util…），
 * 而安卓不会自动到应用私有目录里找依赖库，必须按拓扑序手动 System.load，
 * 且顺序错了会 UnsatisfiedLinkError。顺序由依赖分析得出，见 LOAD_ORDER。
 */
public final class Radare2Bridge {

    private static final String TAG = "R2B_R2";

    /** 按依赖拓扑排序的加载顺序（libr2aibridge.so 必须在 libr_core.so 之后）。 */
    private static final String[] LOAD_ORDER = {
        "libc++_shared.so",
        "libcapstone.so",
        "libkeystone.so",
        "libr_util.so",
        "libunicorn.so",
        "libdemumble.so",
        "libr_bp.so",
        "libr_config.so",
        "libr_cons.so",
        "libr_flag.so",
        "libr_magic.so",
        "libr_muta.so",
        "libr_reg.so",
        "libr_socket.so",
        "libr_syscall.so",
        "libunicorn_java.so",
        "libr_esil.so",
        "libr_fs.so",
        "libr_io.so",
        "libr_search.so",
        "libr_arch.so",
        "libr_bin.so",
        "libr_anal.so",
        "libr_asm.so",
        "libr_egg.so",
        "libr_lang.so",
        "libr_debug.so",
        "libr_core.so",
        "libr2aibridge.so",
        "libr_main.so",
    };

    /**
     * 初始化必须跑的 r2 配置命令。
     * 从 libr2aibridge.so 的字符串表逆向得出——它 initR2Core 里就执行这些：
     *   scr.color=0        关 ANSI 颜色，否则输出混着转义码
     *   scr.interactive=0  关交互，否则命令可能等输入卡死
     *   scr.utf8=0         关 UTF8 框图
     *   io.cache=true      打开 IO 缓存，读写不落盘
     *   anal.strings=true  分析时顺带抽字符串
     */
    private static final String[] INIT_CMDS = {
        "e scr.color=0",
        "e scr.interactive=false",
        "e scr.utf8=0",
        "e io.cache=true",
        "e anal.strings=true",
    };

    public static class LoadReport {
        public boolean ok;
        public List<String> loaded = new ArrayList<String>();
        public List<String> missing = new ArrayList<String>();
        public String error;
    }

    private static volatile boolean loaded = false;
    /** initR2Core 是否已成功；配合 ensureInit 使用。 */
    private static volatile boolean initDone = false;
    private static String initError = null;
    private static volatile String loadError = null;
    private static volatile java.util.List<String> lastMissing = null;
    private static final Object LOCK = new Object();

    /**
     * radare2 的 so 所在目录。
     * 打包进 lib/arm64-v8a/ 后由系统提取到 nativeLibraryDir，
     * 不再走 filesDir/engine/radare2（那条路径现在不存在）。
     */
    public static File dir(Context c) {
        File nd = EngineUnpacker.nativeDir(c);
        if (nd != null && nd.isDirectory()) return nd;
        // 兜底：老版本可能释放过
        File legacy = new File(EngineUnpacker.engineRoot(c), "radare2");
        if (legacy.isDirectory()) return legacy;
        return nd != null ? nd : legacy;
    }

    /** 加载全部 so（幂等）。 */
    public static synchronized LoadReport load(Context c) {
        LoadReport rep = new LoadReport();
        if (loaded) {
            rep.ok = true;
            return rep;
        }
        synchronized (LOCK) {
            if (loaded) {
                rep.ok = true;
                return rep;
            }
            File d = dir(c);
            if (!d.isDirectory()) {
                rep.error = "引擎目录不存在: " + d.getAbsolutePath();
                loadError = rep.error;
                lastMissing = rep.missing;
                return rep;
            }
            // 第一遍：检查缺失（缺关键库就直接放弃，避免半加载状态）
            for (String n : LOAD_ORDER) {
                File f = new File(d, n);
                if (!f.exists()) rep.missing.add(n);
            }
            // libr_core 与桥必须有，否则整个 radare2 不可用
            if (!new File(d, "libr_core.so").exists()
                    || !new File(d, "libr2aibridge.so").exists()) {
                rep.error = "缺少关键库 libr_core.so / libr2aibridge.so；缺失清单: "
                        + rep.missing;
                loadError = rep.error;
                Log.w(TAG, rep.error);
                return rep;
            }

            // 第二遍：按序加载。缺失的跳过（非关键库缺了可能仍能跑基础命令）
            for (String n : LOAD_ORDER) {
                File f = new File(d, n);
                if (!f.exists()) continue;
                try {
                    System.load(f.getAbsolutePath());
                    rep.loaded.add(n);
                } catch (Throwable t) {
                Log.w(TAG, "加载失败 " + n + ": " + t.getClass().getSimpleName()
                        + ": " + t.getMessage());
                    // 单个库失败不中断：记下来继续，最后看桥能不能用
                    Log.w(TAG, "加载失败 " + n + ": " + t.getMessage());
                    if (rep.error == null) {
                        rep.error = n + ": " + t.getMessage();
                    }
                }
            }

            // 验证：桥的 native 方法能否解析
            try {
                Class<?> k = Class.forName("com.r2aibridge.R2Core");
                k.getMethod("initR2Core");
                rep.ok = true;
                loaded = true;
                loadError = null;
                Log.i(TAG, "radare2 加载完成，已加载 " + rep.loaded.size() + " 个库");
                // 不再自动跑 INIT_CMDS。
                // 崩溃栈实证：load() 里自动执行 INIT_CMDS 会进 native，
                // 其中一条命令变成 null，r_core_cmd_str → r_cons_push 里
                // SIGSEGV（fault addr 0x166898000001ba），整个进程被带崩。
                // native 崩溃不抛 Java 异常，try/catch 拦不住。
                // 初始化推迟到真正调用工具时按需做。
                Log.i(TAG, "r2 初始化命令已执行");
            } catch (Throwable t) {
                rep.error = "JNI 桥不可用: " + t.getClass().getSimpleName()
                        + ": " + t.getMessage();
                loadError = rep.error;
                Log.e(TAG, rep.error);
            }
            return rep;
        }
    }

    public static boolean isLoaded() { return loaded; }

    /**
     * 执行一条 r2 命令。
     * 返回 String；任何失败都变成带错误说明的字符串，不抛异常。
     */
    /**
     * 确保 r_core 已初始化。返回 null 表示可用；否则返回错误说明，
     * 此时绝不能再进 native。
     *
     * 之前 cmd() 每次都无条件 initR2Core() 且从不检查返回值：
     *   · 反复创建 r_core，旧的直接泄漏
     *   · initR2Core 返回 false 时 r_core 为 NULL，仍照样 executeCommand
     *     → r_core_cmd_str(NULL,...) → core_cmd_str_context
     *     → r_cons_push 解引用 → SIGSEGV 带崩整个进程
     * （与崩溃栈完全一致）
     * 现在只 init 一次，失败即拒绝。
     */
    private static String ensureInit() {
        if (initDone) return null;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            Object r = k.getMethod("initR2Core").invoke(null);
            if (!Boolean.TRUE.equals(r)) {
                initError = "initR2Core 返回 false（r_core 为 NULL）";
                return initError;
            }
            initDone = true;
            // 注意：这里**不**跑 INIT_CMDS。
            // 2.9.3 的崩溃现场就是服务启动时自动执行这 5 条命令，
            // 其中一条在 native 里变成 null → r_cons_push SIGSEGV。
            // 即便移到 init 之后执行，风险依旧（同一次 native 调用链）。
            // 先保证能用；scr.color 等配置留到确认稳定后再加。
            return null;
        } catch (Throwable t) {
            initError = "initR2Core 失败: " + t.getClass().getSimpleName()
                    + ": " + t.getMessage();
            return initError;
        }
    }

    public static String cmd(String command) {
        if (!loaded) return "radare2 未加载: " + loadError;
        // 传 null 给 r_core_cmd_str 必崩（见上方崩溃栈），Java 侧直接挡掉
        if (command == null || command.trim().isEmpty()) {
            return "命令为空：不传给 native（会导致 SIGSEGV）";
        }
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            String ie = ensureInit();
            if (ie != null) return "radare2 未就绪，拒绝执行（避免 NULL core 崩溃）: " + ie;
            java.lang.reflect.Method exec = k.getMethod("executeCommand", String.class);
            Object out = exec.invoke(null, command == null ? "" : command.trim());
            return String.valueOf(out);
        } catch (ClassNotFoundException e) {
            return "R2Core 类不存在（桥未打进包）";
        } catch (NoSuchMethodException e) {
            // native 方法签名不匹配最有可能是这里。把可用方法一并列出，便于修正。
            return "native 方法签名不匹配: " + e.getMessage() + "；可用方法: "
                    + Arrays.toString(availableMethods());
        } catch (Throwable t) {
            return "r2 执行失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /**
     * 打开目标文件（so / 二进制 / APK）。
     *
     * 桥内部是「先 o，失败再 oo+」的双策略（见其日志字符串
     * "File opened with o: %s" / "File opened with oo+: %s"），
     * 这里同样做两次尝试，并把每次的结果都带回来便于排查。
     */
    public static String open(String path) {
        if (!loaded) return "radare2 未加载: " + loadError;
        if (path == null || path.trim().isEmpty()) return "路径为空";
        File f = new File(path);
        if (!f.exists()) return "文件不存在: " + path;
        String ie = ensureInit();
        if (ie != null) return "radare2 未就绪，拒绝打开（避免 NULL core 崩溃）: " + ie;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            Object out = k.getMethod("openFile", String.class).invoke(null, path.trim());
            String r = String.valueOf(out);
            // openFile 返回 false / 错误时，退而用 oo+ 重新打开
            if (r == null || "false".equalsIgnoreCase(r.trim())
                    || r.toLowerCase().contains("fail")) {
                String viaCmd = cmd("oo+ " + path);
                if (viaCmd != null && !viaCmd.toLowerCase().contains("fail")) {
                    return "oo+ 成功: " + viaCmd;
                }
                return "两种方式均失败。o -> " + r + " | oo+ -> " + viaCmd;
            }
            return r;
        } catch (Throwable t) {
            return "打开文件失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** 自检：跑 testR2 看桥通不通。 */
    public static String test() {
        if (!loaded) return "radare2 未加载: " + loadError;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            k.getMethod("initR2Core").invoke(null);
            java.lang.reflect.Method m = k.getMethod("testR2");
            String r = String.valueOf(m.invoke(null));
            cachedVersion = r;
            // 关键：testR2 内部跑的是 r_core_new → r_core_cmd_str → r_core_free。
            // 它结束后 core 已被释放，桥里那个静态指针成了悬空指针。
            // 之后任何 executeCommand 都在这个已释放的 core 上跑 → SIGSEGV。
            // （服务启动自检通过、但一调工具就崩，正是这个原因）
            // 所以自检完必须重新 init，把有效 core 建回来。
            initDone = false;
            String ie = ensureInit();
            if (ie != null) {
                return r + "\n[警告] 自检后重新初始化失败: " + ie
                        + "\n后续 r2 命令已被拒绝，避免崩溃。";
            }
            return r + "\n[已重新初始化 core，可供后续命令使用]";
        } catch (Throwable t) {
            return "自检失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** 启动自检拿到的版本串；R2_Version 直接用它，不再进 native。 */
    private static String cachedVersion = null;

    public static String cachedVersion() { return cachedVersion; }

    /** 是否已成功加载。 */
    /** 加载时缺失的库清单。 */
    public static java.util.List<String> missingLibs() {
        return lastMissing == null ? new java.util.ArrayList<String>() : lastMissing;
    }

    /** 当前状态摘要，供工具在 radare2 不可用时回给调用方。 */
    public static String status() {
        return loaded ? ("已加载 radare2 库")
                : ("未加载: " + loadError);
    }

    private static String[] availableMethods() {
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            java.lang.reflect.Method[] ms = k.getDeclaredMethods();
            String[] out = new String[ms.length];
            for (int i = 0; i < ms.length; i++) {
                out[i] = ms[i].getName() + "("
                        + Arrays.toString(ms[i].getParameterTypes()) + ")";
            }
            return out;
        } catch (Throwable t) {
            return new String[]{"<无法列出>"};
        }
    }

    /** 状态摘要，供 Engine_Status 展示。 */
    public static String describe(Context c) {
        File d = dir(c);
        if (!d.isDirectory()) return "radare2: 引擎目录不存在";
        int have = 0;
        for (String n : LOAD_ORDER) if (new File(d, n).exists()) have++;
        return "radare2: 库 " + have + "/" + LOAD_ORDER.length
                + "，已加载=" + loaded
                + (loadError != null ? ("，错误=" + loadError) : "");
    }
}
