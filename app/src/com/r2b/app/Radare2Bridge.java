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
        // 注意：libunicorn.so / libunicorn_java.so **不能**放在这里。
        // 崩溃日志实证：它们的 JNI_OnLoad 会返回 JNI_ERR
        // （"JNI_ERR returned from JNI_OnLoad in .../libunicorn.so"），
        // 因为这两个是 unidbg 的库，不属于 radare2 依赖链，
        // 强行加载会失败并让"已加载"数永远少 2 个。
        // unidbg 走自己的 DexClassLoader 通道，与这里无关。
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

    /**
     * 总开关：是否允许真正调用 radare2 的 native 方法。
     *
     * 为什么需要它：radare2 是进程内 dlopen 的，它一旦 SIGSEGV，
     * 整个 App 进程立刻死——Java 的 try/catch 完全拦不住
     * （native 崩溃不走 Java 异常体系）。
     * 实测就是：服务起来 1.5 秒后 SIGSEGV → Force finishing activity。
     *
     * 所以默认**只加载 so、不调 native**。要真用 radare2 必须
     * 在设置里显式打开，并且用手动"测试 radare2"单独验证——
     * 崩了也只是那一次，不会拖垮整个服务。
     */
    private static volatile boolean nativeEnabled = false;

    public static void setNativeEnabled(boolean on) { nativeEnabled = on; }
    public static boolean isNativeEnabled() { return nativeEnabled; }

    /** 所有进 native 的调用都必须先过这个闸门。 */
    private static String gate() {
        if (!loaded) return "radare2 未加载: " + loadError;
        if (!nativeEnabled) {
            return "radare2 native 已禁用（设置里可开启）。\n"
                    + "原因：进程内崩溃无法用 try/catch 拦截，默认关闭以保证服务不闪退。";
        }
        return null;
    }

    /**
     * 参数校验——本次闪退的根治点。
     *
     * 崩溃栈实证：
     *   #00 r_cons_push+24          (libr_cons.so)
     *   #01 core_cmd_str_context    (libr_core.so)
     *   #02 r_core_cmd_str          (libr_core.so)
     *   #03 Java_..._executeCommand (libr2aibridge.so)
     * 崩溃前日志：Executing command: (null)
     *
     * Java 把 null 传进 native → 桥用 %s 打出 "(null)" →
     * 把 NULL 交给 r_core_cmd_str → r_cons_push 解引用 → SIGSEGV。
     * native 崩溃不走 Java 异常，try/catch 拦不住，进程直接死。
     * 所以 null / 空串一律在 Java 侧挡掉，绝不进 native。
     */
    private static String checkCmd(String command) {
        if (command == null) return "命令为 null：拒绝传给 native（否则必 SIGSEGV）";
        if (command.trim().isEmpty()) return "命令为空串：拒绝传给 native";
        return null;
    }
    private static volatile String loadError = null;
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
                // 注意：这里**不再**自动跑 initR2Core / INIT_CMDS。
                // 那会立刻进 native，若 radare2 内部不稳就整个进程 SIGSEGV。
                // 初始化推迟到用户手动点"测试 radare2"、且开关打开时才做。
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
    public static String cmd(String command) {
        String g = gate(); if (g != null) return g;
        String bad = checkCmd(command); if (bad != null) return bad;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            java.lang.reflect.Method init = k.getMethod("initR2Core");
            Object r = init.invoke(null);
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
        String g = gate(); if (g != null) return g;
        if (!loaded) return "radare2 未加载: " + loadError;
        if (path == null || path.trim().isEmpty()) return "路径为空：拒绝传给 native";
        File f = new File(path);
        if (!f.exists()) return "文件不存在: " + path;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            k.getMethod("initR2Core").invoke(null);
            Object out = k.getMethod("openFile", String.class).invoke(null, path);
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

    /**
     * 显式初始化 + 跑 INIT_CMDS。
     * 这是**唯一**会主动进 native 做初始化的入口，且必须先开总开关。
     * 放在手动按钮后面：万一 radare2 还是崩，也只崩这一次，
     * 不会在服务启动时连带整个 App 一起死。
     */
    public static String initNow() {
        String g = gate(); if (g != null) return g;
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            Object r = k.getMethod("initR2Core").invoke(null);
            sb.append("initR2Core=").append(r);
            for (String c : INIT_CMDS) {
                String bad = checkCmd(c);
                if (bad != null) {
                    sb.append("\n").append(c).append(" -> 跳过: ").append(bad);
                    continue;
                }
                sb.append("\n").append(c).append(" -> ").append(cmd(c));
            }
        } catch (Throwable t) {
            sb.append("\n初始化失败: ").append(t.getClass().getSimpleName())
              .append(": ").append(t.getMessage());
        }
        return sb.toString();
    }

    /** 自检：跑 testR2 看桥通不通。 */
    public static String test() {
        String g = gate(); if (g != null) return g;
        try {
            Class<?> k = Class.forName("com.r2aibridge.R2Core");
            k.getMethod("initR2Core").invoke(null);
            java.lang.reflect.Method m = k.getMethod("testR2");
            return String.valueOf(m.invoke(null));
        } catch (Throwable t) {
            return "自检失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
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
