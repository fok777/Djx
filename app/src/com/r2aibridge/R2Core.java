package com.r2aibridge;

/**
 * radare2 JNI 桥的 Java 侧声明。
 *
 * 之前一直报 ClassNotFoundException: com.r2aibridge.R2Core——
 * 原因很直接：libr2aibridge.so 导出的方法名是
 *   Java_com_r2aibridge_R2Core_initR2Core
 *   Java_com_r2aibridge_R2Core_executeCommand
 *   Java_com_r2aibridge_R2Core_openFile
 *   Java_com_r2aibridge_R2Core_closeR2Core
 *   Java_com_r2aibridge_R2Core_testR2
 * JNI 是按「包名_类名_方法名」找 Java 类的，所以必须存在
 * com.r2aibridge.R2Core 这个类并声明对应的 native 方法，
 * 否则 so 加载成功也没法调用。
 *
 * 这个包是桥 so 自带的约定，不是我们能改的——顺着它写。
 */
public final class R2Core {

    private R2Core() {}

    static {
        // Radare2Bridge 已经按依赖拓扑用 System.load(绝对路径) 手动加载过
        // libr2aibridge.so 了。这里再 loadLibrary 一次，Android 上同一库
        // 被 load(路径) 和 loadLibrary(名) 各加载一次会被当成两个不同的库，
        // 导致桥里的 JNI 符号注册不到本类的 native 方法上，
        // 表现为 UnsatisfiedLinkError 或方法调用直接失败。
        //
        // 所以这里只在"确实还没加载"时补加载，且失败绝不抛出——
        // 抛异常会让 Class.forName 直接失败，进而整个 radare2 不可用。
        try {
            System.loadLibrary("r2aibridge");
        } catch (Throwable t) {
            android.util.Log.w("R2B_R2Core",
                    "loadLibrary 跳过（通常已由 Radare2Bridge 加载）: " + t.getMessage());
        }
    }

    /** 初始化 r_core。返回 true 表示可用。 */
    public static native boolean initR2Core();

    /** 执行一条 r2 命令，返回文本输出。 */
    public static native String executeCommand(String cmd);

    /** 打开文件（桥内部先尝试 o，失败退 oo+）。 */
    public static native boolean openFile(String path);

    /** 关闭并释放 r_core。 */
    public static native void closeR2Core();

    /** 自检：桥与 libr_core 是否联通。 */
    public static native String testR2();
}
