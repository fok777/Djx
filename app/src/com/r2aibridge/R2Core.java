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
        // 由 Radare2Bridge 按依赖拓扑加载完 libr_*.so 后再加载桥
        System.loadLibrary("r2aibridge");
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
