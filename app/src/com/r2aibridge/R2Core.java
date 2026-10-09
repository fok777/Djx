package com.r2aibridge;

/**
 * radare2 JNI 桥的 Java 侧声明。
 *
 * 类名与包名必须严格匹配 libr2aibridge.so 里导出的符号名：
 *   Java_com_r2aibridge_R2Core_initR2Core
 *   Java_com_r2aibridge_R2Core_executeCommand
 *   Java_com_r2aibridge_R2Core_openFile
 *   Java_com_r2aibridge_R2Core_closeR2Core
 *   Java_com_r2aibridge_R2Core_testR2
 *
 * 返回值一律声明为 String：从 so 内的字符串常量
 * （"OK: r_core_cmd_str() works, version:" / "FAILED: ..."）判断，
 * 这些方法大概率返回 jstring。若实际签名不同，调用方会捕获
 * NoSuchMethodError / UnsatisfiedLinkError 并降级，不会导致进程崩溃。
 *
 * 注意：不在 static 块里 System.loadLibrary——库文件位于应用私有目录
 * （filesDir/engine/radare2/），不在系统 nativeLibraryDir，
 * 必须由调用方先用 System.load(绝对路径) 按顺序加载依赖后再加载本库。
 */
public class R2Core {

    /** 由调用方显式调用，传入 libr2aibridge.so 的绝对路径。 */
    public static void load(String bridgePath) {
        System.load(bridgePath);
    }

    public native String initR2Core();

    public native String executeCommand(String command);

    public native String openFile(String path);

    public native String closeR2Core();

    public native String testR2();
}
