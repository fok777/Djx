package capstone.jni;

/**
 * libdisassembler.so 的 JNI 桥接类。
 *
 * 这个类的存在本身就是必需的：JNI 按「包名_类名_方法名」反查 Java 类，
 * 类不在 dex 里的话，即使 so 加载成功也会 ClassNotFoundException，
 * native 方法一个都注册不上。之前 Capstone_Disasm 报
 * "JNI 桥 capstone.jni.FastDisassembler 不可用" 就是这个原因。
 *
 * 导出方法（从 libdisassembler.so 符号表读出，共 10 个）：
 *   nativeInitialize / nativeDestroy / setDetail
 *   disasm / getOpInfo / regsAccess
 *   regName / mapToUnicornReg / mapToCapstoneReg / cs_1free
 *
 * 注意：该 so 有 JNI_OnLoad 且无 RegisterNatives 字符串符号，
 * 说明走的是动态注册——方法签名必须与 so 期望的完全一致。
 * 签名是从符号名 + capstone C API 用法推断的，未经真机验证。
 * 若注册失败，调用时会抛 UnsatisfiedLinkError，
 * 其消息里带有 so 期望的完整签名，按它改一次即可。
 *
 * 本类只声明不实现：真正的实现在 native 侧。
 */
public final class FastDisassembler {

    /** 架构常量（cs_arch）。 */
    public static final int CS_ARCH_ARM = 0;
    public static final int CS_ARCH_ARM64 = 1;
    public static final int CS_ARCH_X86 = 3;

    /** 模式（cs_mode）。 */
    public static final int CS_MODE_LITTLE_ENDIAN = 0;
    public static final int CS_MODE_ARM = 0;
    public static final int CS_MODE_THUMB = 16;
    public static final int CS_MODE_32 = 4;
    public static final int CS_MODE_64 = 8;

    public FastDisassembler() {}

    // ---- 生命周期 ----

    /** 初始化反汇编器，返回 native 句柄；失败返回 0。 */
    public native long nativeInitialize(int arch, int mode);

    /** 释放句柄。 */
    public native void nativeDestroy(long handle);

    /** 是否解析操作数细节。 */
    public native void setDetail(long handle, boolean detail);

    // ---- 反汇编 ----

    /**
     * 反汇编一段机器码。
     * 返回值实际类型取决于 so 实现（可能是 String / 数组 / 集合），
     * 调用侧统一按 Object 接住再做适配。
     */
    public native Object disasm(long handle, byte[] code, long addr, int count);

    /** 带显式长度的重载，签名不确定时提高命中率。 */
    public native Object disasm(long handle, byte[] code, long addr, int size, int count);

    // ---- 操作数 / 寄存器 ----

    public native Object getOpInfo(long handle, byte[] code, long addr);

    public native Object regsAccess(long handle, byte[] code, long addr);

    /** 取寄存器名。 */
    public native String regName(long handle, int regId);

    /** capstone 寄存器编号 → unicorn 编号。 */
    public native int mapToUnicornReg(int capstoneReg);

    /** unicorn 寄存器编号 → capstone 编号。 */
    public native int mapToCapstoneReg(int unicornReg);

    /** 释放 capstone 内部的一次性分配（对应 cs_free 的封装）。 */
    public native void cs_1free(long handle, long ptr);
}
