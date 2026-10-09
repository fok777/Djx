package com.r2b.app;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Capstone 独立反汇编（JNI 桥）。
 *
 * 参照「Flutter 解析工具 8.0」的 libdisassembler.so（11.9 KB）逆向得出：
 *   Java 侧类名：capstone.jni.FastDisassembler
 *   导出方法（10 个）：
 *     nativeInitialize / nativeDestroy / setDetail
 *     disasm / getOpInfo / regsAccess
 *     regName / mapToUnicornReg / mapToCapstoneReg / cs_1free
 *   底层导入的 capstone API：
 *     cs_open / cs_close / cs_option / cs_regs_access
 *     cs_disasm / cs_free / cs_reg_name
 *
 * 为什么还要单独接一层：radare2 里虽然有 libcapstone.so，但那是给 r2
 * 自己用的；想直接对一段裸字节做反汇编（比如从内存 dump 出来的机器码），
 * 走 r2 得先建会话、打开文件、seek，太绕。这层是直通的。
 *
 * 全部反射调用：桥缺失或签名不匹配都只返回错误，不崩溃，
 * 并把实际可用的方法列出来便于修正。
 */
public final class CapstoneJni {

    private static final String TAG = "R2B_Capstone";
    private static final String BRIDGE_CLASS = "capstone.jni.FastDisassembler";
    private static final String[] LIBS = {
        "libcapstone.so",
        "libdisassembler.so",
    };

    /** 架构常量（capstone 的 cs_arch）。 */
    public static final int ARCH_ARM = 0;
    public static final int ARCH_ARM64 = 1;
    public static final int ARCH_X86 = 3;

    /** 模式（cs_mode）。 */
    public static final int MODE_LITTLE_ENDIAN = 0;
    public static final int MODE_ARM = 0;
    public static final int MODE_THUMB = 16;
    public static final int MODE_32 = 4;
    public static final int MODE_64 = 8;

    public static final class Insn {
        public long address;
        public String mnemonic;
        public String operands;
        public byte[] bytes;

        @Override public String toString() {
            return String.format("0x%x  %-10s %s", address, mnemonic,
                    operands == null ? "" : operands);
        }
    }

    private static volatile boolean loaded;
    private static volatile String loadError;

    private CapstoneJni() {}

    /** 加载桥。幂等。 */
    public static synchronized boolean load(Context c) {
        if (loaded) return true;
        File nd = EngineUnpacker.nativeDir(c);
        if (nd == null) {
            loadError = "拿不到 nativeLibraryDir";
            return false;
        }
        // capstone 本体必须在前，桥依赖它
        for (String n : LIBS) {
            File f = new File(nd, n);
            if (!f.exists()) {
                // libdisassembler.so 是可选的：没有它就用不了 JNI 桥
                if ("libcapstone.so".equals(n)) {
                    loadError = "缺少 libcapstone.so";
                    return false;
                }
                continue;
            }
            try {
                System.load(f.getAbsolutePath());
            } catch (Throwable t) {
                Log.w(TAG, "加载 " + n + " 失败: " + t.getMessage());
            }
        }
        try {
            Class.forName(BRIDGE_CLASS);
            loaded = true;
            loadError = null;
            return true;
        } catch (Throwable t) {
            loadError = "JNI 桥 " + BRIDGE_CLASS + " 不可用: " + t.getMessage();
            return false;
        }
    }

    public static String lastError() {
        return loadError;
    }

    /**
     * 反汇编一段机器码。
     *
     * @param code   原始字节
     * @param addr   起始地址
     * @param arch   ARCH_* 常量
     * @param mode   MODE_* 常量
     * @param count  最多几条，0 表示不限
     */
    public static List<Insn> disasm(byte[] code, long addr, int arch, int mode, int count) {
        List<Insn> out = new ArrayList<Insn>();
        if (!loaded) return out;
        if (code == null || code.length == 0) return out;
        try {
            Class<?> k = Class.forName(BRIDGE_CLASS);
            Object inst = k.newInstance();

            // nativeInitialize(arch, mode) -> long handle
            java.lang.reflect.Method init = findMethod(k, "nativeInitialize", 2);
            if (init == null) return out;
            init.setAccessible(true);
            Object h = init.invoke(inst, arch, mode);
            if (h == null) return out;

            try {
                java.lang.reflect.Method dis = findMethod(k, "disasm", -1);
                if (dis == null) return out;
                dis.setAccessible(true);
                Object res;
                Class<?>[] ps = dis.getParameterTypes();
                // 尝试几种可能的签名
                if (ps.length == 4) {
                    res = dis.invoke(inst, h, code, addr, count <= 0 ? 0 : count);
                } else if (ps.length == 5) {
                    res = dis.invoke(inst, h, code, addr, code.length, count <= 0 ? 0 : count);
                } else {
                    return out;
                }
                parseResult(res, out);
            } finally {
                java.lang.reflect.Method destroy = findMethod(k, "nativeDestroy", 1);
                if (destroy != null) {
                    destroy.setAccessible(true);
                    try { destroy.invoke(inst, h); } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            // 签名对不上时把真实方法列出来，便于一次修正到位
            Log.w(TAG, "disasm 失败: " + t.getClass().getSimpleName() + ": "
                    + t.getMessage() + " | 可用方法: " + availableMethods());
        }
        return out;
    }

    private static void parseResult(Object res, List<Insn> out) {
        if (res == null) return;
        if (res instanceof Object[]) {
            for (Object o : (Object[]) res) {
                Insn in = toInsn(o);
                if (in != null) out.add(in);
            }
            return;
        }
        if (res instanceof java.util.Collection) {
            for (Object o : (java.util.Collection<?>) res) {
                Insn in = toInsn(o);
                if (in != null) out.add(in);
            }
            return;
        }
        // 可能是 JSON 字符串
        if (res instanceof String) {
            try {
                org.json.JSONArray arr = new org.json.JSONArray((String) res);
                for (int i = 0; i < arr.length(); i++) {
                    org.json.JSONObject o = arr.optJSONObject(i);
                    if (o == null) continue;
                    Insn in = new Insn();
                    in.address = o.optLong("address", o.optLong("addr", 0));
                    in.mnemonic = o.optString("mnemonic", "");
                    in.operands = o.optString("op_str", o.optString("operands", ""));
                    out.add(in);
                }
            } catch (Exception ignored) {}
        }
    }

    private static Insn toInsn(Object o) {
        if (o == null) return null;
        if (o instanceof org.json.JSONObject) {
            org.json.JSONObject j = (org.json.JSONObject) o;
            Insn in = new Insn();
            in.address = j.optLong("address", j.optLong("addr", 0));
            in.mnemonic = j.optString("mnemonic", "");
            in.operands = j.optString("op_str", j.optString("operands", ""));
            return in;
        }
        // 反射取字段（桥可能返回 Java bean）
        try {
            Insn in = new Insn();
            boolean any = false;
            for (java.lang.reflect.Field f : o.getClass().getFields()) {
                f.setAccessible(true);
                String n = f.getName().toLowerCase();
                Object v = f.get(o);
                if (n.contains("addr")) { in.address = toLong(v); any = true; }
                else if (n.contains("mnemonic")) { in.mnemonic = String.valueOf(v); any = true; }
                else if (n.contains("op")) { in.operands = String.valueOf(v); any = true; }
            }
            return any ? in : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static long toLong(Object v) {
        if (v instanceof Number) return ((Number) v).longValue();
        try { return Long.parseLong(String.valueOf(v)); } catch (Exception e) { return 0; }
    }

    private static java.lang.reflect.Method findMethod(Class<?> k, String name, int argc) {
        for (java.lang.reflect.Method m : k.getDeclaredMethods()) {
            if (!m.getName().equals(name)) continue;
            if (argc >= 0 && m.getParameterTypes().length != argc) continue;
            return m;
        }
        for (java.lang.reflect.Method m : k.getMethods()) {
            if (!m.getName().equals(name)) continue;
            if (argc >= 0 && m.getParameterTypes().length != argc) continue;
            return m;
        }
        return null;
    }

    private static String availableMethods() {
        try {
            Class<?> k = Class.forName(BRIDGE_CLASS);
            StringBuilder sb = new StringBuilder();
            for (java.lang.reflect.Method m : k.getDeclaredMethods()) {
                sb.append(m.getName()).append('(');
                Class<?>[] ps = m.getParameterTypes();
                for (int i = 0; i < ps.length; i++) {
                    if (i > 0) sb.append(',');
                    sb.append(ps[i].getSimpleName());
                }
                sb.append(") ");
            }
            return sb.toString().trim();
        } catch (Throwable t) {
            return "<无法列出>";
        }
    }

    /** 状态。 */
    public static String describe(Context c) {
        File nd = EngineUnpacker.nativeDir(c);
        StringBuilder sb = new StringBuilder("capstone: loaded=").append(loaded);
        if (nd != null) {
            sb.append(" capstone.so=").append(new File(nd, "libcapstone.so").exists())
              .append(" bridge=").append(new File(nd, "libdisassembler.so").exists());
        }
        if (loadError != null) sb.append(" error=").append(loadError);
        return sb.toString();
    }
}
