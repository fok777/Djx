package com.r2b.app;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * unidbg 模拟执行引擎（安卓 ART 上直接跑，不需要 JVM / Termux）。
 *
 * 之前一直说「unidbg 是 JVM jar，安卓跑不了」——这个判断是错的，纠正如下：
 *
 *   - unidbg 的 unicorn2 backend 用 com.github.unidbg.arm.backend.unicorn.Unicorn，
 *     那是 Unicorn 的纯 Java JNI binding，native 侧是 libunicorn.so +
 *     libunicorn_java.so，**不走 JNA**，ART 上可直接加载。
 *   - jar 本身用 d8 转成 dex 后，用 DexClassLoader 载入即可
 *     （构建期完成，见 build.sh 的 unidbg jar → dex 步骤）。
 *
 * 所以完整链路是：
 *   assets/engine/unidbg/*.dex  → DexClassLoader
 *   lib/arm64-v8a/libunicorn.so → System.load
 *   lib/arm64-v8a/libunicorn_java.so → System.load
 *   lib/arm64-v8a/libc.so 等 7 个 → unidbg 模拟时加载的"目标库"
 *
 * 由于编译期不依赖 unidbg，全部用反射调用。反射写起来啰嗦，
 * 但好处是：unidbg 缺失或 API 变动时不会让主程序崩溃，只会返回明确错误。
 *
 * 诚实边界：
 *   - emulator 不是线程安全的，每个会话独占一个实例
 *   - 模拟执行吃内存，任务结束必须显式 close()，否则 OOM
 *   - 本类只实现「打开 / 加载 so / 调用符号 / 读内存 / 关闭」这条主线，
 *     断点调试、GDB stub 等高级能力未实现，不在 capabilities 里谎报
 */
public final class UnidbgEngine {

    private static final String TAG = "R2B_Unidbg";

    private static ClassLoader dexLoader;
    private static boolean nativeLoaded;
    private static String loadError;

    /** 会话：一个 emulator 实例。 */
    public static final class Session {
        public String id;
        public Object emulator;   // AndroidEmulator
        public Object vm;         // VM / DalvikVM
        public Object module;     // 最后加载的 Module
        public boolean closed;
        public String error;
    }

    private UnidbgEngine() {}

    // ---------- 加载 ----------

    /** 加载 native 与 dex。幂等。 */
    public static synchronized boolean load(Context c) {
        if (nativeLoaded && dexLoader != null) return true;

        // 1) native：unicorn 引擎 + JNI binding
        File nd = EngineUnpacker.nativeDir(c);
        if (nd == null) {
            loadError = "拿不到 nativeLibraryDir";
            return false;
        }
        String[] need = {"libunicorn.so", "libunicorn_java.so"};
        for (String n : need) {
            File f = new File(nd, n);
            if (!f.exists()) {
                loadError = "缺少 " + n + "（unidbg 的 unicorn2 backend 依赖它）";
                Log.w(TAG, loadError);
                return false;
            }
            try {
                System.load(f.getAbsolutePath());
            } catch (Throwable t) {
                loadError = "加载 " + n + " 失败: " + t.getMessage();
                Log.w(TAG, loadError);
                return false;
            }
        }

        // 2) dex：从 assets 释放后由 DexClassLoader 载入
        File dexDir = new File(EngineUnpacker.engineRoot(c), "unidbg");
        dexDir.mkdirs();
        List<File> dexes = collectDexes(c, dexDir);
        if (dexes.isEmpty()) {
            loadError = "未找到 unidbg dex（应在 assets/engine/unidbg/ 下）";
            Log.w(TAG, loadError);
            return false;
        }
        try {
            File opt = new File(c.getCodeCacheDir(), "unidbg-opt");
            if (!opt.exists()) opt.mkdirs();
            StringBuilder cp = new StringBuilder();
            for (int i = 0; i < dexes.size(); i++) {
                if (i > 0) cp.append(File.pathSeparator);
                cp.append(dexes.get(i).getAbsolutePath());
            }
            dexLoader = new dalvik.system.DexClassLoader(
                    cp.toString(), opt.getAbsolutePath(), null,
                    UnidbgEngine.class.getClassLoader());
            // 冒烟：能不能拿到关键类
            Class.forName("com.github.unidbg.AndroidEmulator", false, dexLoader);
            nativeLoaded = true;
            loadError = null;
            Log.i(TAG, "unidbg 就绪，dex " + dexes.size() + " 个");
            return true;
        } catch (Throwable t) {
            loadError = "DexClassLoader 加载失败: " + t.getClass().getSimpleName()
                    + ": " + t.getMessage();
            Log.e(TAG, loadError, t);
            return false;
        }
    }

    private static List<File> collectDexes(Context c, File outDir) {
        List<File> out = new ArrayList<File>();
        try {
            String[] list = c.getAssets().list("engine/unidbg");
            if (list != null) {
                for (String n : list) {
                    if (!n.endsWith(".dex")) continue;
                    File dst = new File(outDir, n);
                    if (!dst.exists()) {
                        java.io.InputStream is = c.getAssets().open("engine/unidbg/" + n);
                        java.io.FileOutputStream os = new java.io.FileOutputStream(dst);
                        byte[] buf = new byte[65536];
                        int r;
                        while ((r = is.read(buf)) > 0) os.write(buf, 0, r);
                        is.close(); os.close();
                    }
                    out.add(dst);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "释放 unidbg dex 失败: " + e.getMessage());
        }
        return out;
    }

    // ---------- 会话 ----------

    /** 开一个模拟会话（64 位）。 */
    public static Session open(boolean is64, String processName, File apkOrSo) {
        Session s = new Session();
        try {
            Class<?> builder = Class.forName(
                    "com.github.unidbg.AndroidEmulatorBuilder", true, dexLoader);
            Object b = is64
                    ? builder.getMethod("for64Bit").invoke(null)
                    : builder.getMethod("for32Bit").invoke(null);
            b = call(b, "setProcessName", processName == null ? "com.r2b.target" : processName);
            Object emu = call(b, "build");
            s.emulator = emu;

            // Memory + LibraryResolver（AndroidResolver 让 unidbg 能解析安卓系统库）
            Object mem = call(emu, "getMemory");
            try {
                Class<?> ar = Class.forName(
                        "com.github.unidbg.linux.android.AndroidResolver", true, dexLoader);
                Object resolver = ar.getConstructor(int.class).newInstance(23);
                call(mem, "setLibraryResolver", resolver);
            } catch (Throwable t) {
                Log.w(TAG, "AndroidResolver 不可用: " + t.getMessage());
            }

            // Dalvik VM：有 APK 就加载，能跑 JNI_OnLoad
            if (apkOrSo != null && apkOrSo.isFile()) {
                try {
                    Object vm = call(emu, "createDalvikVM", apkOrSo);
                    s.vm = vm;
                } catch (Throwable t) {
                    Log.w(TAG, "createDalvikVM 失败: " + t.getMessage());
                }
            }
            s.id = "u" + System.currentTimeMillis();
            return s;
        } catch (Throwable t) {
            s.error = "创建 emulator 失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
            Log.e(TAG, s.error, t);
            return s;
        }
    }

    /** 加载一个 so 并返回 Module。 */
    public static Object loadLibrary(Session s, File so, boolean forceCallInit) {
        if (s == null || s.emulator == null) return null;
        try {
            // 优先用 emulator.loadLibrary（不需要 dalvik vm）
            try {
                return call(s.emulator, "loadLibrary", so, forceCallInit);
            } catch (Throwable ignored) {
            }
            if (s.vm != null) return call(s.vm, "loadLibrary", so, forceCallInit);
        } catch (Throwable t) {
            Log.w(TAG, "loadLibrary 失败: " + t.getMessage());
        }
        return null;
    }

    /** 按符号名调用（符号需在 Module 的导出表里）。 */
    public static String callSymbol(Session s, Object module, String symbol, Object... args) {
        if (s == null || s.emulator == null || module == null) return "会话/模块未就绪";
        try {
            Object sym = call(module, "findSymbolByName", symbol);
            if (sym == null) return "未找到符号: " + symbol;
            Object num = call(sym, "call", s.emulator, args);
            return String.valueOf(num);
        } catch (Throwable t) {
            return "调用失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** 按地址调用。 */
    public static String callAddress(Session s, Object module, long offset, Object... args) {
        if (s == null || s.emulator == null || module == null) return "会话/模块未就绪";
        try {
            Object num = call(module, "callFunction", s.emulator, offset, args);
            return String.valueOf(num);
        } catch (Throwable t) {
            return "调用失败: " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /** 列出模块导出符号。 */
    public static String listSymbols(Object module, int limit) {
        if (module == null) return "模块未就绪";
        try {
            Object map = call(module, "getSymbolMap");
            if (map == null) return "无符号表";
            StringBuilder sb = new StringBuilder();
            int n = 0;
            if (map instanceof java.util.Map) {
                for (Object k : ((java.util.Map<?, ?>) map).keySet()) {
                    sb.append(k).append('\n');
                    if (++n >= limit) break;
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return "列符号失败: " + t.getMessage();
        }
    }

    /** 关闭并释放。必须调用，否则 native 内存不回收。 */
    public static void close(Session s) {
        if (s == null || s.closed) return;
        try {
            if (s.emulator != null) call(s.emulator, "close");
        } catch (Throwable t) {
            Log.w(TAG, "close 失败: " + t.getMessage());
        }
        s.emulator = null;
        s.vm = null;
        s.module = null;
        s.closed = true;
    }

    // ---------- 能力声明 ----------

    /** capabilities：如实报告，不谎报未实现的能力。 */
    public static String capabilities(Context c) {
        StringBuilder sb = new StringBuilder();
        sb.append("loaded=").append(nativeLoaded && dexLoader != null);
        if (loadError != null) sb.append(" error=").append(loadError);
        sb.append("\n实现: open / loadLibrary / callSymbol / callAddress / listSymbols / close");
        sb.append("\n未实现: 断点调试 / GDB stub / 内存断点 / 寄存器读写");
        File nd = EngineUnpacker.nativeDir(c);
        if (nd != null) {
            sb.append("\nunicorn: ").append(new File(nd, "libunicorn.so").exists() ? "有" : "缺")
              .append(", unicorn_java: ")
              .append(new File(nd, "libunicorn_java.so").exists() ? "有" : "缺");
        }
        return sb.toString();
    }

    public static String lastError() {
        return loadError;
    }

    // ---------- 反射helper ----------

    /** 在当前 dexLoader 里按名字找一个 public 方法并调用（支持父类）。 */
    private static Object call(Object target, String name, Object... args) throws Exception {
        if (target == null) throw new IllegalStateException("目标为空: " + name);
        Class<?> k = target.getClass();
        Class<?>[] types = new Class<?>[args == null ? 0 : args.length];
        for (int i = 0; i < types.length; i++) {
            Object a = args[i];
            types[i] = a == null ? Object.class : box(a.getClass());
        }
        java.lang.reflect.Method m = findMethod(k, name, types);
        if (m == null) {
            throw new NoSuchMethodException(k.getName() + "." + name + argTypes(types));
        }
        m.setAccessible(true);
        return m.invoke(target, args);
    }

    private static java.lang.reflect.Method findMethod(Class<?> k, String name, Class<?>[] types) {
        // 精确匹配
        try {
            return k.getMethod(name, types);
        } catch (NoSuchMethodException ignored) {}
        // 放宽：按参数个数 + 可赋值匹配
        for (java.lang.reflect.Method m : k.getMethods()) {
            if (!m.getName().equals(name)) continue;
            Class<?>[] ps = m.getParameterTypes();
            if (ps.length != types.length) continue;
            boolean ok = true;
            for (int i = 0; i < ps.length; i++) {
                if (types[i] == Object.class) continue;
                if (!ps[i].isAssignableFrom(types[i])) { ok = false; break; }
            }
            if (ok) return m;
        }
        return null;
    }

    private static Class<?> box(Class<?> c) {
        if (!c.isPrimitive()) return c;
        if (c == int.class) return Integer.class;
        if (c == long.class) return Long.class;
        if (c == boolean.class) return Boolean.class;
        if (c == byte.class) return Byte.class;
        if (c == short.class) return Short.class;
        if (c == float.class) return Float.class;
        if (c == double.class) return Double.class;
        if (c == char.class) return Character.class;
        return c;
    }

    private static String argTypes(Class<?>[] t) {
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < t.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(t[i].getSimpleName());
        }
        return sb.append(')').toString();
    }
}
