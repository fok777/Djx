package com.r2b.app;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 纯 Java 二进制解析引擎（ELF / DEX / APK）。
 *
 * 为什么不用 JNI：应用内的 libr2aibridge.so 是第三方桥，其 native 方法签名
 * 不可考，签名不匹配会直接 UnsatisfiedLinkError 崩溃。而 ELF/DEX/APK 的格式
 * 是完全公开且有规范的，用纯 Java 解析零依赖、零崩溃风险，
 * 覆盖逆向分析里最常用的那部分能力。
 */
public final class NativeAnalyzer {

    private NativeAnalyzer() {}

    // ---------- ELF ----------

    /** ELF 解析结果。 */
    public static class ElfInfo {
        public String path;
        public String arch;         // arm64 / arm32 / x86_64 / x86
        public String machine;      // 原始 e_machine 名
        public int type;            // ET_DYN / ET_EXEC
        public boolean isPie;
        public long entry;
        public List<String> sections = new ArrayList<String>();
        public List<Sym> symbols = new ArrayList<Sym>();
        public List<Str> strings = new ArrayList<Str>();
        public String error;
    }

    public static class Sym {
        public String name;
        public long addr;
        public long size;
        public String type;
        public Sym(String n, long a, long s, String t) { name = n; addr = a; size = s; type = t; }
    }

    public static class Str {
        public String value;
        public long offset;
        public Str(String v, long o) { value = v; offset = o; }
    }

    private static final int ET_EXEC = 2, ET_DYN = 3;
    private static final int SHT_SYMTAB = 2, SHT_STRTAB = 3;

    /** 解析 ELF（.so / 可执行文件）。 */
    public static ElfInfo parseElf(File f) {
        ElfInfo out = new ElfInfo();
        out.path = f.getAbsolutePath();
        byte[] d;
        try {
            d = readAll(f);
        } catch (Exception e) {
            out.error = "读取失败: " + e.getMessage();
            return out;
        }
        if (d.length < 64 || d[0] != 0x7f || d[1] != 'E' || d[2] != 'L' || d[3] != 'F') {
            out.error = "不是 ELF 文件";
            return out;
        }
        try {
            boolean is64 = (d[4] == 2);
            ByteBuffer b = ByteBuffer.wrap(d);
            b.order(d[5] == 1 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            int eType = b.getShort(16) & 0xffff;
            int eMachine = b.getShort(18) & 0xffff;
            long eEntry, eShoff, ePhoff;
            int eShnum, eShstrndx, ePhentsize, ePhnum, eShentsize;
            if (is64) {
                eEntry = b.getLong(24);
                ePhoff = b.getLong(32);
                eShoff = b.getLong(40);
                ePhentsize = b.getShort(54) & 0xffff;
                ePhnum = b.getShort(56) & 0xffff;
                eShentsize = b.getShort(58) & 0xffff;
                eShnum = b.getShort(60) & 0xffff;
                eShstrndx = b.getShort(62) & 0xffff;
            } else {
                eEntry = b.getInt(24) & 0xffffffffL;
                ePhoff = b.getInt(28) & 0xffffffffL;
                eShoff = b.getInt(32) & 0xffffffffL;
                ePhentsize = b.getShort(42) & 0xffff;
                ePhnum = b.getShort(44) & 0xffff;
                eShentsize = b.getShort(46) & 0xffff;
                eShnum = b.getShort(48) & 0xffff;
                eShstrndx = b.getShort(50) & 0xffff;
            }
            out.type = eType;
            out.isPie = eType == ET_DYN;
            out.entry = eEntry;
            out.machine = machineName(eMachine);
            out.arch = archOf(eMachine);

            // 段头：找 PT_LOAD 判断可执行
            for (int i = 0; i < ePhnum; i++) {
                long off = ePhoff + (long) i * ePhentsize;
                if (off + (is64 ? 56 : 32) > d.length) break;
                int pType = b.getInt((int) off) & 0xffffffff;
                if (pType == 1) { // PT_LOAD
                    long pFlags;
                    if (is64) pFlags = b.getLong((int) off + 4);
                    else pFlags = b.getInt((int) off + 24) & 0xffffffffL;
                    if ((pFlags & 0x1) != 0) { /* 可执行段 */ }
                }
            }

            // 节头表
            if (eShoff > 0 && eShnum > 0 && eShoff + (long) eShnum * eShentsize <= d.length) {
                int[] shName = new int[eShnum];
                int[] shType = new int[eShnum];
                long[] shOff = new long[eShnum];
                long[] shSize = new long[eShnum];
                int[] shLink = new int[eShnum];
                int[] shEntsize = new int[eShnum];
                for (int i = 0; i < eShnum; i++) {
                    long o = eShoff + (long) i * eShentsize;
                    shName[i] = b.getInt((int) o) & 0xffffffff;
                    shType[i] = b.getInt((int) o + 4) & 0xffffffff;
                    if (is64) {
                        shOff[i] = b.getLong((int) o + 24);
                        shSize[i] = b.getLong((int) o + 32);
                        shLink[i] = b.getInt((int) o + 40) & 0xffff;
                        shEntsize[i] = (int) (b.getLong((int) o + 56) & 0xffffffffL);
                    } else {
                        shOff[i] = b.getInt((int) o + 16) & 0xffffffffL;
                        shSize[i] = b.getInt((int) o + 20) & 0xffffffffL;
                        shLink[i] = b.getInt((int) o + 24) & 0xffff;
                        shEntsize[i] = b.getInt((int) o + 36) & 0xffff;
                    }
                }
                // 节名字符串表
                byte[] shstr = null;
                if (eShstrndx < eShnum) {
                    shstr = slice(d, shOff[eShstrndx], shSize[eShstrndx]);
                }
                for (int i = 0; i < eShnum; i++) {
                    String nm = shstr != null ? cstr(shstr, shName[i]) : ("#" + i);
                    if (nm != null && nm.length() > 0) out.sections.add(nm);
                }
                // 符号表 + 字符串
                for (int i = 0; i < eShnum; i++) {
                    if (shType[i] != SHT_SYMTAB || shLink[i] >= eShnum) continue;
                    byte[] strtab = slice(d, shOff[shLink[i]], shSize[shLink[i]]);
                    if (strtab == null) continue;
                    int esz = shEntsize[i] > 0 ? shEntsize[i] : (is64 ? 24 : 16);
                    long cnt = shSize[i] / esz;
                    for (long k = 0; k < cnt && out.symbols.size() < 30000; k++) {
                        long so = shOff[i] + k * esz;
                        if (so + esz > d.length) break;
                        int stName;
                        long stValue, stSize;
                        int stInfo;
                        if (is64) {
                            stName = b.getInt((int) so) & 0xffffffff;
                            stInfo = d[(int) so + 4] & 0xff;
                            stValue = b.getLong((int) so + 8);
                            stSize = b.getLong((int) so + 16);
                        } else {
                            stName = b.getInt((int) so) & 0xffffffff;
                            stValue = b.getInt((int) so + 4) & 0xffffffffL;
                            stSize = b.getInt((int) so + 8) & 0xffffffffL;
                            stInfo = d[(int) so + 12] & 0xff;
                        }
                        String nm = cstr(strtab, stName);
                        if (nm == null || nm.length() == 0) continue;
                        out.symbols.add(new Sym(nm, stValue, stSize, symType(stInfo & 0xf)));
                    }
                }
            }

            // 字符串提取（覆盖 .rodata / .dynstr，Dart/Unity 符号常在这）
            out.strings = extractStrings(d, 5, 4000);
        } catch (Exception e) {
            out.error = "解析异常: " + e.getMessage();
        }
        return out;
    }

    private static String symType(int t) {
        switch (t) {
            case 0: return "NOTYPE";
            case 1: return "OBJECT";
            case 2: return "FUNC";
            case 3: return "SECTION";
            case 4: return "FILE";
            case 6: return "TLS";
            case 10: return "GNU_IFUNC";
            default: return "OTHER";
        }
    }

    private static String machineName(int m) {
        switch (m) {
            case 0x28: return "ARM";
            case 0xB7: return "AArch64";
            case 0x03: return "386";
            case 0x3E: return "X86_64";
            case 0x08: return "MIPS";
            default: return "0x" + Integer.toHexString(m);
        }
    }

    private static String archOf(int m) {
        switch (m) {
            case 0xB7: return "arm64-v8a";
            case 0x28: return "armeabi-v7a";
            case 0x3E: return "x86_64";
            case 0x03: return "x86";
            default: return "unknown";
        }
    }

    /** 从任意二进制提取可打印字符串（含偏移）。 */
    public static List<Str> extractStrings(byte[] d, int minLen, int limit) {
        List<Str> out = new ArrayList<Str>();
        StringBuilder cur = new StringBuilder();
        int start = -1;
        for (int i = 0; i < d.length && out.size() < limit; i++) {
            int c = d[i] & 0xff;
            boolean ok = (c >= 0x20 && c < 0x7f) || c == '\t';
            if (ok) {
                if (start < 0) start = i;
                cur.append((char) c);
            } else {
                if (cur.length() >= minLen) {
                    out.add(new Str(cur.toString(), start));
                }
                cur.setLength(0);
                start = -1;
            }
        }
        if (cur.length() >= minLen) out.add(new Str(cur.toString(), start));
        return out;
    }

    // ---------- DEX ----------

    public static class DexInfo {
        public String path;
        public int version;
        public List<String> strings = new ArrayList<String>();
        public List<String> typeNames = new ArrayList<String>();
        public String error;
    }

    /** 解析 DEX 字符串池与类型名（classes.dex / classes2.dex ...）。 */
    public static DexInfo parseDex(File f) {
        DexInfo out = new DexInfo();
        out.path = f.getAbsolutePath();
        byte[] d;
        try {
            d = readAll(f);
        } catch (Exception e) {
            out.error = "读取失败: " + e.getMessage();
            return out;
        }
        try {
            ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
            // magic "dex\n035\0"
            if (d.length < 112 || d[0] != 'd' || d[1] != 'e' || d[2] != 'x') {
                out.error = "不是 DEX 文件";
                return out;
            }
            out.version = Integer.parseInt(new String(d, 4, 3));
            int strIdsSize = b.getInt(56);
            int strIdsOff = b.getInt(60);
            int typeIdsSize = b.getInt(64);
            int typeIdsOff = b.getInt(68);

            // 字符串池
            for (int i = 0; i < strIdsSize && out.strings.size() < 20000; i++) {
                long off = (strIdsOff & 0xffffffffL) + (long) i * 4;
                if (off + 4 > d.length) break;
                int dataOff = b.getInt((int) off);
                String s = dexString(d, dataOff);
                if (s != null) out.strings.add(s);
            }
            // 类型名
            for (int i = 0; i < typeIdsSize && out.typeNames.size() < 20000; i++) {
                long off = (typeIdsOff & 0xffffffffL) + (long) i * 4;
                if (off + 4 > d.length) break;
                int descIdx = b.getInt((int) off);
                if (descIdx >= 0 && descIdx < out.strings.size()) {
                    out.typeNames.add(dexToJava(out.strings.get(descIdx)));
                }
            }
        } catch (Exception e) {
            out.error = "解析异常: " + e.getMessage();
        }
        return out;
    }

    private static String dexString(byte[] d, int off) {
        if (off < 0 || off >= d.length) return null;
        // MUTF-8: 开头是 ULEB128 长度
        int p = off, len = 0, shift = 0;
        while (p < d.length) {
            int v = d[p++] & 0xff;
            len |= (v & 0x7f) << shift;
            if ((v & 0x80) == 0) break;
            shift += 7;
        }
        if (p + len > d.length || len <= 0) return null;
        try {
            return new String(d, p, len, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    /** L 类型描述符 -> Java 类名。 */
    public static String dexToJava(String desc) {
        if (desc == null) return desc;
        if (desc.startsWith("L") && desc.endsWith(";")) {
            return desc.substring(1, desc.length() - 1).replace('/', '.');
        }
        return desc;
    }

    // ---------- APK ----------

    public static class ApkInfo {
        public String path;
        public long size;
        public List<String> entries = new ArrayList<String>();
        public List<String> dexes = new ArrayList<String>();
        public List<String> libs = new ArrayList<String>();
        public List<String> archs = new ArrayList<String>();
        public List<String> classNames = new ArrayList<String>();
        public boolean hasFlutter = false;
        public boolean hasIl2Cpp = false;
        public boolean hasReactNative = false;
        public String error;
    }

    /**
     * 壳检测。
     *
     * 自动分析第一步必须做这个——加了壳的 APK，dex 与 so 都是密文，
     * 直接分析只会得到乱码。判定出来后走脱壳流程，而不是硬解析。
     */
    public enum Packer {
        NONE, QI_HOO, BANG_BANG, TENCENT, ALI, BAI_DU, AI_JIA_MI, TONG_DUN, UNKNOWN
    }

    public static class PackerInfo {
        public Packer packer = Packer.NONE;
        public String name = "无壳";
        public String evidence = "";
        public boolean packed = false;
        public String unpackHint = "";
    }

    /** 已知壳特征文件/库名 → 壳标识。 */
    private static final String[][] PACKER_FILES = {
        {"libx3g.so",          "QI_HOO"},
        {"libjiagu.so",        "QI_HOO"},
        {"libprotectClass.so", "QI_HOO"},
        {"libDexHelper.so",    "BANG_BANG"},
        {"libsecexe.so",       "BANG_BANG"},
        {"libsecmain.so",      "BANG_BANG"},
        {"libSecShell.so",     "BANG_BANG"},
        {"libshell.so",        "TENCENT"},
        {"libshella.so",       "TENCENT"},
        {"libshellx.so",       "TENCENT"},
        {"libmobisec.so",      "ALI"},
        {"libsgmain.so",       "ALI"},
        {"libbaiduprotect.so", "BAI_DU"},
        {"libddog.so",         "AI_JIA_MI"},
        {"libexec.so",         "AI_JIA_MI"},
        {"libexecmain.so",     "AI_JIA_MI"},
        {"libtongdun.so",      "TONG_DUN"},
    };

    public static PackerInfo detectPacker(ApkInfo info) {
        PackerInfo r = new PackerInfo();
        if (info == null) return r;

        // 1) 特征 so
        if (info.libs != null) {
            for (String l : info.libs) {
                String n = l.substring(l.lastIndexOf('/') + 1);
                for (String[] pf : PACKER_FILES) {
                    if (n.equals(pf[0])) {
                        r.packer = Packer.valueOf(pf[1]);
                        r.evidence = "特征库: " + l;
                        r.packed = true;
                        break;
                    }
                }
                if (r.packed) break;
            }
        }

        // 2) 特征条目（assets 下也放）
        if (!r.packed && info.entries != null) {
            for (String e : info.entries) {
                String n = e.substring(e.lastIndexOf('/') + 1);
                for (String[] pf : PACKER_FILES) {
                    if (n.equals(pf[0])) {
                        r.packer = Packer.valueOf(pf[1]);
                        r.evidence = "特征文件: " + e;
                        r.packed = true;
                        break;
                    }
                }
                if (r.packed) break;
            }
        }

        // 3) 壳 Application 包名
        if (!r.packed && info.classNames != null) {
            String[][] apps = {
                {"com.secneo.apkwrapper",  "BANG_BANG"},
                {"com.qihoo.util",         "QI_HOO"},
                {"com.stub.StubApp",       "QI_HOO"},
                {"com.tencent.StubShell",  "TENCENT"},
                {"com.ali.mobisecenhance", "ALI"},
                {"com.baidu.protect",      "BAI_DU"},
            };
            for (String cn : info.classNames) {
                for (String[] pa : apps) {
                    if (cn.startsWith(pa[0])) {
                        r.packer = Packer.valueOf(pa[1]);
                        r.evidence = "壳 Application: " + cn;
                        r.packed = true;
                        break;
                    }
                }
                if (r.packed) break;
            }
        }

        // 4) 兜底：只有 1 个 dex 却塞了很多 so —— 正常应用不会这样
        if (!r.packed && info.dexes != null && info.dexes.size() == 1
                && info.libs != null && info.libs.size() >= 3) {
            r.packer = Packer.UNKNOWN;
            r.evidence = "只有 1 个 DEX 却有 " + info.libs.size() + " 个 so，高度可疑";
            r.packed = true;
        }

        if (r.packed) r.name = packerName(r.packer);
        r.unpackHint = unpackHint(r.packer);
        return r;
    }

    private static String packerName(Packer p) {
        switch (p) {
            case QI_HOO:    return "360 加固";
            case BANG_BANG: return "梆梆加固";
            case TENCENT:   return "腾讯乐固";
            case ALI:       return "阿里聚安全";
            case BAI_DU:    return "百度加固";
            case AI_JIA_MI: return "爱加密";
            case TONG_DUN:  return "通付盾";
            default:        return "未知壳";
        }
    }

    private static String unpackHint(Packer p) {
        switch (p) {
            case QI_HOO:
                return "360 壳：dex 运行时解密到内存。用 frida hook libart 的 "
                        + "OpenMemory 把真实 dex dump 出来";
            case BANG_BANG:
                return "梆梆壳：hook memcpy / mmap 拦截解密后的 dex，或 "
                        + "hook DexClassLoader 加载点";
            case TENCENT:
                return "乐固壳：libshell 解密，hook dvmDexFileOpenPartial / "
                        + "OpenMemory 抓 dex";
            case ALI:
                return "阿里壳：libmobisec 解密，走内存 dump 路线";
            default:
                return "通用脱壳：frida hook libart OpenMemory / DexFile 构造，"
                        + "把解密后的 dex 从内存 dump 出来";
        }
    }

    /** 打开 APK：列条目、识别技术栈（Flutter / Unity / RN）。 */
    public static ApkInfo openApk(File f) {
        ApkInfo out = new ApkInfo();
        out.path = f.getAbsolutePath();
        out.size = f.length();
        ZipFile z = null;
        try {
            z = new ZipFile(f);
            java.util.Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String n = e.getName();
                out.entries.add(n);
                if (n.endsWith(".dex")) out.dexes.add(n);
                if (n.endsWith(".so")) {
                    out.libs.add(n);
                    String arch = archFromPath(n);
                    if (arch != null && !out.archs.contains(arch)) out.archs.add(arch);
                    if (n.endsWith("libflutter.so")) out.hasFlutter = true;
                    if (n.endsWith("libil2cpp.so")) out.hasIl2Cpp = true;
                    if (n.endsWith("libreactnativejni.so")) out.hasReactNative = true;
                }
                if (n.endsWith(".apk")) { /* 可能是 xapk 之类 */ }
            }
            // assets 里也可能藏着 Flutter / Unity 资源
            if (!out.hasFlutter) {
                for (String n : out.entries) {
                    if (n.contains("flutter_assets") || n.startsWith("assets/flutter")) {
                        out.hasFlutter = true; break;
                    }
                }
            }
            if (!out.hasIl2Cpp) {
                for (String n : out.entries) {
                    if (n.contains("il2cpp") || n.startsWith("assets/bin/Data")) {
                        out.hasIl2Cpp = true; break;
                    }
                }
            }
            if (!out.hasReactNative) {
                for (String n : out.entries) {
                    if (n.startsWith("assets/index.android.bundle")) {
                        out.hasReactNative = true; break;
                    }
                }
            }
            Collections.sort(out.entries);
        } catch (Exception e) {
            out.error = "打开失败: " + e.getMessage();
        } finally {
            if (z != null) try { z.close(); } catch (Exception ignored) {}
        }
        return out;
    }

    private static String archFromPath(String n) {
        if (n.contains("/arm64-v8a/") || n.contains("/arm64/")) return "arm64-v8a";
        if (n.contains("/armeabi-v7a/") || n.contains("/arm/")) return "armeabi-v7a";
        if (n.contains("/x86_64/")) return "x86_64";
        if (n.contains("/x86/")) return "x86";
        return null;
    }

    /** 从 APK 里解压出指定条目到缓存目录，返回本地文件。 */
    public static File extractEntry(File apk, String entryName, File outDir) {
        ZipFile z = null;
        InputStream is = null;
        try {
            z = new ZipFile(apk);
            ZipEntry e = z.getEntry(entryName);
            if (e == null) return null;
            if (!outDir.exists()) outDir.mkdirs();
            File out = new File(outDir, entryName.replace('/', '_'));
            is = z.getInputStream(e);
            java.io.FileOutputStream os = new java.io.FileOutputStream(out);
            byte[] buf = new byte[65536];
            int r;
            while ((r = is.read(buf)) > 0) os.write(buf, 0, r);
            os.close();
            return out;
        } catch (Exception ex) {
            return null;
        } finally {
            if (is != null) try { is.close(); } catch (Exception ignored) {}
            if (z != null) try { z.close(); } catch (Exception ignored) {}
        }
    }

    // ---------- 通用 ----------

    public static byte[] readAll(File f) throws Exception {
        long len = f.length();
        if (len > 512L * 1024 * 1024) throw new Exception("文件过大: " + len);
        byte[] out = new byte[(int) len];
        FileInputStream in = new FileInputStream(f);
        try {
            int off = 0;
            while (off < out.length) {
                int r = in.read(out, off, out.length - off);
                if (r <= 0) break;
                off += r;
            }
        } finally {
            in.close();
        }
        return out;
    }

    private static byte[] slice(byte[] d, long off, long size) {
        if (off < 0 || size < 0 || off + size > d.length) return null;
        byte[] r = new byte[(int) size];
        System.arraycopy(d, (int) off, r, 0, (int) size);
        return r;
    }

    private static String cstr(byte[] d, int off) {
        if (d == null || off < 0 || off >= d.length) return null;
        int e = off;
        while (e < d.length && d[e] != 0) e++;
        if (e == off) return "";
        try {
            return new String(d, off, e - off, "UTF-8");
        } catch (Exception ex) {
            return null;
        }
    }

    /** 按关键词过滤字符串（找 URL / 密钥 / 端点常用）。 */
    public static List<Str> filterStrings(List<Str> src, String kw, int limit) {
        List<Str> out = new ArrayList<Str>();
        String k = kw == null ? "" : kw.toLowerCase();
        for (Str s : src) {
            if (s.value.toLowerCase().contains(k)) {
                out.add(s);
                if (out.size() >= limit) break;
            }
        }
        return out;
    }

    /** 猜可能的敏感串：URL / http / key / token / secret。 */
    public static List<Str> interestingStrings(List<Str> src, int limit) {
        List<Str> out = new ArrayList<Str>();
        String[] pats = {"http://", "https://", "api", "token", "secret", "key",
                         "passw", "aes", "rsa", "md5", "sha", "sign", "salt"};
        for (Str s : src) {
            String v = s.value.toLowerCase();
            for (String p : pats) {
                if (v.contains(p)) { out.add(s); break; }
            }
            if (out.size() >= limit) break;
        }
        return out;
    }
}
