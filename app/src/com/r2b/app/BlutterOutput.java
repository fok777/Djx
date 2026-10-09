package com.r2b.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 解析真实 blutter 的输出目录。
 *
 * 官方 blutter 跑完会产生：
 *   outdir/
 *   ├── asm/              带符号的汇编（函数名、地址、大小）
 *   ├── pp.txt            对象池 ← 找 URL / 密钥 / 端点最有用的一个
 *   ├── objs.txt          对象表
 *   └── blutter_frida.js  现成的 Frida 脚本
 *
 * 关键格式坑：asm 里是「函数名在前，// ** addr: 在后」，
 * 早期版本我把顺序写反了，抽出来全是汇编注释。这里按真实格式解析。
 */
public final class BlutterOutput {

    private BlutterOutput() {}

    /** 解析输出目录，返回结构化结果。目录不存在或为空则返回 null。 */
    public static JSONObject parse(File dir) {
        if (dir == null || !dir.isDirectory()) return null;
        JSONObject out = new JSONObject();
        try {
            // ---- asm/ ----
            File asmDir = new File(dir, "asm");
            List<Func> funcs = new ArrayList<Func>();
            if (asmDir.isDirectory()) {
                File[] fs = asmDir.listFiles();
                if (fs != null) {
                    for (File f : fs) {
                        if (!f.isFile()) continue;
                        funcs.addAll(parseAsm(f));
                    }
                }
            }
            Collections.sort(funcs, new Comparator<Func>() {
                public int compare(Func a, Func b) { return Long.compare(a.addr, b.addr); }
            });
            out.put("function_count", funcs.size());
            JSONArray fa = new JSONArray();
            int lim = Math.min(funcs.size(), 500);
            for (int i = 0; i < lim; i++) {
                Func f = funcs.get(i);
                JSONObject o = new JSONObject();
                o.put("name", f.name);
                o.put("addr", f.addr);
                o.put("size", f.size);
                fa.put(o);
            }
            out.put("functions", fa);

            // 类名：Dart AOT 的函数名通常带 Class.method 形态
            Map<String, Integer> classes = new LinkedHashMap<String, Integer>();
            for (Func f : funcs) {
                String c = guessClass(f.name);
                if (c == null) continue;
                Integer v = classes.get(c);
                classes.put(c, v == null ? 1 : v + 1);
            }
            JSONArray ca = new JSONArray();
            int cl = 0;
            for (Map.Entry<String, Integer> e : classes.entrySet()) {
                JSONObject o = new JSONObject();
                o.put("class", e.getKey());
                o.put("method_count", e.getValue());
                ca.put(o);
                if (++cl >= 300) break;
            }
            out.put("class_count", classes.size());
            out.put("classes", ca);

            // ---- pp.txt ----
            File pp = new File(dir, "pp.txt");
            if (pp.isFile()) {
                String txt = readText(pp, 8 * 1024 * 1024);
                List<String> lines = splitLines(txt);
                out.put("pool_object_count", lines.size());
                JSONArray interesting = new JSONArray();
                int n = 0;
                for (String ln : lines) {
                    if (looksInteresting(ln)) {
                        interesting.put(ln.trim());
                        if (++n >= 200) break;
                    }
                }
                out.put("interesting_strings", interesting);
                JSONArray sample = new JSONArray();
                for (int i = 0; i < Math.min(lines.size(), 200); i++) {
                    sample.put(lines.get(i));
                }
                out.put("pool_sample", sample);
            }

            // ---- blutter_frida.js ----
            File js = new File(dir, "blutter_frida.js");
            if (js.isFile()) {
                out.put("frida_script", js.getAbsolutePath());
                out.put("frida_script_size", js.length());
            }

            out.put("parsed", true);
            return out;
        } catch (Exception e) {
            JSONObject err = new JSONObject();
            try {
                err.put("parse_error", e.getClass().getSimpleName() + ": " + e.getMessage());
            } catch (Exception ignored) {}
            return err;
        }
    }

    static class Func {
        String name;
        long addr;
        long size;
        Func(String n, long a, long s) { name = n; addr = a; size = s; }
    }

    /**
     * 解析单个 asm 文件。
     * 真实格式示例：
     *   flutter::Foo.bar_ // ** addr: 0x1a2b3c ** size: 48 ** cid: 12
     */
    static List<Func> parseAsm(File f) {
        List<Func> out = new ArrayList<Func>();
        String txt = readText(f, 16 * 1024 * 1024);
        if (txt == null) return out;
        for (String line : splitLines(txt)) {
            String t = line.trim();
            int p = t.indexOf("// ** addr:");
            if (p <= 0) continue;
            String name = t.substring(0, p).trim();
            if (name.length() == 0) continue;
            // 去掉尾部可能的 : 或 @
            if (name.endsWith(":")) name = name.substring(0, name.length() - 1);
            long addr = parseAfter(t, "addr:");
            long size = parseAfter(t, "size:");
            if (addr >= 0) out.add(new Func(name, addr, size < 0 ? 0 : size));
        }
        return out;
    }

    private static long parseAfter(String s, String key) {
        int i = s.indexOf(key);
        if (i < 0) return -1;
        int j = i + key.length();
        // 跳空格 + 可选 0x
        while (j < s.length() && (s.charAt(j) == ' ' || s.charAt(j) == '\t')) j++;
        boolean hex = false;
        if (j + 1 < s.length() && s.charAt(j) == '0'
                && (s.charAt(j + 1) == 'x' || s.charAt(j + 1) == 'X')) {
            hex = true;
            j += 2;
        }
        int k = j;
        while (k < s.length() && (Character.isDigit(s.charAt(k))
                || (hex && "abcdefABCDEF".indexOf(s.charAt(k)) >= 0))) k++;
        if (k == j) return -1;
        String num = s.substring(j, k);
        try {
            return hex ? Long.parseLong(num, 16) : Long.parseLong(num);
        } catch (Exception e) {
            return -1;
        }
    }

    private static String guessClass(String sym) {
        if (sym == null) return null;
        int dot = sym.indexOf('.');
        if (dot > 0) {
            String c = sym.substring(0, dot);
            if (c.matches("[A-Za-z_$][A-Za-z0-9_$]*")) return c;
        }
        if (sym.startsWith("_")) {
            int at = sym.indexOf('@');
            String c = at > 0 ? sym.substring(1, at) : sym.substring(1);
            if (c.matches("[A-Za-z_$][A-Za-z0-9_$]*")) return c;
        }
        return null;
    }

    private static boolean looksInteresting(String ln) {
        String v = ln.toLowerCase();
        return v.contains("http://") || v.contains("https://")
                || v.contains("api") || v.contains("token")
                || v.contains("secret") || v.contains("key")
                || v.contains("passw") || v.contains("aes")
                || v.contains("rsa") || v.contains("sign");
    }

    private static List<String> splitLines(String s) {
        List<String> out = new ArrayList<String>();
        if (s == null) return out;
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                out.add(s.substring(start, i));
                start = i + 1;
            }
        }
        if (start < s.length()) out.add(s.substring(start));
        return out;
    }

    private static String readText(File f, long max) {
        try {
            long len = f.length();
            if (len > max) len = max;
            byte[] d = new byte[(int) len];
            FileInputStream in = new FileInputStream(f);
            int off = 0;
            while (off < d.length) {
                int r = in.read(d, off, d.length - off);
                if (r <= 0) break;
                off += r;
            }
            in.close();
            return new String(d, 0, off, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }
}
