"""
engine/blutter_output.py — 解析 Blutter 官方产物

开源项目 github.com/worawit/blutter 的产物结构：

    outdir/
    ├── asm/                带符号的 ARM64 汇编，按库/包分文件
    │   ├── dart:core/
    │   ├── package:flutter/
    │   └── package:app_name/
    ├── pp.txt              对象池（所有字符串/常量，找 URL、密钥、API 就看它）
    ├── objs.txt            对象池的嵌套 dump
    ├── blutter_frida.js    预生成的 Frida hook 模板
    └── ida_script/
        ├── addNames.py     IDA 导入符号脚本
        └── ida_dart_struct.h

asm/ 里的关键行：
    // ** addr: 0x8fcc2c, size: 0x38
    static Uri termsLink(){
    // 0x8fcc40: r1 = "https://app.com/terms"
    // 0x8fcc4c: bl #0x4cb1c4 ; [package:flutter/...] WidgetsFlutterBinding::ensureInitialized

pp.txt 里的关键行（对象池条目，含偏移与内容）：
    [pp+0x25980] "https://app.com/terms"
    [pp+0x358] List(5) [0, 0x1, 0, 0x1, Null]

本模块把这些解析成 R2B 内部统一的 classes / funcs / strings / pp_table 结构，
让 Blutter_* 工具直接消费真实数据（不再靠启发式）。
"""
import os
import re
import glob
from typing import Dict, Any, List

# asm/ 中函数头： "// ** addr: 0x8fcc2c, size: 0x38" 后面紧跟函数签名
RE_FUNC_HEAD = re.compile(r"//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+),\s*size:\s*(0x[0-9a-fA-F]+)")
# 调用目标： "bl #0x4cb1c4 ; [package:flutter/src/.../binding.dart] WidgetsFlutterBinding::ensureInitialized"
RE_CALL = re.compile(r"bl\s+#(0x[0-9a-fA-F]+)\s*;\s*(?:\[([^\]]*)\]\s*)?([A-Za-z_][\w$<>.:]*)\s*(?:::|\.)?\s*([\w$<>]*)\s*(?:\(\))?")
# pp.txt 条目： "[pp+0x25980] \"https://...\"" 或 "0x1234: [pp+0x100] Something"
RE_PP = re.compile(r"\[pp\+(0x[0-9a-fA-F]+)\]\s*(.+)")
RE_PP_ALT = re.compile(r"^(0x[0-9a-fA-F]+)\s*[:=]\s*(?:\[pp\+[^\]]*\]\s*)?(.+)")


def _walk_asm(outdir: str):
    for p in sorted(glob.glob(os.path.join(outdir, "asm", "**", "*"), recursive=True)):
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            yield p


def parse_asm(outdir: str, max_funcs: int = 200000) -> List[Dict]:
    """扫 asm/ 抽函数：地址、大小、所属包、类名、方法名、调用目标。"""
    out: List[Dict] = []
    for fp in _walk_asm(outdir):
        lib = os.path.relpath(fp, os.path.join(outdir, "asm"))
        try:
            lines = open(fp, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        prev = ""
        for line in lines:
            raw = line.rstrip()
            m = RE_FUNC_HEAD.search(raw)
            if m:
                # 真实格式：签名在前一行，"// ** addr:" 在后
                #   static Uri termsLink(){
                #   // ** addr: 0x8fcc2c, size: 0x38
                cls, meth, full = _split_sig(prev)
                if full:
                    out.append({"addr": m.group(1), "size": m.group(2),
                                "lib": lib, "class": cls, "method": meth,
                                "name": full, "signature": prev})
                    if len(out) >= max_funcs:
                        return out
                prev = ""
                continue
            if raw.strip():
                prev = raw.strip()
        if len(out) >= max_funcs:
            break
    return out


def _split_sig(sig: str):
    """'static Uri ClassName.methodName(){' -> (Class, method, Class.method)。"""
    s = sig.split("(")[0].strip()
    s = re.sub(r"^(static|final|const|abstract|external)\s+", "", s)
    s = re.sub(r"^[\w<>?,\s\[\]]+?\s(?=[A-Za-z_])", "", s)  # 去掉返回类型
    s = s.strip().rstrip("{").strip()
    if not s:
        return None, None, None
    if "::" in s:            # Dart VM 风格 Class::method
        cls, meth = s.split("::", 1)
    elif "." in s:           # 常见 Class.method
        cls, meth = s.rsplit(".", 1)
    else:
        cls, meth = None, s
    full = f"{cls}.{meth}" if cls else meth
    return cls, meth, full


def parse_pp(outdir: str, max_items: int = 200000) -> List[Dict]:
    """解析 pp.txt：对象池条目。找 URL / 密钥 / 端点主要靠它。"""
    fp = os.path.join(outdir, "pp.txt")
    if not os.path.isfile(fp):
        return []
    out = []
    try:
        lines = open(fp, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = RE_PP.search(line) or RE_PP_ALT.match(line)
        if not m:
            continue
        off, val = m.group(1), m.group(2).strip()
        # 只保留可读内容（字符串常量最有用）
        s = _extract_string(val)
        out.append({"offset": off, "raw": val[:300], "value": s})
        if len(out) >= max_items:
            break
    return out


def _extract_string(raw: str):
    """从 pp 条目里抽可读字符串；不是字符串则返回 None。"""
    m = re.search(r'"((?:[^"\\]|\\.)*)"', raw)
    if m:
        return m.group(1)
    return None


def parse_objs(outdir: str, max_lines: int = 100000) -> List[str]:
    """objs.txt：对象嵌套 dump，只做行级保留，供关键词搜索。"""
    fp = os.path.join(outdir, "objs.txt")
    if not os.path.isfile(fp):
        return []
    try:
        return [l.strip() for l in open(fp, encoding="utf-8", errors="ignore")
                if l.strip()][:max_lines]
    except OSError:
        return []


def frida_script(outdir: str):
    """取官方生成的 blutter_frida.js 路径。"""
    p = os.path.join(outdir, "blutter_frida.js")
    return p if os.path.isfile(p) else None


def ida_script(outdir: str):
    """取官方生成的 ida_script/addNames.py 路径。"""
    p = os.path.join(outdir, "ida_script", "addNames.py")
    return p if os.path.isfile(p) else None


def to_registry(reg: Dict, outdir: str) -> int:
    """把 Blutter 产物灌进 blutter 会话 registry，返回灌入的函数数。

    reg 结构与 engine/blutter_engine.py 的 _reg() 一致：
      classes / funcs / strings / pp_table
    """
    funcs = parse_asm(outdir)
    pps = parse_pp(outdir)
    n = 0

    reg.setdefault("classes", {})
    reg.setdefault("funcs", {})
    reg.setdefault("strings", {})
    reg.setdefault("pp_table", [])

    for f in funcs:
        name = f["name"]
        reg["funcs"][name] = {"name": name, "class": f["class"],
                              "offset": f["addr"], "size": _hx(f["size"]),
                              "lib": f["lib"]}
        if f["class"] and f["class"] not in reg["classes"]:
            reg["classes"][f["class"]] = {"name": f["class"], "parents": [],
                                          "methods": [], "fields": []}
        n += 1

    # 字符串：pp 里的可读常量（真实、精确，比启发式强得多）
    for e in pps:
        if e["value"]:
            reg["strings"][e["value"]] = e["offset"]
    reg["pp_table"] = [{"type": "string", "name": e["value"], "offset": e["offset"]}
                       for e in pps if e["value"]][:20000]
    reg["pp_table"] += [{"type": "func", "name": f["name"], "offset": f["addr"]}
                        for f in funcs][:20000]

    reg["blutter_outdir"] = outdir
    reg["blutter_frida_js"] = frida_script(outdir)
    reg["blutter_ida_script"] = ida_script(outdir)
    reg["real_engine"] = True
    return n


def _hx(v):
    try:
        return int(v, 16)
    except (TypeError, ValueError):
        return 0


def summary(outdir: str) -> Dict[str, Any]:
    """产物概览，用于确认解析是否成功。"""
    f = parse_asm(outdir)
    p = parse_pp(outdir)
    o = parse_objs(outdir)
    return {"outdir": outdir,
            "funcs": len(f),
            "pp_entries": len(p),
            "pp_strings": sum(1 for x in p if x["value"]),
            "obj_lines": len(o),
            "asm_files": sum(1 for _ in _walk_asm(outdir)),
            "frida_js": frida_script(outdir),
            "ida_script": ida_script(outdir),
            "sample_funcs": [x["name"] for x in f[:5]],
            "sample_strings": [x["value"] for x in p[:5] if x["value"]]}
