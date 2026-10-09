"""
engine/dex.py — DEX 逆向

真实解析 Android classes.dex：DEX header / string_ids / class_defs。
产出 dex 字符串表 + class 名清单 + 数量，供关键词定位/去授权点分析。
不依赖 apktool，纯二进制解析（MUTF-8 + uleb128）。
"""
import os, struct, glob
from typing import Dict, Any, List

DEX_MAGIC = b"dex\n"


def _uleb128(data: bytes, off: int):
    """读 uleb128，返回 (value, new_off)。"""
    result, shift, b = 0, 0, 0
    while True:
        b = data[off]; off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 35:
            break
    return result, off


def _mutf8(data: bytes, off: int, length: int) -> str:
    """DEX MUTF-8（近似 UTF-8，短类名基本等价）。"""
    out = []
    i = off
    while i < off + length:
        b = data[i]
        if b == 0:
            break
        if b < 0x80:
            out.append(chr(b)); i += 1
        elif b < 0xE0:
            out.append(chr(((b & 0x1F) << 6) | (data[i+1] & 0x3F))); i += 2
        else:
            out.append(chr(((b & 0x0F) << 12) | ((data[i+1] & 0x3F) << 6) | (data[i+2] & 0x3F)))
            i += 3
    return "".join(out)


def parse_dex(path: str, max_strings: int = 200000) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": path, "ok": False, "error": None}
    if not os.path.isfile(path):
        out["error"] = "not found"; return out
    data = open(path, "rb").read()
    if data[:4] != DEX_MAGIC:
        out["error"] = "not a dex (magic 不匹配)"; return out
    # header (offsets in DEX header)
    magic = data[:8]
    string_ids_size, = struct.unpack_from("<I", data, 0x38)
    string_ids_off, = struct.unpack_from("<I", data, 0x3C)
    class_defs_size, = struct.unpack_from("<I", data, 0x50)
    class_defs_off, = struct.unpack_from("<I", data, 0x54)
    type_ids_size, = struct.unpack_from("<I", data, 0x40)
    type_ids_off, = struct.unpack_from("<I", data, 0x44)
    out.update({
        "ok": True, "magic": magic.decode(errors="ignore").replace("\n", "\\n"),
        "size_bytes": len(data),
        "string_ids_size": string_ids_size,
        "class_defs_size": class_defs_size,
    })

    # 读 string_ids 表 → 每个 string offset
    str_offsets = struct.unpack_from("<%dI" % string_ids_size, data, string_ids_off) \
        if string_ids_size else []
    strings = []
    for so in str_offsets[:max_strings]:
        off = so
        if off >= len(data):
            continue
        length, off = _uleb128(data, off)
        strings.append(_mutf8(data, off, length))
    out["strings"] = strings[:max_strings]
    out["string_count"] = len(strings)

    # type_ids 表（class_idx → type_id → string_idx）
    type_ids = struct.unpack_from("<%dI" % type_ids_size, data, type_ids_off) \
        if type_ids_size else ()
    # class_defs → class 名（descriptor Lcom/xxx/Foo; → com.xxx.Foo）
    classes, _seen = [], set()
    for i in range(class_defs_size):
        base = class_defs_off + i * 32
        if base + 32 > len(data):
            break
        class_idx, = struct.unpack_from("<I", data, base)
        if class_idx < len(type_ids):
            str_idx = type_ids[class_idx]
            if str_idx < len(str_offsets):
                off = str_offsets[str_idx]
                if off < len(data):
                    L, o2 = _uleb128(data, off)
                    cn = _mutf8(data, o2, L)
                    if cn.startswith("L") and cn.endswith(";"):
                        cn = cn[1:-1]
                    cn = cn.replace("/", ".")
                    if cn and cn not in _seen:
                        _seen.add(cn)
                        classes.append(cn)
    out["classes"] = classes[:20000]
    out["class_count"] = len(classes)
    return out


def scan_apk_dex(apk_or_extract: str) -> Dict[str, Any]:
    """在 apk 解压目录找 classes*.dex，逐个解析。"""
    files = glob.glob(os.path.join(apk_or_extract, "**", "classes*.dex"), recursive=True)
    if not files:
        files = [f for f in glob.glob(os.path.join(apk_or_extract, "*.dex"))]
    report = {"found": len(files), "targets": []}
    for f in files:
        r = parse_dex(f)
        r["rel"] = os.path.relpath(f, apk_or_extract)
        # 关键词粗筛（去授权常用类名）
        r["interesting_classes"] = [c for c in r["classes"]
                                    if any(k in c for k in ("Vip", "Member", "Ad", "Auth",
                                                            "License", "Check", "Guard", "Security"))][:500]
        report["targets"].append({k: v for k, v in r.items()
                                  if k in ("rel", "ok", "error", "size_bytes",
                                            "string_count", "class_count", "interesting_classes")})
    return report
