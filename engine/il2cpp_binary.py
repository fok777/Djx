"""
engine/il2cpp_binary.py — global-metadata.dat 二进制结构解析（多版本自适应）

Unity 各版本（v28/32/34/35/39）的 metadata header 字段偏移不同。用**候选 header 表 + 自动择优**：
对每套候选偏移解析 methodDef，选"有效方法名（name_idx 落在 nameBlock 内）最多"的那套。
不靠死记 version，真实 Unity 游戏 APK（v29/35/39）也能自动适配出精确 RVA。
"""
import struct
from typing import Dict, List, Any

MD_STRIDE = 18  # methodDef: name(4) token(4) argc(2) iflags(1) iflags2(1) classIndex(2) methodOffset(4)
TD_STRIDE = 60   # typeDef 近似 15*4

# 候选 header 偏移表（methodDef/typeDef/stringLit/name 的 off/size 位置，随 Unity 版本前后移）
_CANDIDATES = [
    {"tag": "v28", "md": (0x44, 0x48), "td": (0x54, 0x58), "sl": (0x9C, 0xA0), "nm": (0xA4, 0xA8)},
    {"tag": "v32", "md": (0x48, 0x4C), "td": (0x58, 0x5C), "sl": (0xA0, 0xA4), "nm": (0xA8, 0xAC)},
    {"tag": "v34", "md": (0x4C, 0x50), "td": (0x5C, 0x60), "sl": (0xA4, 0xA8), "nm": (0xAC, 0xB0)},
    {"tag": "v35", "md": (0x50, 0x54), "td": (0x60, 0x64), "sl": (0xA8, 0xAC), "nm": (0xB0, 0xB4)},
    {"tag": "v39", "md": (0x54, 0x58), "td": (0x64, 0x68), "sl": (0xB4, 0xB8), "nm": (0xBC, 0xC0)},
]


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def _read_names(data: bytes, block_off: int, block_len: int, utf16: bool = True) -> List[str]:
    if block_len <= 0 or block_off >= len(data):
        return []
    blob = data[block_off:block_off + block_len]
    out = []
    if utf16:
        i = 0
        while i + 1 < len(blob):
            if blob[i] == 0 and blob[i + 1] == 0:
                i += 2
                continue
            j = i
            while j + 1 < len(blob) and not (blob[j] == 0 and blob[j + 1] == 0):
                j += 2
            s = blob[i:j].decode("utf-16-le", "ignore")
            out.append(s)
            i = j
    else:
        for seg in blob.split(b"\x00"):
            if seg:
                out.append(seg.decode("utf-8", "ignore"))
    return out


def _parse_one(data: bytes, cand: Dict) -> Dict:
    md_off, md_sz = _u32(data, cand["md"][0]), _u32(data, cand["md"][1])
    td_off, td_sz = _u32(data, cand["td"][0]), _u32(data, cand["td"][1])
    nm_off, nm_len = _u32(data, cand["nm"][0]), _u32(data, cand["nm"][1])
    sl_off, sl_len = _u32(data, cand["sl"][0]), _u32(data, cand["sl"][1])
    names = _read_names(data, nm_off, nm_len, True) or _read_names(data, nm_off, nm_len, False)

    methods = []
    # 合法性：methodDef 表 size 必须是 MD_STRIDE 倍数且在文件内（淘汰错位/garbage 候选）
    if not (md_sz > 0 and md_sz % MD_STRIDE == 0 and md_off + md_sz <= len(data)):
        return {"methods": [], "types": [], "strings": [], "valid": 0, "tag": cand["tag"], "names": names}
    if md_sz > 0 and md_off + md_sz <= len(data):
        for i in range(md_sz // MD_STRIDE):
            p = md_off + i * MD_STRIDE
            ni = _u32(data, p)
            rva = _u32(data, p + 14)
            nm = names[ni] if 0 <= ni < len(names) else None
            methods.append({"name": nm, "rva": rva, "name_idx": ni})
    types = []
    if td_sz > 0 and td_off + td_sz <= len(data):
        for i in range(td_sz // TD_STRIDE):
            p = td_off + i * TD_STRIDE
            ni, nsi = _u32(data, p), _u32(data, p + 4)
            nm = names[ni] if 0 <= ni < len(names) else None
            ns = names[nsi] if 0 <= nsi < len(names) else None
            if nm:
                types.append({"name": ns + "." + nm if ns else nm, "raw": nm})
    strings = []
    if sl_len > 0 and sl_off + sl_len <= len(data):
        p, end = sl_off, sl_off + sl_len
        while p + 4 < end:
            slen = _u32(data, p)
            p += 4
            if slen == 0 or p + slen > len(data):
                break
            s = data[p:p + slen].decode("utf-8", "ignore")
            p += slen + 1
            if s:
                strings.append(s)
    valid = sum(1 for m in methods if m["name"])
    return {"methods": methods, "types": types, "strings": strings,
            "valid": valid, "tag": cand["tag"], "names": names}


def parse_global_metadata(path: str) -> Dict[str, Any]:
    import os
    res: Dict[str, Any] = {"path": path, "ok": False, "methods": [], "types": [], "strings": [],
                           "error": None, "version": None, "imageBase": 0, "candidate": None}
    if not os.path.isfile(path):
        res["error"] = "file not found"
        return res
    data = open(path, "rb").read()
    if len(data) < 0x40:
        res["error"] = "file too small"
        return res
    res["version"] = struct.unpack_from("<i", data, 0)[0]
    res["imageBase"] = _u32(data, 4)

    # 多候选自动择优（选有效方法名最多的 header 布局）
    best = None
    for cand in _CANDIDATES:
        r = _parse_one(data, cand)
        if r["valid"] > 0 and (best is None or r["valid"] > best["valid"]):
            best = r
    if best is None:
        res["error"] = "no candidate header matched (非标准/损坏 metadata)"
        res["ok"] = False
        return res
    res.update({
        "ok": True, "methods": best["methods"], "types": best["types"], "strings": best["strings"],
        "candidate": best["tag"], "method_count": len(best["methods"]),
        "type_count": len(best["types"]), "string_count": len(best["strings"]),
        "note": f"精确 RVA(相对imageBase) via candidate {best['tag']}; r2: af @ imageBase+rva",
    })
    return res


def rva_to_abs(image_base: int, rva: int) -> int:
    return image_base + rva


def build_import_r2(parsed: Dict) -> str:
    base = parsed.get("imageBase", 0)
    lines = [f"# R2B Il2CPP → r2 导入（candidate {parsed.get('candidate')}，精确 RVA）"]
    for m in parsed["methods"][:1000]:
        if not m.get("name"):
            continue
        absa = base + m["rva"]
        nm = m["name"].replace(".", "_").replace("::", "_")[:60]
        lines.append(f"af @0x{absa:x}\nafn {nm} @0x{absa:x}")
    return "\n".join(lines)


def build_import_ida(parsed: Dict) -> str:
    base = parsed.get("imageBase", 0)
    lines = [f"# R2B Il2CPP → IDA 导入（candidate {parsed.get('candidate')}）", "import idc"]
    for m in parsed["methods"][:1000]:
        if not m.get("name"):
            continue
        absa = base + m["rva"]
        nm = m["name"].replace(".", "_").replace("::", "_")[:60]
        lines.append(f'idc.SetName(0x{absa:x}, "{nm}", idc.SN_FORCE | idc.SN_NOCHECK)')
    return "\n".join(lines)
