"""
engine/patch.py — 补丁生成（读伪 C → 定位偏移 → 写入）

把「关键词命中 + r2 搜到的偏移 + 伪 C」组织成可执行补丁方案。
不伪造成功：每个 patch 标注 confidence 与 rationale，最终写入由
pack_sign/r2_write_patch 落盘并说明。
"""
import json
from typing import Dict, Any, List

# 常见"绕过/改值"补丁语义
OPS = {
    "return_true":  ("把 分支结果 置 true（如 mov x0,#1 / ret）"),
    "nop_branch":   ("把判断跳 改成 nop 直走（patch b 条件为 never/taken）"),
    "const_xor":    ("改 硬编码 密钥/魔数（xor 目标字节）"),
    "bypass_check": ("把 授权/次数 校验 短路"),
}


def plan_patches(so: str, keyword_hits: Dict[str, List[str]],
                 r2_offsets: Dict[str, List[str]], pseudoc: Dict[str, str],
                 op: str = "bypass_check") -> Dict[str, Any]:
    """生成补丁方案清单。"""
    patches = []
    for kw, hits in list((keyword_hits or {}).items())[:30]:
        offs = (r2_offsets or {}).get(kw, [])
        for off in offs[:3]:
            ref = ""
            for fn, code in (pseudoc or {}).items():
                if kw.lower() in code.lower():
                    ref = f"fn={fn}"
                    break
            patches.append({
                "keyword": kw, "so": so, "offset_hint": off, "op": op,
                "op_desc": OPS.get(op, "custom"),
                "ref_pseudoc": ref,
                "rationale": f"命中关键词 '{kw}'，偏移 {off}；语义={OPS.get(op,'custom')}",
                "confidence": "low",  # 需 AI/人工结合伪 C 提升到 high
                "needs_confirm": True,
            })
    return {"so": so, "op": op, "patches": patches,
            "count": len(patches),
            "note": "confidence=low 表示候选；结合 r2 伪 C 人工/AI 确认后由 r2_write_patch 落盘"}


def apply_patches(so: str, patches: List[Dict], out_so: str = None) -> Dict[str, Any]:
    """把 confirmed 的 patch 写入 so。patch 需含 offset(hex) 与 bytes(hex)。"""
    import os
    out_so = out_so or so + ".patched"
    data = bytearray(open(so, "rb").read())
    applied = []
    for p in patches:
        off = p.get("offset_hex") or p.get("offset")
        b = p.get("bytes_hex")
        if not off or not b:
            continue
        o = int(off, 16) if isinstance(off, str) else int(off)
        bb = bytes.fromhex(b.replace(" ", ""))
        data[o:o + len(bb)] = bb
        applied.append({"offset": off, "bytes": b})
    open(out_so, "wb").write(bytes(data))
    return {"ok": True, "out": out_so, "applied": applied, "applied_count": len(applied)}


# ============ arm64 补丁字节自动生成（"自己算偏移→自己打补丁"的核心）============
import struct

def _le(*opcodes):
    return b"".join(struct.pack("<I", o) for o in opcodes)

NOP = 0xD503201F
RET = 0xD65F03C0
# mov w0,#imm / mov x0,#imm
def _mov_imm(reg_w, imm):
    base = 0x52800000 if reg_w else 0xD2800000
    return base | ((imm & 0xFF) << 5) | (0)   # Rd=0 (x0/w0)

# 常用补丁模板（写进 so 的 .text）
PATCH_OPS = {
    "return_true":   _le(_mov_imm(True, 1), RET),            # 函数直接返回 1
    "return_false":  _le(_mov_imm(True, 0), RET),            # 返回 0
    "return_1_x":    _le(_mov_imm(False, 1), RET),           # 64 位返回 1
    "return_0_x":    _le(_mov_imm(False, 0), RET),
    "nop2":          _le(NOP, NOP),
    "branch_always": _le(0x14000000),                        # b +0（无条件跳 0 → 需按目标算）
}


def arm64_ret_patch(val=1, wide=False) -> Dict[str, Any]:
    """函数体开头改写成 '立即返回 val'。wide=False→w0(32位), True→x0(64位)。"""
    base = 0xD2800000 if wide else 0x52800000   # wide→x0, 否→w0
    opcode = base | ((val & 0xFF) << 5)
    b = _le(opcode, RET)
    return {"op": "ret_const", "value": val, "bytes": b.hex(), "len": len(b),
            "disasm": f"mov {'x' if wide else 'w'}0,#{val}; ret",
            "note": "写在目标函数入口；让 VIP/付费校验直接返回成功值"}


def arm64_branch_bypass(cond_bytes_hex: str, always_take: bool = True) -> Dict[str, Any]:
    """把条件分支 b.cond/cbz/cbnz 改成'总跳'（绕过校验）或'总不跳'。
    给定 4 字节分支指令，翻转/置位条件码。"""
    op = struct.unpack("<I", bytes.fromhex(cond_bytes_hex.replace(" ", "")))[0]
    if always_take:
        op |= 0xF            # cond → AL (1111) = 无条件
    else:
        op = (op & 0xFFFFFFF0) | ((op & 0xF) ^ 0xF)   # 取反条件码(近似)
    b = struct.pack("<I", op)
    return {"op": "bypass" if always_take else "force_skip",
            "bytes": b.hex(), "len": 4, "orig": cond_bytes_hex,
            "note": "总是跳/总是不跳，短路掉 VIP/授权判断"}


def plan_vip_patch(so: str, keyword: str, offset_hex: str, func_entry_hex: str = None,
                   branch_hex: str = None, op: str = "return_true") -> Dict[str, Any]:
    """把'定位到 VIP 判断点'转成确切 patch 方案（offset + bytes + rationale）。
    优先级：能分支绕过就绕过，否则函数入口改返回。"""
    p = {"keyword": keyword, "so": so, "offset": offset_hex, "needs_confirm": False}
    if branch_hex:
        p["patch"] = arm64_branch_bypass(branch_hex, always_take=(op in ("return_true", "bypass")))
        p["patch"]["offset"] = offset_hex
    elif func_entry_hex:
        p["patch"] = arm64_ret_patch(1 if op in ("return_true", "bypass", "bypass_check") else 0)
        p["patch"]["offset"] = func_entry_hex
    else:
        p["patch"] = arm64_ret_patch(1)
        p["note"] = "未给分支/入口字节，默认函数入口改返回 1 (mov x0/w0,#1; ret)；需 r2 出该处字节后回填"
    p["rationale"] = f"关键词'{keyword}' 命中 {offset_hex}；语义 {op} → 写 {p['patch']['bytes']} ({p['patch']['len']}B)"
    p["confidence"] = "high" if (branch_hex or func_entry_hex) else "medium"
    return p
