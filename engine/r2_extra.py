"""
engine/r2_extra.py — R2_* 补齐的 7 个元信息工具

现行 r2_engine 有 33 个工具，缺架构/内存映射/块/全局变量/类型/
符号总表/补丁这几种元信息查询。全部走真实 radare2 命令。
"""
import json
import re
from typing import Dict, Any, List

from . import r2_engine
from .r2_engine import _r2, _so, _require


def _cmd_json(sid: str, cmd: str, timeout: int = 90):
    """执行 r2 命令并解析 JSON，失败返回原始输出。"""
    r = _r2(_so(sid), cmd, timeout=timeout)
    out = r.get("out", "")
    if not r.get("ok"):
        return {"error": r.get("err") or "r2 command failed", "raw": out[:500]}
    i = min([x for x in (out.find("["), out.find("{")) if x >= 0], default=-1)
    if i >= 0:
        try:
            return json.loads(out[i:])
        except json.JSONDecodeError:
            pass
    return {"raw": out[:4000]}


# ---------- 元信息 ----------

def r2_arch(sid: str) -> Dict:
    """架构信息：arch/bits/endian/cpu/canary/nx 等。"""
    r = _r2(_so(sid), "iIj", timeout=60)
    out = r.get("out", "")
    i = out.find("{")
    if i >= 0:
        try:
            d = json.loads(out[i:])
            return {"session_id": sid,
                    "arch": d.get("arch"), "bits": d.get("bits"),
                    "endian": d.get("endian"), "cpu": d.get("cpu"),
                    "machine": d.get("machine"), "os": d.get("os"),
                    "class": d.get("class"), "compiler": d.get("compiler"),
                    "canary": d.get("canary"), "nx": d.get("nx"),
                    "pic": d.get("pic"), "relocs": d.get("relocs"),
                    "stripped": d.get("stripped"),
                    "static": d.get("static")}
        except json.JSONDecodeError:
            pass
    # 降级：文本解析
    txt = out or r.get("err", "")
    def g(k):
        m = re.search(k + r"\s*(\S+)", txt)
        return m.group(1) if m else None
    return {"session_id": sid, "arch": g("arch"), "bits": g("bits"),
            "endian": g("endian"), "raw": txt[:500]}


def r2_map(sid: str) -> Dict:
    """内存映射（om/段布局）。"""
    d = _cmd_json(sid, "omj")
    if isinstance(d, list):
        return {"session_id": sid, "count": len(d),
                "maps": [{"addr": hex(m.get("from", 0)), "to": hex(m.get("to", 0)),
                          "size": m.get("size", 0), "perm": m.get("perm"),
                          "name": m.get("name")} for m in d]}
    return {"session_id": sid, **d}


def r2_globals(sid: str, filter: str = None, max_results: int = 200) -> Dict:
    """全局变量（isj 数据符号）。"""
    d = _cmd_json(sid, "isj")
    items = d if isinstance(d, list) else []
    out = []
    for s in items:
        if s.get("type") not in ("OBJ", "OBJECT", "NOTYPE") and s.get("is_global"):
            pass
        if s.get("type") != "FUNC":
            nm = s.get("name") or s.get("realname") or ""
            if filter and filter.lower() not in nm.lower():
                continue
            out.append({"name": nm, "addr": hex(s.get("vaddr", 0)),
                        "size": s.get("size", 0), "type": s.get("type")})
    return {"session_id": sid, "total": len(out), "globals": out[:max_results]}


def r2_types(sid: str, filter: str = None) -> Dict:
    """类型与结构体定义（tj / tsj）。"""
    d = _cmd_json(sid, "tsj")
    if isinstance(d, list):
        items = [{"struct": s.get("name"), "size": s.get("size")} for s in d]
    else:
        txt = _r2(_so(sid), "t", timeout=60).get("out", "")
        items = [{"struct": x} for x in re.findall(r"^(struct\.\S+|enum\.\S+)",
                                                   txt, re.M)]
    if filter:
        items = [i for i in items if filter.lower() in str(i).lower()]
    return {"session_id": sid, "total": len(items), "types": items[:300]}


def r2_blocks(sid: str, func: str = None) -> Dict:
    """基本块（afbj），用于看控制流。"""
    cmd = "afbj" + (f" @ {func}" if func else "")
    d = _cmd_json(sid, cmd)
    if isinstance(d, list):
        return {"session_id": sid, "func": func, "count": len(d),
                "blocks": [{"addr": hex(b.get("addr", 0)), "size": b.get("size"),
                            "jump": hex(b.get("jump", 0)) if b.get("jump") else None,
                            "fail": hex(b.get("fail", 0)) if b.get("fail") else None,
                            "ninstr": b.get("ninstr")} for b in d]}
    return {"session_id": sid, **d}


def r2_symbols(sid: str, filter: str = None, kind: str = None,
               max_results: int = 300) -> Dict:
    """符号总表（isj），可按类型过滤。"""
    d = _cmd_json(sid, "isj")
    items = d if isinstance(d, list) else []
    out = []
    for s in items:
        t = s.get("type")
        if kind and kind.upper() != str(t).upper():
            continue
        nm = s.get("name") or s.get("realname") or ""
        if filter and filter.lower() not in nm.lower():
            continue
        out.append({"name": nm, "addr": hex(s.get("vaddr", 0)),
                    "size": s.get("size", 0), "type": t,
                    "bind": s.get("bind"), "global": s.get("is_global")})
    return {"session_id": sid, "total": len(out), "symbols": out[:max_results]}


def r2_patch(sid: str, address: str, hex_bytes: str = None,
             asm: str = None, nop: int = None) -> Dict:
    """打补丁：写 hex / 写汇编 / 填 NOP。三者选一。"""
    if not any([hex_bytes, asm, nop]):
        return {"error": "hex_bytes / asm / nop 三选一", "session_id": sid}
    if nop:
        cmds = f"wao nop {int(nop)} @ {address}"
    elif hex_bytes:
        cmds = f"wx {hex_bytes.replace(' ', '')} @ {address}"
    else:
        cmds = f"wa {asm} @ {address}"
    r = _r2(_so(sid), cmds, timeout=60)
    if not r.get("ok"):
        return {"error": r.get("err") or "patch failed",
                "session_id": sid, "cmd": cmds}
    # 校验
    v = _r2(_so(sid), f"px 16 @ {address}", timeout=30)
    return {"session_id": sid, "address": address, "cmd": cmds,
            "applied": True, "verify": v.get("out", "")[:400],
            "note": "改的是内存中的会话副本；要落到文件用 R2_Cmd 'w' 后重打包，"
                    "或改用 Apply_Hex_Patch + Apk_Pack"}
