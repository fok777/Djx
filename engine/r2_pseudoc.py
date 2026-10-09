"""
engine/r2_pseudoc.py — Radare2 集成（Blutter_To_R2：函数跳 r2 看伪 C / 打补丁）

radare2 已安装。按需分析（避免对大 libapp.so 全量 -A 卡死）：
  r2_open      打开 + 导入符号（轻量）
  r2_pseudo_c  单函数出伪 C
  r2_search    在 so 里搜字符串/字节（找偏移）
  r2_write_patch 在 r2 里写 patch（配合 pack_sign 重新打包）
所有 r2 命令用 subprocess 带超时，失败降级不崩。
"""
import os, subprocess, json, shutil, tempfile
from typing import Dict, Any

R2 = shutil.which("radare2") or "radare2"
TIMEOUT = 60


def _run_r2(so: str, cmds: str, timeout: int = TIMEOUT, analyze: bool = False) -> Dict[str, Any]:
    """走 r2_engine._r2：有 r2 可执行文件就用，没有则退到 ctypes 直调 libr_core.so。"""
    from . import r2_engine
    if analyze:
        cmds = "aa; " + cmds
    r = r2_engine._r2(so, cmds, timeout=timeout)
    if isinstance(r.get("out"), str) and len(r.get("out", "")) > 4000:
        r["out"] = r["out"][-4000:]
    return r


def r2_open(so: str) -> Dict[str, Any]:
    """轻量打开：架构 + 符号表。"""
    r = _run_r2(so, "iI; iE 400; ls | head -30", analyze=False)
    info = {"path": so}
    if r["ok"]:
        out = r["out"]
        import re
        m = re.search(r"arch:\s*(\S+)\s*bits:\s*(\d+)", out)
        if m:
            info["arch"], info["bits"] = m.group(1), m.group(2)
        info["symbols"] = [l for l in out.splitlines() if l.startswith("sym.")]
    info.update(r)
    return info


def r2_pseudo_c(session_or_so: Any, func: str) -> str:
    """单函数出伪 C。session 是 r2_open 的 dict。"""
    so = session_or_so.get("path") if isinstance(session_or_so, dict) else session_or_so
    # pdf = pseudo-c disassembly；先定位函数再出
    cmds = f"af @ {func} >/dev/null 2>&1; pdf @ {func} 2>/dev/null || pdf {func}"
    r = _run_r2(so, cmds, analyze=True)
    return r["out"] if r["ok"] else f"(r2: {r['err']})"


def r2_search_string(so: str, needle: str) -> Dict[str, Any]:
    """按字符串找偏移（关键词定位）。"""
    r = _run_r2(so, f"/s {needle} | head -40")
    return {"needle": needle, "hits": r["out"].strip().splitlines()[:40], "ok": r["ok"]}


def r2_write_patch(so: str, offset_hex: str, byte_hex: str, out_so: str = None) -> Dict[str, Any]:
    """在 so 里写 patch（offset 写 bytes）。返回 patch 后的文件。"""
    out_so = out_so or (so + ".patched")
    try:
        data = bytearray(open(so, "rb").read())
        off = int(offset_hex, 16)
        b = bytes.fromhex(byte_hex.replace(" ", ""))
        data[off:off + len(b)] = b
        open(out_so, "wb").write(bytes(data))
        return {"ok": True, "offset": offset_hex, "bytes": byte_hex, "out": out_so,
                "note": "已写 patch；下一步 pack_sign 重新打包签名"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def r2_cmd(so: str, cmd: str) -> Dict[str, Any]:
    """通用 Radare2 命令执行（覆盖 Xrefs/Hexdump/Sections/Imports/Exports/Strings 等）。
    cmd 例: 'axt @ <addr>' / 'pdf @ <fn>' / 'iE' / 'iS' / 'is' / 'px <n> @ <addr>'
    """
    r = _run_r2(so, cmd, analyze=True)
    return {"cmd": cmd, "so": so, "ok": r["ok"], "out": r["out"], "err": r.get("err", "")}
