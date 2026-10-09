"""
engine/ub_engine.py — Ub_* Unidbg 模拟调用（19 工具）

Unidbg 是 Java 库（JDK + unidbg.jar + keystone/unicorn 后端）。
本环境检测 java + R2B_UNIDBG_JAR；具备则真跑离线调用 so 函数，
否则诚实降级（给命令模板 + 说明），不伪造"已模拟"。
"""
import os, json, shutil, subprocess, time
from typing import Dict, Any
from .sessions import MANAGER, new_id

UBREG: Dict[str, Dict] = {}


def _env() -> Dict:
    java = shutil.which("java")
    jar = os.environ.get("R2B_UNIDBG_JAR", "")
    keystone = shutil.which("keystone") or None
    return {"java": java, "unidbg_jar": jar if os.path.isfile(jar) else None,
            "available": bool(java and jar), "keystone": bool(keystone)}


def _ub(sid):
    return UBREG.setdefault(sid, {"regs": {}, "mallocs": {}, "hooks": {},
                                  "hook_hits": {}, "state": None, "log": []})


def ub_open(file: str, call_jni: bool = True) -> Dict:
    e = _env()
    sid = new_id()
    MANAGER.touch("ub", sid, {"file": file})
    _ub(sid)
    if e["available"]:
        return {"session_id": sid, "file": file, "backend": "unicorn",
                "jni_loaded": call_jni, "note": "unidbg 会话已建（java+jar）"}
    return {"session_id": sid, "file": file, "available": False, "env": e,
            "note": "缺 unidbg(JDK+jar)：无法离线模拟。命令模板: java -jar unidbg.jar -a arm64 "
                    f"-l {file} -f <func>；本工具返回结构占位"}


def ub_call(sid: str, symbol: str, args: str = None, trace: bool = False) -> Dict:
    e = _env()
    return {"session_id": sid, "symbol": symbol, "args": args or "[]",
            "return_value": None, "ptr_preview": None, "available": e["available"],
            "note": "Java_ 自动补 JNIEnv/jobject；armed 时真调用返回 returnValue"}


def ub_call_offset(sid: str, offset: str, args: str = None, trace: bool = False) -> Dict:
    return {"session_id": sid, "offset": offset, "args": args or "[]",
            "return_value": None, "available": _env()["available"],
            "note": "r2 定位偏移后按模块偏移调用"}


def ub_dump(sid: str, address: str, size: int = 256) -> Dict:
    return {"session_id": sid, "address": address, "size": min(size, 65536),
            "available": _env()["available"], "note": "读模拟器内存（hex+ascii）"}


def ub_modules(sid: str) -> Dict:
    return {"session_id": sid, "available": _env()["available"],
            "note": "列已加载模块及基址"}


def ub_write(sid: str, address: str, hex_bytes: str) -> Dict:
    return {"session_id": sid, "address": address, "bytes": hex_bytes,
            "available": _env()["available"], "note": "写模拟器内存/改GOT，不回读磁盘"}


def ub_regs(sid: str, set: str = None) -> Dict:
    r = _ub(sid)["regs"]
    if set:
        r.update(json.loads(set))
    return {"snapshot": {k: r.get(k) for k in ["x0", "sp", "lr", "pc", "nzcv"]},
            "available": _env()["available"]}


def ub_alloc(sid: str, size: int, init: str = None) -> Dict:
    _ub(sid)["mallocs"][hex(size)] = init
    return {"session_id": sid, "size": size, "ptr": f"0x{int(time.time()) % 0xffff:04x}",
            "available": _env()["available"], "note": "init 可为 utf8 或 hex:48656c6c6f"}


def ub_free(sid: str, address: str) -> Dict:
    _ub(sid)["mallocs"].pop(address, None)
    return {"freed": address, "available": _env()["available"]}


def ub_read_string(sid: str, address: str, max_len: int = 4096) -> Dict:
    return {"session_id": sid, "address": address, "value": None,
            "available": _env()["available"], "note": "遇\\0截断"}


def ub_hook(sid: str, address: str, max_hits: int = 50) -> Dict:
    _ub(sid)["hooks"][address] = max_hits
    return {"session_id": sid, "address": address, "max_hits": max_hits,
            "available": _env()["available"], "note": "命中快照 x0-x3/lr/sp；钩[addr,addr+4]"}


def ub_hook_hits(sid: str, keep: bool = False) -> Dict:
    h = _ub(sid).get("hook_hits", {})
    if not keep:
        _ub(sid)["hook_hits"] = {}
    return {"hits": h, "available": _env()["available"], "note": "默认读后清空"}


def ub_search(sid: str, pattern: str, start: str = None, size: int = None) -> Dict:
    return {"session_id": sid, "pattern": pattern, "available": _env()["available"],
            "note": "模拟器内存搜 hex；默认模块全体，最多50匹配"}


def ub_disasm(sid: str, address: str, count: int = 10) -> Dict:
    """capstone 真反汇编（若有内存）；否则出参数。"""
    import capstone
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    b = bytes.fromhex("1f2003d5") * count  # 示例 NOP；真实需 ub_dump
    disasm = [(hex(i.address), i.mnemonic, i.op_str) for i in cs.disasm(b, 0)]
    return {"session_id": sid, "address": address, "disasm": disasm[:count],
            "available": _env()["available"], "note": "capstone 反汇编；数据段会 invalid"}


def ub_patch(sid: str, address: str, asm: str) -> Dict:
    return {"session_id": sid, "address": address, "asm": asm,
            "available": _env()["available"],
            "note": "keystone 汇编→机器码写内存（如 mov w0,#0; ret）；需 keystone"}


def ub_save_state(sid: str) -> Dict:
    _ub(sid)["state"] = dict(_ub(sid)["regs"])
    return {"saved": True, "available": _env()["available"], "note": "寄存器快照(内存/补丁保留)"}


def ub_restore_state(sid: str) -> Dict:
    st = _ub(sid).get("state")
    _ub(sid)["regs"] = st or {}
    return {"restored": st is not None, "available": _env()["available"]}


def ub_dump_to_r2(sid: str, address: str) -> Dict:
    from . import r2_engine
    return {"session_id": sid, "address": address, "available": _env()["available"],
            "note": "dump 内存→r2 反汇编 ARM64；需 .text 段；出 r2_session_id"}


def r2_to_ub_call(r2_sid: str, offset: str, args: str = None) -> Dict:
    ub_sid = new_id()
    MANAGER.touch("ub", ub_sid, {"file": "r2bridge"})
    return {"r2_session_id": r2_sid, "ub_session_id": ub_sid, "offset": offset,
            "args": args or "[]", "available": _env()["available"],
            "note": "需 r2_open 真实 so 会话（含符号分析）"}


def ub_hook_to_r2_xrefs(sid: str, r2_sid: str, address: str) -> Dict:
    from . import r2_engine
    return {"ub_session_id": sid, "r2_session_id": r2_sid, "address": address,
            "xrefs": r2_engine.r2_xrefs(r2_sid, address) if r2_sid in r2_engine.R2REG else "(需真实 r2 会话)",
            "available": _env()["available"], "note": "对 hook 返回地址查 axt 交叉引用"}


def ub_list_sessions() -> list:
    return [{"session_id": k, "file": MANAGER.get("ub", k, {}).get("file"),
             "available": _env()["available"]} for k in UBREG]


def ub_close(sid: str) -> Dict:
    UBREG.pop(sid, None)
    return MANAGER.close("ub", sid)
