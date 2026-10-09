"""
engine/nav_engine.py — Nav_* 12 工具（调用图/导航/反混淆，主打 Mermaid）

调用图用**反汇编 bl/call 指令**直接建边（radare2 axf/axt 对动态 so 不稳），
比依赖 r2 xref 可靠。session_id 即 R2_Open 的 sid。
"""
import re
from typing import Dict, Any, List
from . import r2_engine


def _addr_of(sid, name_or_addr) -> str:
    idx = r2_engine._require(sid).get("func_index", {})
    if name_or_addr in idx:
        return name_or_addr
    for a, n in idx.items():
        if n == name_or_addr or name_or_addr in n:
            return a
    try:
        return str(int(name_or_addr, 16) if str(name_or_addr).lower().startswith("0x") else name_or_addr)
    except Exception:
        return name_or_addr


def _call_edges(sid):
    """反汇编各函数解析 bl 目标，建调用边 {from_off:int → [to_off:int]}。自给自足建索引。"""
    reg = r2_engine._require(sid)
    if reg.get("_nav_cache"):
        return reg["_nav_cache"], reg["_nav_inv"]
    so = r2_engine._so(sid)
    idx = reg.get("func_index", {})
    if not idx:  # 后台线程还没建 → 自己 aa;aflj 建
        import json as _j
        r = r2_engine._r2(so, "aa; aflj", timeout=120)
        try:
            js = r["out"][r["out"].find("["):]
            idx = {str(f["offset"]): f.get("name", "") for f in _j.loads(js)}
            reg["func_index"] = idx
        except Exception:
            idx = {}
    inv = {k: v for k, v in idx.items() if k.isdigit()}
    name2off = {}
    for off, nm in inv.items():
        base = nm[4:] if nm.startswith("sym.") else nm
        name2off[base] = int(off)
        name2off[nm] = int(off)
    edges = {}
    for off in list(inv.keys())[:800]:
        offi = int(off)
        dis = r2_engine._r2(so, f"aa; pd 30 @ {offi}")["out"]
        tgts = set()
        for m in re.finditer(r"bl\s+(?:fcn\.0*([0-9a-fA-F]+)|sym\.(\w+)|([0-9a-f]{4,}))", dis):
            if m.group(1):
                tgts.add(int(m.group(1), 16))
            elif m.group(2) and m.group(2) in name2off:
                tgts.add(name2off[m.group(2)])
            elif m.group(3):
                tgts.add(int(m.group(3), 16))
        tgts.discard(offi)
        edges[offi] = sorted(tgts)
    reg["_nav_cache"] = edges
    reg["_nav_inv"] = inv
    return edges, inv


def _xref_from(sid, addr):
    edges, inv = _call_edges(sid)
    return edges.get(int(addr, 0) if str(addr).lower().startswith("0x") else int(addr), [])


def _xref_to(sid, addr):
    edges, inv = _call_edges(sid)
    target = int(addr, 0) if str(addr).lower().startswith("0x") else int(addr)
    return [inv.get(o, str(o)) for o, tg in edges.items() if target in tg]


def nav_build_call_graph(sid, func, depth=1):
    edges, inv = _call_edges(sid)
    start = _addr_of(sid, func)
    try:
        start = int(start, 0) if str(start).lower().startswith("0x") else int(start)
    except (ValueError, TypeError):
        return {"nodes": {}, "edges": [], "note": f"无法解析 {func} 的地址(需先 R2_Open)"}
    inv_full = {int(k): (v[4:] if str(v).startswith("sym.") else v) for k, v in inv.items() if k.isdigit()}
    graph = {"nodes": {start: inv_full.get(start, func)}, "edges": []}
    frontier = [start]
    for _ in range(int(depth)):
        nxt = []
        for a in frontier:
            for t in edges.get(a, []):
                if t not in graph["nodes"]:
                    graph["nodes"][t] = inv_full.get(t, f"0x{t:04x}")
                graph["edges"].append({"from": a, "to": t, "from_name": inv_full.get(a), "to_name": inv_full.get(t)})
                nxt.append(t)
        frontier = nxt
    return graph


def nav_mermaid(sid, func, depth=1):
    g = nav_build_call_graph(sid, func, depth)
    lines = ["graph TD", f"  N0[{g['nodes'].get(list(g['nodes'])[0]) if g['nodes'] else func}]"]
    for i, e in enumerate(g["edges"]):
        lines.append(f"  N{i}[{e['from_name'] or e['from']}] --> N{i}b[{e['to_name'] or e['to']}]")
    return {"mermaid": "\n".join(lines), "node_count": len(g["nodes"]), "edge_count": len(g["edges"]),
            "note": "调用图由反汇编 bl 指令解析；粘进 mermaid 渲染"}


def nav_call_chain(sid, from_func, to_func):
    edges, inv = _call_edges(sid)
    start, end = _addr_of(sid, from_func), _addr_of(sid, to_func)
    start = int(start, 0) if str(start).lower().startswith("0x") else int(start)
    end = int(end, 0) if str(end).lower().startswith("0x") else int(end)
    inv_full = {int(k): (v[4:] if str(v).startswith("sym.") else v) for k, v in inv.items() if k.isdigit()}
    from collections import deque
    q, parent = deque([(start, [start])], {start: None})
    found = []
    while q:
        a, path = q.popleft()
        if a == end:
            found = path
            break
        for t in edges.get(a, []):
            if t not in parent:
                parent[t] = a
                q.append((t, path + [t]))
    names = [inv_full.get(a, str(a)) for a in found]
    return {"from": from_func, "to": to_func, "chain": names, "found": bool(found)}


def nav_who_calls(sid, func):
    a = _addr_of(sid, func)
    callers = _xref_to(sid, a)
    inv = r2_engine._require(sid).get("func_index", {})
    return {"func": func, "callers": [c for c in callers][:100],
            "note": "谁 bl 到该函数（反汇编解析）"}


def nav_what_calls(sid, func):
    a = _addr_of(sid, func)
    callees = _xref_from(sid, a)
    inv_full = {int(k): (v[4:] if str(v).startswith("sym.") else v) for k, v in inv.items() if k.isdigit()}
    return {"func": func, "callees": [inv_full.get(c, f"0x{c:04x}") for c in callees]}


def nav_reverse_search(sid, result_str):
    so = r2_engine._so(sid)
    hits = r2_engine.r2_search_string(sid, result_str, max_results=5)
    off = re.search(r"0x([0-9a-f]+)", hits[0]).group(1) if hits else None
    return {"result_str": result_str, "string_offset": off,
            "note": "字符串偏移；引用它的位置需数据 xref（r2 axt data）"}


def nav_symbol_jump(sid, symbol):
    a = _addr_of(sid, symbol)
    pc = r2_engine.r2_get_pseudoc(sid, a)
    return {"symbol": symbol, "address": a, "pseudoc_preview": pc[:400]}


def nav_deobfuscate_guide(sid, func):
    a = _addr_of(sid, func)
    dis = r2_engine.r2_disassemble(sid, a, 40)
    flat = dis.count("jumptable") > 2 or ("switch" in dis and dis.count("jmp") > 8)
    hints = []
    if flat:
        hints.append("疑似控制流扁平化(Flattening)：大量 jumptable/分支")
        hints.append("还原思路：符号执行(Triton/Miasm)求分发器 switch 真实控制流")
    if dis.count("nop") > 20:
        hints.append("大量 nop：疑似 BCF/填充，可对比 r2ghidra")
    return {"func": func, "obfuscated_like": flat, "hints": hints,
            "note": "启发式识别；深度还原需 De-OLLVM/符号执行工具链"}


def nav_function_context(sid, func):
    a = _addr_of(sid, func)
    inv = r2_engine._require(sid).get("func_index", {})
    inv_full = {int(k): (v[4:] if str(v).startswith("sym.") else v) for k, v in inv.items() if k.isdigit()}
    return {"func": func, "address": a,
            "callees": [inv_full.get(c, c) for c in _xref_from(sid, a)],
            "callers": _xref_to(sid, a),
            "pseudoc": r2_engine.r2_get_pseudoc(sid, a)[:600]}


def nav_dominators(sid, func=None, depth=2):
    edges, inv = _call_edges(sid)
    inv_full = {int(k): (v[4:] if str(v).startswith("sym.") else v) for k, v in inv.items() if k.isdigit()}
    in_deg = {}
    for frm, tg in edges.items():
        for t in tg:
            in_deg[t] = in_deg.get(t, 0) + 1
    top = sorted(in_deg.items(), key=lambda x: -x[1])[:20]
    return {"hub_functions": [{"name": inv_full.get(o, f"0x{o:04x}"), "in_degree": d} for o, d in top if d],
            "note": "入度高的枢纽函数（关键逻辑节点）"}


def nav_export_graph(sid: str = None, func: str = None, fmt: str = "json",
                    path: str = None, depth: int = 2) -> Dict:
    """导出调用图。完整实现（含导出到文件）见 nav_extra.nav_export_graph。"""
    from . import nav_extra
    return nav_extra.nav_export_graph(sid=sid, func=func, path=path,
                                     fmt=fmt, depth=depth)


def nav_list_sessions():
    return [{"r2_session_id": k, "file": v.get("file"), "arch": v.get("arch_name")}
            for k, v in r2_engine.R2REG.items()]
