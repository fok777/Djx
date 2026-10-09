"""
engine/nav_extra.py — Nav_* 补齐的 11 个图算法与补丁候选工具

现行 nav_engine 有 12 个工具（建图、Mermaid、调用链、who-calls 等），
缺图的**加载/持久化、遍历算法（DFS/环检测）、统计、补丁候选推荐**。

图的边来自 nav_engine._call_edges()（反汇编 bl/call 建边），本模块直接复用。
"""
import json
import os
import re
from typing import Dict, Any, List

from . import r2_engine, nav_engine

NAVREG: Dict[str, Dict] = {}


def _reg(sid):
    return NAVREG.setdefault(sid, {"graph": None, "inv": None, "loaded_from": None})


def _g(sid):
    """取（正向边, 反向边, 函数名索引）。"""
    r = _reg(sid)
    if r["graph"] is None:
        try:
            g, inv = nav_engine._call_edges(sid)
        except Exception as e:
            raise KeyError(f"无法为会话 {sid} 建调用图: {e}")
        r["graph"], r["inv"] = g, inv
    idx = r2_engine._require(sid).get("func_index", {})
    return r["graph"], r["inv"], idx


def _name(idx, off) -> str:
    return idx.get(str(off)) or idx.get(off) or f"sub_{off}"


# ---------- 图加载 / 持久化 ----------

def nav_load(sid: str, path: str = None) -> Dict:
    """从磁盘加载已导出的图（nav_export_graph 的产物），避免每次重建。"""
    r = _reg(sid)
    if not path:
        g, inv, idx = _g(sid)
        return {"session_id": sid, "nodes": len(g), "edges": sum(len(v) for v in g.values()),
                "loaded_from": r["loaded_from"] or "built-in-memory"}
    if not os.path.isfile(path):
        return {"error": f"graph file not found: {path}", "session_id": sid}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"load failed: {e}", "session_id": sid}
    r["graph"] = {int(k): v for k, v in data.get("edges", {}).items()}
    r["inv"] = {int(k): v for k, v in data.get("inv", {}).items()}
    r["loaded_from"] = path
    return {"session_id": sid, "loaded": path,
            "nodes": len(r["graph"]), "edges": sum(len(v) for v in r["graph"].values())}


def nav_build_graph(sid: str, func: str = None, depth: int = 3) -> Dict:
    """显式建图并返回节点/边（nav_build_call_graph 的轻量版，只给结构）。"""
    g, inv, idx = _g(sid)
    if func:
        sub = _subgraph(g, _resolve(idx, func), depth)
        return {"session_id": sid, "root": func, "depth": depth,
                "nodes": [{"offset": hex(n), "name": _name(idx, n)} for n in sub],
                "edges": [{"from": hex(a), "to": hex(b)}
                          for a in sub for b in g.get(a, []) if b in sub]}
    return {"session_id": sid, "nodes": len(g),
            "edges": sum(len(v) for v in g.values()),
            "note": "全图较大，建议指定 func 与 depth 取子图"}


def _resolve(idx, name_or_addr) -> int:
    """名字/地址 → 偏移 int。"""
    try:
        return int(name_or_addr, 16) if str(name_or_addr).lower().startswith("0x") \
            else int(name_or_addr)
    except (ValueError, TypeError):
        pass
    for a, n in idx.items():
        if n == name_or_addr or name_or_addr in str(n):
            return int(a)
    raise KeyError(f"function not found: {name_or_addr}")


def _subgraph(g, root: int, depth: int) -> set:
    """从 root 出发向下 depth 层可达节点。"""
    seen, stack = {root}, [(root, 0)]
    while stack:
        cur, d = stack.pop()
        if d >= depth:
            continue
        for nxt in g.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, d + 1))
    return seen


# ---------- 遍历算法 ----------

def nav_dfs(sid: str, func: str, depth: int = 10,
            direction: str = "down") -> Dict:
    """深度优先遍历，direction=down 看它调谁，up 看谁调它。"""
    g, inv, idx = _g(sid)
    root = _resolve(idx, func)
    table = g if direction == "down" else inv
    out: List[Dict] = []
    seen = {root}

    def walk(node, d, path):
        if d > depth or len(out) >= 500:
            return
        for nxt in table.get(node, []):
            if nxt in path:  # 环
                out.append({"offset": hex(nxt), "name": _name(idx, nxt),
                            "depth": d + 1, "cycle": True})
                continue
            if nxt in seen:
                continue
            seen.add(nxt)
            out.append({"offset": hex(nxt), "name": _name(idx, nxt),
                        "depth": d + 1, "cycle": False})
            walk(nxt, d + 1, path + [nxt])

    walk(root, 0, [root])
    return {"session_id": sid, "root": func, "direction": direction,
            "depth": depth, "visited": len(out), "nodes": out[:500]}


def nav_cycle(sid: str, max_cycles: int = 50) -> Dict:
    """检测调用环（递归/互相调用），用于识别加密轮函数与死循环。"""
    g, inv, idx = _g(sid)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[int, int] = {}
    cycles: List[List[str]] = []

    def dfs(u, stack):
        if len(cycles) >= max_cycles:
            return
        color[u] = GRAY
        stack.append(u)
        for v in g.get(u, []):
            if color.get(v, WHITE) == GRAY:
                i = stack.index(v)
                cycles.append([_name(idx, x) for x in stack[i:]] + [_name(idx, v)])
            elif color.get(v, WHITE) == WHITE:
                dfs(v, stack)
        stack.pop()
        color[u] = BLACK

    for n in list(g):
        if color.get(n, WHITE) == WHITE:
            dfs(n, [])
    return {"session_id": sid, "cycles_found": len(cycles),
            "cycles": cycles[:max_cycles],
            "note": "环常见于递归、状态机、加解密轮函数"}


def nav_stats(sid: str) -> Dict:
    """图统计：节点数、边数、入度/出度 Top、孤立函数。"""
    g, inv, idx = _g(sid)
    nodes = set(g) | set(inv)
    out_deg = sorted(((n, len(g.get(n, []))) for n in nodes), key=lambda x: -x[1])
    in_deg = sorted(((n, len(inv.get(n, []))) for n in nodes), key=lambda x: -x[1])
    isolated = [n for n in nodes if not g.get(n) and not inv.get(n)]
    return {"session_id": sid,
            "nodes": len(nodes),
            "edges": sum(len(v) for v in g.values()),
            "top_callers": [{"name": _name(idx, n), "out_degree": d} for n, d in out_deg[:20]],
            "top_callees": [{"name": _name(idx, n), "in_degree": d} for n, d in in_deg[:20]],
            "isolated_count": len(isolated),
            "isolated_sample": [_name(idx, n) for n in isolated[:20]]}


# ---------- 补丁候选 ----------

_PATCH_HINTS = [
    (r"(?i)(verify|check|valid|auth|licen[sc]e|sign)", "校验/授权"),
    (r"(?i)(vip|premium|member|subscri|purchase|pay|order)", "付费/会员"),
    (r"(?i)(trial|expire|limit|quota|count)", "试用/限额"),
    (r"(?i)(root|jailbreak|emulator|debug|tamper|integrity)", "环境检测"),
    (r"(?i)(ad|advert)", "广告"),
]


def nav_patch_candidates(sid: str, keywords: str = None,
                         max_results: int = 50) -> Dict:
    """推荐值得打补丁的函数：名字命中校验/付费/反调试等关键词 + 入度高。"""
    g, inv, idx = _g(sid)
    pats = [(re.compile(p), t) for p, t in _PATCH_HINTS]
    if keywords:
        pats = [(re.compile(re.escape(keywords), re.I), "自定义")] + pats
    out = []
    for off, name in idx.items():
        if not name:
            continue
        for rx, tag in pats:
            if rx.search(str(name)):
                try:
                    o = int(off)
                except (ValueError, TypeError):
                    continue
                out.append({"offset": hex(o), "name": name, "tag": tag,
                            "in_degree": len(inv.get(o, [])),
                            "out_degree": len(g.get(o, []))})
                break
    out.sort(key=lambda x: (-x["in_degree"], x["name"]))
    return {"session_id": sid, "total": len(out),
            "candidates": out[:max_results],
            "hint": "in_degree 高说明被多处调用，改动影响面大，优先验证"}


# ---------- 其他 ----------

def nav_function(sid: str, func: str) -> Dict:
    """单函数画像：调用者、被调用者、是否成环、建议。"""
    g, inv, idx = _g(sid)
    o = _resolve(idx, func)
    callers = [{"offset": hex(c), "name": _name(idx, c)} for c in inv.get(o, [])]
    callees = [{"offset": hex(c), "name": _name(idx, c)} for c in g.get(o, [])]
    leaf = not callees
    return {"session_id": sid, "offset": hex(o), "name": _name(idx, o),
            "callers": callers[:50], "caller_count": len(callers),
            "callees": callees[:50], "callee_count": len(callees),
            "is_leaf": leaf,
            "note": ("叶子函数，无内部调用，改返回值安全" if leaf
                     else "有下游调用，patch 前确认不影响其他逻辑")}


def nav_modules(sid: str) -> Dict:
    """列出当前会话涉及的模块/段信息（走 r2 iS）。"""
    try:
        r = r2_engine.r2_cmd(sid, "iSj", timeout=60)
        out = r.get("out", "")
        j = out[out.find("["):] if "[" in out else out
        secs = json.loads(j)
        return {"session_id": sid, "count": len(secs),
                "sections": [{"name": s.get("name"), "addr": hex(s.get("vaddr", 0)),
                              "size": s.get("vsize", 0)} for s in secs]}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "session_id": sid}


def nav_export_graph(sid: str, func: str = None, path: str = None,
                     fmt: str = "json", depth: int = 3) -> Dict:
    """导出图到文件（json / dot / mermaid），可再 nav_load 载回。"""
    g, inv, idx = _g(sid)
    if func:
        sub = _subgraph(g, _resolve(idx, func), depth)
        edges = {a: [b for b in g.get(a, []) if b in sub] for a in sub}
    else:
        edges = g
    if fmt == "mermaid":
        lines = ["graph TD"]
        for a, bs in edges.items():
            for b in bs:
                lines.append(f'  {_name(idx,a)} --> {_name(idx,b)}')
        text = "\n".join(lines)
    elif fmt == "dot":
        lines = ["digraph G {"]
        for a, bs in edges.items():
            for b in bs:
                lines.append(f'  "{_name(idx,a)}" -> "{_name(idx,b)}";')
        lines.append("}")
        text = "\n".join(lines)
    else:
        text = json.dumps({"edges": {str(k): v for k, v in edges.items()},
                           "inv": {str(k): v for k, v in inv.items()},
                           "names": {str(k): _name(idx, k) for k in edges}},
                          ensure_ascii=False)
    if path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            open(path, "w", encoding="utf-8").write(text)
            return {"session_id": sid, "written": path, "fmt": fmt,
                    "nodes": len(edges)}
        except OSError as e:
            return {"error": f"write failed: {e}", "session_id": sid}
    return {"session_id": sid, "fmt": fmt, "nodes": len(edges), "content": text[:20000]}


def nav_close(sid: str) -> Dict:
    """释放该会话缓存的图。"""
    r = NAVREG.pop(sid, None)
    try:
        r2_engine._require(sid).pop("_nav_cache", None)
    except Exception:
        pass
    return {"session_id": sid, "closed": bool(r),
            "note": "仅清图缓存，r2 会话本身用 R2_Close 关闭"}


# ---------- 别名：工具名小写化与函数名不一致时对齐 ----------
# Nav_BuildGraph -> nav_buildgraph（而非 nav_build_graph）
nav_buildgraph = nav_build_graph
# Nav_ExportGraph -> nav_exportgraph（而非 nav_export_graph）
nav_exportgraph = nav_export_graph
# Nav_CallChain -> nav_callchain（复用 nav_engine 已有实现）
def nav_callchain(sid: str, from_func: str, to_func: str) -> Dict:
    """调用链（复用 nav_engine.nav_call_chain）。"""
    return nav_engine.nav_call_chain(sid, from_func, to_func)
