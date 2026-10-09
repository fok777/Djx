"""
r2b_mcp/audit.py — 一致性自检

背景：原工程文档注释全面失真——
  tools_registry.py 写「124 具名 + 补齐到 164」
  server.py       写「164 工具分发到 6 个引擎模块」
  legacy_tools.py 写「205 工具」
实际 build_tools() 返回 276 个工具、10 个引擎模块。
新人接手会被直接带偏，且加新工具时没人发现文档没跟。

本模块在启动时自动跑，把「实际值 vs 文档声明值」的偏差直接报出来。

用法：
    from r2b_mcp.audit import run_audit, format_report
    report = run_audit()
    print(format_report(report))
"""
import ast
import os
import re
from typing import Dict, Any, List

from r2b_mcp.logging_setup import get_logger

log = get_logger(__name__)

_ENGINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine")


def _collect_engine_symbols() -> set:
    """静态收集 engine/ 下所有顶层可调用符号（不执行 import，避免重依赖）。"""
    names = set()
    if not os.path.isdir(_ENGINE_DIR):
        return names
    for fn in os.listdir(_ENGINE_DIR):
        if not fn.endswith(".py"):
            continue
        try:
            tree = ast.parse(open(os.path.join(_ENGINE_DIR, fn), encoding="utf-8").read())
        except SyntaxError as e:
            log.warning("engine/%s 语法解析失败: %s", fn, e)
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        names.add(t.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    names.add(a.asname or a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.asname or a.name.split(".")[0])
    return names


def _declared_counts() -> Dict[str, int]:
    """从源码注释/文档字符串里抓出「声明的工具数」，用于和实际值比对。"""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    declared: Dict[str, int] = {}
    targets = [
        os.path.join(base, "r2b_mcp", "tools_registry.py"),
        os.path.join(base, "r2b_mcp", "server.py"),
        os.path.join(base, "engine", "legacy_tools.py"),
        os.path.join(base, "README.md"),
    ]
    pat = re.compile(r"(\d{2,4})\s*(?:个)?\s*工?具")
    # 出现这些词说明该行是在描述历史/旧版，不算现行声明，跳过
    historical = ("旧版", "旧注释", "历史", "过期", "legacy", "原始蓝图")
    # 只在明确是「总表声明」的行上取数，避免把分类数量/影响面数字当声明
    total_only = ("共", "总计", "总数", "工具总数")
    for p in targets:
        if not os.path.exists(p):
            continue
        try:
            text = open(p, encoding="utf-8").read()
        except OSError:
            continue
        is_readme = os.path.basename(p) == "README.md"
        for line in text.splitlines():
            low = line.lower()
            if any(h in low for h in historical):
                continue
            if is_readme and not any(t in line for t in total_only):
                continue
            for m in pat.finditer(line):
                declared.setdefault(os.path.relpath(p, base), set()).add(int(m.group(1)))
    return {k: sorted(v) for k, v in declared.items()}


# README 里只有这几处是「总表声明」，其余（分类数量、缺失影响面）不算
_README_TOTAL_HINTS = ("共", "总计", "总数", "工具总数", "个工具")


def _shadowed_symbols() -> list:
    """检测跨模块同名函数：HANDLER_MODULES 里靠前的模块会遮蔽后面的，
    导致工具实际调到旧实现。这是静默 bug，必须显式检查。"""
    import inspect
    from r2b_mcp.server import HANDLER_MODULES
    from r2b_mcp.tools_registry import build_tools

    routes = {t["route"] for t in build_tools()}
    owner: Dict[str, list] = {}
    for m in HANDLER_MODULES:
        mname = m.__name__.split(".")[-1]
        for n in dir(m):
            if n.startswith("_") or n not in routes:
                continue
            if callable(getattr(m, n)):
                owner.setdefault(n, []).append(mname)

    bad = []
    for fn, mods in owner.items():
        if len(set(mods)) <= 1:
            continue
        # 第一个模块胜出；后面的是被遮蔽的
        winner = mods[0]
        for shadowed in dict.fromkeys(mods[1:]):
            # 允许显式转发（只调另一个模块同名函数的不算问题）
            src = ""
            try:
                src = inspect.getsource(getattr(
                    [m for m in HANDLER_MODULES
                     if m.__name__.split(".")[-1] == winner][0], fn))
            except Exception:
                pass
            if "from . import" in src and f"{fn}(" in src:
                continue  # 已是转发实现
            bad.append({"route": fn, "wins": winner, "shadowed": shadowed,
                        "hint": "同名函数被靠前模块遮蔽，实际调到旧实现"})
    return bad


def run_audit() -> Dict[str, Any]:
    """跑全量自检，返回结构化报告。"""
    from r2b_mcp.tools_registry import build_tools
    from r2b_mcp import server

    tools = build_tools()
    symbols = _collect_engine_symbols()

    dangling = [t["name"] for t in tools if t["route"] not in symbols]
    shadowed = _shadowed_symbols()
    dup_names = sorted({t["name"] for t in tools
                        if [x["name"] for x in tools].count(t["name"]) > 1})

    schema_err = []
    for t in tools:
        props = set(t.get("inputSchema", {}).get("properties", {}))
        for r in t.get("inputSchema", {}).get("required", []):
            if r not in props:
                schema_err.append(f'{t["name"]}.{r}')

    actual = len(tools)
    stale = []
    for f, nums in _declared_counts().items():
        for n in nums:
            if n != actual:
                stale.append({"file": f, "declared": n, "actual": actual})

    registered = [m.__name__.split(".")[-1] for m in getattr(server, "HANDLER_MODULES", [])]

    # 分类校验：所有工具必须能归入 categories.py 声明的大类，且合计等于总数
    from r2b_mcp.categories import category_of, CATEGORIES
    cat_sum = _by_category(tools)
    unclassified = [t["name"] for t in tools if category_of(t["name"]) not in CATEGORIES]
    cat_total = sum(cat_sum.values())
    cat_mismatch = [] if cat_total == actual else [
        f"分类合计 {cat_total} != 工具总数 {actual}"]

    return {
        "ok": not dangling and not dup_names and not schema_err
             and not unclassified and not cat_mismatch and not shadowed,
        "tools_actual": actual,
        "engine_modules_registered": len(registered),
        "engine_symbols": len(symbols),
        "dangling_routes": dangling,
        "duplicate_names": dup_names,
        "shadowed_symbols": shadowed,
        "schema_errors": schema_err,
        "stale_doc_counts": stale,
        "categories": cat_sum,
        "unclassified": unclassified,
        "category_errors": cat_mismatch,
    }


def _by_category(tools: List[Dict[str, Any]]) -> Dict[str, int]:
    """按 categories.py 的大类统计（而非原始前缀，避免 19 个前缀的碎片化）。"""
    from r2b_mcp.categories import category_of
    out: Dict[str, int] = {}
    for t in tools:
        c = category_of(t["name"])
        out[c] = out.get(c, 0) + 1
    return dict(sorted(out.items(), key=lambda x: -x[1]))


def format_report(rep: Dict[str, Any]) -> str:
    lines = [
        f'工具总数: {rep["tools_actual"]}   引擎模块: {rep["engine_modules_registered"]}   引擎符号: {rep["engine_symbols"]}',
    ]
    if rep["categories"]:
        lines.append("分类分布: " + "  ".join(f"{k}={v}" for k, v in rep["categories"].items()))
    if rep["dangling_routes"]:
        lines.append(f'✗ 悬空 route ({len(rep["dangling_routes"])}): {rep["dangling_routes"][:10]}')
    if rep["duplicate_names"]:
        lines.append(f'✗ 重名工具: {rep["duplicate_names"]}')
    if rep["unclassified"]:
        lines.append(f'✗ 未归类工具 ({len(rep["unclassified"])}): {rep["unclassified"][:10]}')
    for e in rep["category_errors"]:
        lines.append(f'✗ {e}')
    if rep["schema_errors"]:
        lines.append(f'✗ schema 错误: {rep["schema_errors"][:10]}')
    if rep["stale_doc_counts"]:
        for s in rep["stale_doc_counts"]:
            lines.append(f'⚠ 文档失真 {s["file"]}: 声明 {s["declared"]} 工具，实际 {s["actual"]}')
    lines.append("自检通过 ✓" if rep["ok"] and not rep["stale_doc_counts"] else "存在问题，见上")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_report(run_audit()))
