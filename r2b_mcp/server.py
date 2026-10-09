"""
r2b_mcp/server.py — Radare2Blutter MCP 服务端（JSON-RPC 2.0）

工具数量与引擎模块数量由 build_tools() / HANDLER_MODULES 动态决定，不写死数字。

会话参数（session_id/blutter_session_id/frida_session_id）自动绑定到引擎形参
(sid/blutter_sid/frida_sid/r2_sid...)，AI 只需按工具 schema 传参。
"""
import os, sys, json, inspect, shutil, traceback
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from engine import (r2_engine, blutter_engine, frida_engine, ub_engine, apk_engine,
                    misc_engine, tools_extra, il2cpp_engine, nav_engine, pentest_engine,
                    blutter_extra, ub_extra, il2cpp_extra, nav_extra, frida_extra,
                    r2_extra, apk_extra, engine_mgmt)
from r2b_mcp.tools_registry import build_tools, tool_count
from r2b_mcp.config import cfg
from r2b_mcp.logging_setup import get_logger, setup_logging

log = get_logger(__name__)

PROTOCOL_VERSION = "2025-06-18"
HANDLER_MODULES = [r2_engine, blutter_engine, frida_engine, ub_engine, apk_engine,
                   misc_engine, tools_extra, il2cpp_engine, nav_engine, pentest_engine,
                   # 补齐模块（legacy 登记但未实现的 87 个工具）
                   blutter_extra, ub_extra, il2cpp_extra, nav_extra, frida_extra,
                   r2_extra, apk_extra, engine_mgmt]

# 工具表与 route 缓存：原实现每次 call_tool 都重建 276 个 dict，改为进程内一次构建
_TOOLS_CACHE: Optional[list] = None
_TOOL_INDEX: Optional[Dict[str, dict]] = None
_ROUTE_CACHE: Dict[str, Any] = {}


def _tools() -> list:
    global _TOOLS_CACHE, _TOOL_INDEX
    if _TOOLS_CACHE is None:
        _TOOLS_CACHE = build_tools()
        _TOOL_INDEX = {t["name"]: t for t in _TOOLS_CACHE}
        log.info("工具表已构建：%d 个工具，%d 个引擎模块", len(_TOOLS_CACHE), len(HANDLER_MODULES))
    return _TOOLS_CACHE


def _tool_index() -> Dict[str, dict]:
    _tools()
    return _TOOL_INDEX


def _resolve(route: str):
    """解析 route 到引擎函数，结果缓存，避免每次遍历 10 个模块。"""
    if route in _ROUTE_CACHE:
        return _ROUTE_CACHE[route]
    fn = None
    for m in HANDLER_MODULES:
        f = getattr(m, route, None)
        if callable(f):
            fn = f
            break
    _ROUTE_CACHE[route] = fn
    return fn


def _bind(fn, args: Dict) -> Dict:
    """把用户参数名绑定到引擎形参名（会话 ID 智能匹配 + 普通精确匹配）。"""
    args = args or {}
    sig = list(inspect.signature(fn).parameters)
    out = {}
    sess = {k: v for k, v in args.items() if "sid" in k.lower() or "session" in k.lower()}
    normal = {k: v for k, v in args.items() if k not in sess}
    for k, v in normal.items():
        if k in sig:
            out[k] = v
    sess_params = [p for p in sig if "sid" in p.lower() or "session" in p.lower()]
    for k, v in sess.items():
        if k in sig:
            out[k] = v
            continue
        kl = k.lower()
        target = None
        if "frida" in kl:
            target = next((p for p in sess_params if "frida" in p.lower()), None)
        elif "blutter" in kl:
            target = next((p for p in sess_params if "blutter" in p.lower()),
                          next((p for p in sess_params if "frida" not in p.lower()), None))
        else:  # session_id / r2_session_id
            target = next((p for p in sess_params if p in ("sid", "session_id", "r2_sid", "blutter_sid")),
                          sess_params[0] if sess_params else None)
        if target and target not in out:
            out[target] = v
    return out


def _status() -> Dict:
    def has(n):
        return bool(shutil.which(n))
    try:
        from engine import engine_runtime
        er = engine_runtime.status()
    except Exception:
        er = {"items": {}, "missing": []}
    items = er.get("items", {})
    return {"radare2": has("radare2") or bool(items.get("radare2", {}).get("path")),
            "frida": has("frida") or has("frida16") or bool(items.get("frida_server", {}).get("path")),
            "java": has("java"), "jarsigner": has("jarsigner"),
            "apksigner": has("apksigner"), "keytool": has("keytool"),
            "builtin_engines": er,
            "tools": tool_count(),
            "note": "内置 so (frida_gadget/blutter) 已就绪；frida_server/unidbg jar 缺则降级出脚本"}


# 工具执行线程池：给每个工具调用套超时，避免单工具卡死拖垮服务。
# 隔离性说明：Python 无法强制杀死线程，超时后该线程仍在后台跑完，
# 但请求会立即返回错误，服务不再被阻塞。
_TOOL_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="r2b-tool")


def _invoke_with_timeout(fn, kwargs, timeout):
    """在线程池里执行 fn，超时则抛 FuturesTimeout。"""
    if timeout is None or timeout <= 0:
        return fn(**kwargs)
    fut = _TOOL_POOL.submit(fn, **kwargs)
    return fut.result(timeout=timeout)


def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    tool = _tool_index().get(name)
    if tool is None:
        log.warning("未知工具: %s", name)
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    ra = tool.get("route_args") or {}
    route = ra.get("__route__", tool["route"])
    pre = {k: v for k, v in ra.items() if k != "__route__"}
    merged = {**pre, **(args or {})}
    fn = _resolve(route)
    if fn is None:
        log.error("工具 %s 的 route 未实现: %s", name, route)
        return {"content": [{"type": "text", "text": f"no handler for route {route}"}], "isError": True}
    kwargs = _bind(fn, merged)
    log.debug("调用 %s -> %s(%s)", name, route, list(kwargs))
    try:
        timeout = getattr(cfg, "tool_timeout", 120)
        result = _invoke_with_timeout(fn, kwargs, timeout)
        text = json.dumps(result, ensure_ascii=False, default=str)
        if len(text) > cfg.max_output_chars:
            text = text[:cfg.max_output_chars] + "\n...[truncated]"
        return {"content": [{"type": "text", "text": text}]}
    except TypeError as e:
        log.error("工具 %s 参数绑定失败: %s | 期望参数: %s",
                  name, e, list(inspect.signature(fn).parameters))
        return {"content": [{"type": "text",
                             "text": f"参数错误 {e}；{route} 接受: {list(inspect.signature(fn).parameters)}"}],
                "isError": True}
    except FuturesTimeout:
        # 超时不是崩溃：明确告诉调用方"卡住了"，并把超时值暴露出来便于调大
        log.error("工具 %s 超过 %s 秒未完成", name, getattr(cfg, "tool_timeout", 120))
        return {"content": [{"type": "text",
                             "text": f"工具 {name} 执行超过 "
                                     f"{getattr(cfg, 'tool_timeout', 120)} 秒未返回。"
                                     f"该任务仍在后台运行，可稍后重试，"
                                     f"或用环境变量 R2B_TOOL_TIMEOUT 调大超时。\n"
                                     f"提示：优先改用带 timeout 参数的工具"
                                     f"（如 R2_Cmd / Blutter_Analyze）自行控制耗时。"}],
                "isError": True}
    except Exception as e:
        log.error("工具 %s 执行异常", name, exc_info=True)
        return {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}


def _ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle(msg: Dict[str, Any]) -> Dict[str, Any]:
    m = msg.get("method")
    id_ = msg.get("id")
    p = msg.get("params", {})
    if m == "initialize":
        return _ok(id_, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                         "serverInfo": {"name": "Radare2Blutter MCP (R2B)", "version": "2.0"}})
    if m in ("notifications/initialized", "initialized"):
        return {}
    if m == "tools/list":
        tools = [{"name": t["name"], "description": t["description"],
                  "inputSchema": t["inputSchema"]} for t in _tools()]
        return _ok(id_, {"tools": tools, "total": len(tools)})
    if m == "r2b/status":
        return _ok(id_, _status())
    if m == "r2b/audit":
        from r2b_mcp.audit import run_audit
        return _ok(id_, run_audit())
    if m == "tools/call":
        name = p.get("name")
        res = call_tool(name, p.get("arguments", {}))
        return _ok(id_, {"name": name, **res})
    if m == "ping":
        return _ok(id_, {})
    return _err(id_, -32601, f"method not found: {m}")


def _startup() -> None:
    """启动自检：建目录、建工具表、跑一致性审计。"""
    setup_logging()
    cfg.ensure_dirs()
    n = len(_tools())
    log.info("R2B MCP 启动：%d 个工具 / %d 个引擎模块", n, len(HANDLER_MODULES))
    if cfg.auto_audit:
        try:
            from r2b_mcp.audit import run_audit, format_report
            rep = run_audit()
            for line in format_report(rep).splitlines():
                log.info("[audit] %s", line)
        except Exception as e:
            log.warning("自检跳过: %s: %s", type(e).__name__, e)


def run_stdio():
    import sys as _s
    _startup()
    for line in _s.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log.warning("收到非法 JSON，已跳过: %s", e)
            continue
        try:
            resp = handle(msg)
        except Exception as e:
            log.error("处理消息异常", exc_info=True)
            resp = _err(msg.get("id"), -32603, f"internal error: {e}")
        if resp:
            print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    run_stdio()
