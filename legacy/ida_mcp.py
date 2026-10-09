"""
engine/ida_mcp.py — IDA 官方/社区 MCP 接入 + 等价 IDA 脚本生成

用户问"IDA 有官方 MCP，能否把这些工具加进来"。本模块把 IDA MCP 的
~30 个工具纳入 R2B（作为第 4 引擎域 Ida_*）：
  - 若配置了 R2B_IDA_MCP_URL（IDA 的 MCP endpoint，stdio/HTTP），则**转发**调用
  - 否则生成**等价 IDA Python 脚本**（可粘进 IDA Script File），诚实标注"未连 IDA"

覆盖 IDA MCP 常见工具：导航/函数/反编译(HexRays)/xrefs/字符串/重命名/类型/内存/补丁。
"""
import os, json, urllib.request
from typing import Dict, Any, List

IDA_MCP_URL_ENV = "R2B_IDA_MCP_URL"   # 指向运行中的 IDA MCP（HTTP 端点）

# IDA MCP 工具 → 说明
IDA_TOOLS: List[Dict[str, str]] = [
    {"name": "get_current_address", "desc": "当前光标地址"},
    {"name": "get_current_function", "desc": "当前函数"},
    {"name": "look_at", "desc": "总览：数据库/函数/字符串摘要"},
    {"name": "list_functions", "desc": "列出所有函数"},
    {"name": "analyze_function", "desc": "分析单函数（结构/签名/xref）"},
    {"name": "analyze_functions_batch", "desc": "批量分析函数"},
    {"name": "decompile_function", "desc": "HexRays 反编译出 C 伪代码"},
    {"name": "disassemble_function", "desc": "反汇编单函数"},
    {"name": "find_function_by_name", "desc": "按名找函数"},
    {"name": "get_function_by_name", "desc": "函数名→地址"},
    {"name": "find_xrefs_to", "desc": "找引用到某地址的 xref"},
    {"name": "find_xrefs_from", "desc": "找某函数调用的 xref"},
    {"name": "get_defined_strings", "desc": "列出已定义字符串"},
    {"name": "find_code_by_string", "desc": "字符串→引用它的代码"},
    {"name": "search_defined_strings", "desc": "搜字符串"},
    {"name": "rename_function", "desc": "重命名函数"},
    {"name": "rename_variable", "desc": "重命名局部变量"},
    {"name": "set_comments", "desc": "写注释"},
    {"name": "get_comments", "desc": "读注释"},
    {"name": "get_defined_types", "desc": "已定义类型"},
    {"name": "define_type", "desc": "定义结构/类型"},
    {"name": "declare_type", "desc": "声明 C 类型"},
    {"name": "create_enum", "desc": "创建枚举"},
    {"name": "get_memory_block", "desc": "内存块信息"},
    {"name": "set_map_bytes", "desc": "写内存/字节"},
    {"name": "patch_bytes", "desc": "打字节补丁"},
    {"name": "find_bytes", "desc": "按字节模式搜索"},
    {"name": "int_convert", "desc": "整数进制转换"},
    {"name": "list_globals", "desc": "列出全局变量"},
    {"name": "get_global_variable", "desc": "读全局变量"},
    {"name": "set_global_variable", "desc": "写全局变量"},
    {"name": "get_metadata", "desc": "数据库元信息"},
    {"name": "set_metadata", "desc": "写元信息"},
]


def ida_endpoint() -> str:
    return os.environ.get(IDA_MCP_URL_ENV, "").strip()


def _forward(ida_tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """转发到运行中的 IDA MCP（HTTP JSON-RPC）。"""
    url = ida_endpoint()
    if not url:
        return {"ok": False, "forwarded": False,
                "reason": f"未设 {IDA_MCP_URL_ENV}；返回等价 IDA 脚本",
                "ida_script": _gen_script(ida_tool, args)}
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": ida_tool, "arguments": args}}).encode()
    try:
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return {"ok": True, "forwarded": True, "result": json.loads(r.read().decode())}
    except Exception as e:
        return {"ok": False, "forwarded": False, "error": str(e),
                "ida_script": _gen_script(ida_tool, args)}


def _gen_script(ida_tool: str, args: Dict[str, Any]) -> str:
    """生成等价 IDA Python 脚本（可粘进 IDA: File/Script）。"""
    a = json.dumps(args, ensure_ascii=False)
    m = {
        "decompile_function": f"import idc, ida_hexrays\nf = ida_hexrays.decompile(idc.name_to_ea({args.get('name',repr(args.get('address')))}))\nprint(f)",
        "list_functions": "import idautils\nprint([idc.get_func_name(e) for e in idautils.Functions()])",
        "find_xrefs_to": f"import idautils\nfor x in idautils.XrefsTo({args.get('address') or 0}, 0):\n    print(hex(x.frm), x.type)",
        "get_defined_strings": "import idc\nfor i in range(idc.get_strqty()):\n    print(idc.get_strname(i))",
        "disassemble_function": f"import idc, idautils\nimport ida_lines\nf = idc.name_to_ea({repr(args.get('name',''))})\nprint('\\n'.join(ida_lines.tag_remove(l) for l in idautils.DisasmLines(f)))",
        "patch_bytes": f"import ida_bytes\nida_bytes.patch_bytes({args.get('address')}, {args.get('bytes_hex','')})",
    }
    code = m.get(ida_tool, f"# {ida_tool}({a})  手动在 IDA 里执行对应操作")
    return (f"# R2B 生成的等价 IDA 脚本 · {ida_tool}\n"
            f"# 用法: IDA 打开目标 → Edit/Script → 运行本段（或 Ctrl+Alt+S 粘到 Output 窗）\n"
            f"import ida_kernutils\n{code}\n")


def ida_call(tool: str, args: Dict[str, Any] = None) -> Dict[str, Any]:
    """统一入口：能转发就转发，否则给等价脚本。"""
    known = [t["name"] for t in IDA_TOOLS]
    # 支持 R2B 侧 r2b_ida_<tool> 或直接 <tool>
    name = tool.replace("r2b_ida_", "")
    if name not in known:
        return {"ok": False, "error": f"未知 IDA 工具 {name}；可选: {known}"}
    return _forward(name, args or {})


def ida_tool_list() -> List[Dict[str, Any]]:
    return [{"name": "r2b_ida_" + t["name"], "description": t["desc"] + "（IDA MCP）",
             "route_args": {"ida_tool": t["name"]}} for t in IDA_TOOLS]
