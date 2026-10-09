"""MCP smoke 测试：计数 + 快工具 + 会话绑定。"""
import os, sys, json, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r2b_mcp.server import call_tool, handle
from r2b_mcp.tools_registry import tool_count, build_tools

print("工具总数:", tool_count())
from collections import Counter
print("按类:", dict(Counter(t["category"] for t in build_tools())))

print("\n--- 快工具 ---")
for name, args in [
    ("R2_Version", {}),
    ("Fr_Detect", {}),
    ("Os_List_Dir", {"path": "/var/minis/workspace/flutter_mcp"}),
    ("Project_Save", {"name": "demo", "arch": "arm64", "notes": "测试", "commands": "aa\naflj\niE"}),
    ("Project_List", {}),
]:
    r = call_tool(name, args)
    print(f"[{name}] {r['content'][0]['text'][:150]}")

# Sqlite 真跑
db = "/var/minis/workspace/flutter_mcp/_test.db"
c = sqlite3.connect(db); c.execute("CREATE TABLE IF NOT EXISTS t(a INT)"); c.execute("INSERT INTO t VALUES(1),(2)"); c.commit(); c.close()
r = call_tool("Sqlite_Query", {"db_path": db, "query": "select * from t"})
print(f"[Sqlite_Query] {r['content'][0]['text'][:120]}")

print("\n--- tools/list JSON-RPC ---")
resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
print("tools/list 返回", resp["result"]["total"], "个工具")
