"""run_stdio.py — R2B MCP · stdio 传输入口（供 Cursor/Claude MCP client 用）
客户端配法：
  "r2b": {"command": "python3",
          "args": ["/var/minis/workspace/flutter_mcp/r2b/run_stdio.py"]}
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r2b_mcp.server import run_stdio

if __name__ == "__main__":
    run_stdio()
