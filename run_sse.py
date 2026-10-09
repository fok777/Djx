"""
run_sse.py — R2B MCP · HTTP / streamable-HTTP 传输

  POST /mcp      JSON-RPC（单请求单响应，streamable-HTTP 简化）
  GET  /mcp      探活 + serverInfo
  GET  /health   探活
默认监听 0.0.0.0:5051，可用 --host / --port 覆盖。

mcp.json 客户端配法：
  {"mcpServers": {"r2b": {"url": "http://<host>:5051/mcp"}}}
"""
import os, json, sys, threading, argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r2b_mcp.server import handle, build_tools, PROTOCOL_VERSION, _status


def _cors(h):
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id")
    h.send_header("Access-Control-Max-Age", "86400")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        _cors(self)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        _cors(self)
        self.end_headers()

    def do_GET(self):
        if self.path.rstrip("/") in ("/mcp", ""):
            self._json({"name": "Radare2Blutter MCP (R2B)",
                        "protocolVersion": PROTOCOL_VERSION,
                        "tools": len(build_tools()), "status": _status(),
                        "endpoints": {"post": "/mcp", "health": "/health"}})
        elif self.path.rstrip("/") == "/health":
            self._json({"ok": True, "tools": len(build_tools())})
        else:
            self._json({"error": "not found", "endpoints": ["/mcp", "/health"]}, 404)

    def do_POST(self):
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._json({"error": "use POST /mcp"}, 404)
            return
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else "{}"
        try:
            msgs = json.loads(raw)
        except Exception:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "bad json"}})
            return
        if isinstance(msgs, list):
            self._json([handle(m) for m in msgs if m])
        else:
            self._json(handle(msgs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5051)
    args = ap.parse_args()
    print(f"R2B MCP HTTP @ http://{args.host}:{args.port}/mcp  tools={len(build_tools())}",
          flush=True)
    ThreadingHTTPServer((args.host, args.port), H).serve_forever()


if __name__ == "__main__":
    main()
