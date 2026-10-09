"""verify2.py — 验证往深做的 4 类新工具 + 164 工具 + 新闭环。"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import dex, hardened, export_symbols, capture, apk
from r2b_mcp import tools_registry, server

DEX = "/var/minis/workspace/flutter_mcp/r2b/android/build/dexout/classes.dex"
EXT = apk.apk_open("/var/minis/workspace/flutter_mcp/test.apk")["extract_dir"]

print("=" * 56)
print("DEX 逆向（真实解析 d8 生成的 classes.dex）")
print("=" * 56)
r = dex.parse_dex(DEX)
print("ok:", r.get("ok"), "string_count:", r.get("string_count"),
      "class_count:", r.get("class_count"))
print("classes:", r.get("classes", [])[:6])

print("=" * 56)
print("壳/加固检测")
print("=" * 56)
h = hardened.detect_hardened(EXT)
print("hardened:", h["hardened"], "vendors:", h["vendors"], "dex_sizes:", h["dex_sizes"])

print("=" * 56)
print("符号导出（r2cmd + IDA）")
print("=" * 56)
syms = [{"name": "Go_VipCheck", "value": "0x798"},
         {"name": "MyGame.GameLogic::IsVip", "rva": None}]
e1 = export_symbols.export_r2cmd(syms, "/var/minis/workspace/flutter_mcp/r2b/out_test/r2cmd.txt", "libapp.so")
e2 = export_symbols.export_ida(syms, "libapp.so", "/var/minis/workspace/flutter_mcp/r2b/out_test/ida.py")
print("r2cmd:", e1["ok"], e1["symbols"], "个符号 →", e1["r2cmd"].split("/")[-1])
print("ida  :", e2["ok"], "→", e2["ida_script"].split("/")[-1])

print("=" * 56)
print("抓包对比（mitmproxy + Frida）")
print("=" * 56)
cap = capture.capture_verify({"domain": "com.ayue.flutter", "so": "libapp.so"},
                              "/var/minis/workspace/flutter_mcp/r2b/out_test/cap")
print("mitm addon:", cap["mitmproxy"]["addon"].split("/")[-1],
      "frida_net:", cap["frida_net"]["script"].split("/")[-1])

print("=" * 56)
print("164 工具（加 8 核心后）")
print("=" * 56)
tools = tools_registry.build_tools()
print("总数:", len(tools), " 核心:", sum(1 for t in tools if t.get("is_core")))
newc = [t["name"] for t in tools if t.get("is_core") and t["name"].startswith("r2b_dex")
        or t["name"].startswith("r2b_detect_hardened") or t["name"].startswith("r2b_export")
        or t["name"].startswith("r2b_capture")]
print("新增核心:", newc)
# 真实调一个新核心
rr = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "r2b_dex_classes", "arguments": {"dex_path": DEX}}})
d = json.loads(rr["result"]["content"][0]["text"])
print("r2b_dex_classes → class_count:", d.get("class_count"))

print("=" * 56)
print("六步全闭环（织入 壳检测/DEX/抓包）")
print("=" * 56)
from engine import pipeline
fl = pipeline.run_full_loop("/var/minis/workspace/flutter_mcp/test.apk",
                            "/var/minis/workspace/flutter_mcp/r2b/out_test/loop2")
for k in ("1b_hardened", "2b_dex", "5_verify"):
    print(f"  {k}: {json.dumps(fl['steps'].get(k), ensure_ascii=False)[:150]}")
print("闭环 keys:", list(fl["steps"].keys()))
print("\n✅ 全部通过" if all([r.get("ok"), e1["ok"], e2["ok"], len(tools) == 164]) else "❌ 有未通过项")
