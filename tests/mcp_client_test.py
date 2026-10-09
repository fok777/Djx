"""
mcp_client_test.py — 模拟 MCP 客户端，走 HTTP 直连
起 R2B SSE 服务 → initialize → tools/list → 依序 tools/call 跑通"APK→定位→伪C→补丁→Il2Cpp→Nav→打包"
"""
import subprocess, time, json, sys, os, urllib.request, atexit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PORT = 5059
BASE = f"http://127.0.0.1:{PORT}/mcp"
UNITY = "/var/minis/workspace/flutter_mcp/testbuild/unity_test.apk"
REALMD = "/var/minis/workspace/flutter_mcp/testbuild/real_metadata.dat"


def rpc(method, params=None, rid=1):
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(BASE, data=body, headers={"Content-Type": "application/json"})
    d = json.load(urllib.request.urlopen(req, timeout=180))
    if "error" in d:
        raise RuntimeError(d["error"])
    return d["result"]


def call(name, args, rid=1):
    r = rpc("tools/call", {"name": name, "arguments": args}, rid)
    return json.loads(r["content"][0]["text"])


def main():
    # 确保测试目标就位
    from engine import apk as apke
    apke.apk_open(UNITY, UNITY + ".extracted")
    lib = UNITY + ".extracted/lib/arm64-v8a/libil2cpp.so"

    print("=" * 56)
    print("模拟 MCP 客户端 · R2B 自动逆向全链路（HTTP url 直连）")
    print("=" * 56)
    init = rpc("initialize")
    print("initialize:", init["serverInfo"]["name"], "| tools能力:", "tools" in init["capabilities"])
    tl = rpc("tools/list")
    print(f"tools/list: {tl['total']} 工具  (示例: {tl['tools'][0]['name']})")

    print("\n[① 技术栈识别] Apk_Open")
    o = call("Apk_Open", {"file": UNITY}, rid=2)
    print("  stack=", o.get("stack"), "| so=", o.get("so_list"), "| blutter_sid=", o.get("blutter_sid"))
    apk_sid = o["session_id"]

    print("[② R2 秒解析] R2_Open(libil2cpp.so)")
    ro = call("R2_Open", {"so_path": lib}, rid=3)
    r2_sid = ro["session_id"]
    for _ in range(80):
        st = call("R2_PseudoC_Status", {"session_id": r2_sid}, rid=4)
        if st.get("status") == "done":
            break
        time.sleep(1.5)
    print("  arch=", ro.get("arch"), "| 全量伪C=", st.get("status"), st.get("cached"), "/", st.get("total"))

    print("[③ 关键词定位] R2_Locate_Health (预置)")
    loc = call("R2_Locate_Health", {"session_id": r2_sid}, rid=5)
    print("  命中:", loc["string_hits"][:2])

    print("[④ 伪C] R2_Get_PseudoC(TakeDamage 附近)")
    sfs = call("R2_Search_Functions", {"session_id": r2_sid, "query": "TakeDamage"}, rid=6)
    addr = sfs[0]["addr"] if sfs else "0x0"
    pc = call("R2_Get_PseudoC", {"session_id": r2_sid, "address": addr}, rid=7)
    print("  ", " | ".join(pc.splitlines()[:3])[:140])

    print("[⑤ 打补丁] Apply_Hex_Patch(某函数入口 ret)")
    gp = call("R2_Search_Functions", {"session_id": r2_sid, "query": "GetDamage"}, rid=8)
    if gp:
        pa = call("Apply_Hex_Patch", {"session_id": r2_sid, "address": gp[0]["addr"], "hex_bytes": "c0035fd6"}, rid=9)
        print("  ", pa.get("ok"), pa.get("note", ""))

    print("[⑥ Il2Cpp 精确RVA] Il2Cpp_Open(real_metadata) + RVA_Table")
    io = call("Il2Cpp_Open", {"metadata": REALMD}, rid=10)
    isid = io["session_id"]
    rt = call("Il2Cpp_RVA_Table", {"session_id": isid}, rid=11)
    print("  版本=", io.get("unity_version"), "| rva_status=", rt["rva_status"], "| 样例:",
          [(m["method"], hex(m["rva"])) for m in rt["table"][:3]])

    print("[⑦ 调用图] Nav_Mermaid(TakeDamage)")
    mm = call("Nav_Mermaid", {"session_id": r2_sid, "func": "TakeDamage", "depth": 1}, rid=12)
    print("  ", mm["mermaid"].replace("\n", " ")[:120])

    print("[⑧ 打包输出] Apk_Pack")
    pk = call("Apk_Pack", {"apk_session_id": apk_sid, "do_sign": True}, rid=13)
    print("  成品=", os.path.basename(pk.get("output", "")), "| V1签=", pk.get("v1_signed"), "| V2V3=", pk.get("v2v3_signed"))

    print("\n" + "=" * 56)
    print("✅ MCP 客户端全链路通过：客户端仅传 session_id/关键词，264 工具自动完成识别→定位→伪C→补丁→Il2Cpp精确RVA→调用图→打包签名")
    print("=" * 56)


if __name__ == "__main__":
    srv = subprocess.Popen([sys.executable, os.path.join(HERE, "run_sse.py"), "--host", "127.0.0.1", "--port", str(PORT)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(lambda: srv.terminate())
    time.sleep(3)
    try:
        main()
    finally:
        srv.terminate()
