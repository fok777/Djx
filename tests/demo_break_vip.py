"""端到端真实破解 demo：test.apk 的 Go_VipCheck → patch 恒真 → 打包成品"""
import sys, os, json, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r2b_mcp.server import call_tool
BASE = "/var/minis/workspace/flutter_mcp"
APK = f"{BASE}/test.apk"


def t(n, a):
    return json.loads(call_tool(n, a)["content"][0]["text"])


print("### 1) Apk_Open 解压+识别")
ao = t("Apk_Open", {"file": APK})
apk_sid = ao["session_id"]
libapp = f"{BASE}/test.apk.extracted/{ao['so_list'][0]}"
print("  stack=", ao.get("stack"), "| libapp=", ao["so_list"][0])

print("### 2) R2_Open + 全量伪C")
r2_sid = t("R2_Open", {"so_path": libapp})["session_id"]
for _ in range(40):
    st = t("R2_PseudoC_Status", {"session_id": r2_sid})
    if st.get("status") == "done":
        break
    time.sleep(2)
print("  pseudoc:", st.get("status"), f"{st.get('cached')}/{st.get('total')} 函数已缓存")

print("### 3) 定位 Go_VipCheck + 读 BEFORE 伪C")
fns = t("R2_Functions", {"session_id": r2_sid, "keyword": "Go_VipCheck"})
addr = fns[0].split()[0]
before = t("R2_Get_PseudoC", {"session_id": r2_sid, "address": addr})
print(f"  偏移 {addr} (0x{int(addr):x}):")
print("  " + before.replace("\n", "\n  ")[:400])

print("### 4) 读判断点原始字节 + 生成 arm64 patch (mov w0,#1; ret = VIP恒真)")
rb = open(libapp, "rb").read()
print("  BEFORE 字节 @0x%x:" % int(addr), rb[int(addr):int(addr) + 8].hex())
hexstr = "20008052c0035fd6"   # aarch64: mov w0,#1 ; ret

print("### 5) Apply_Hex_Patch 写入判断点 (工具名 Apply_Hex_Patch, address 用 16 进制, 参数 hex_bytes)")
ap = t("Apply_Hex_Patch", {"session_id": r2_sid, "address": f"0x{int(addr):x}", "hex_bytes": hexstr})
print("  ", ap)
rb2 = open(libapp, "rb").read()
print("  AFTER  字节 @0x%x:" % int(addr), rb2[int(addr):int(addr) + 8].hex())

print("### 6) 重开 R2 会话读 AFTER 伪C（验证判断被短路）")
r2_sid2 = t("R2_Open", {"so_path": libapp})["session_id"]
time.sleep(1)
for _ in range(40):
    st = t("R2_PseudoC_Status", {"session_id": r2_sid2})
    if st.get("status") == "done":
        break
    time.sleep(2)
after = t("R2_Get_PseudoC", {"session_id": r2_sid2, "address": addr})
print("  " + after.replace("\n", "\n  ")[:300])

print("### 7) Apk_Pack 重新打包+签名 → 成品")
pk = t("Apk_Pack", {"session_id": apk_sid})
out = pk.get("output", "")
print("  ", pk)

print("### 8) 成品验证 (jarsigner 校验签名 + so 字节确认)")
res = subprocess.run(["jarsigner", "-verify", out], capture_output=True, text=True)
print("  jarsigner:", res.stdout.strip() or res.stderr.strip()[:120])
rb3 = open(libapp, "rb").read()
ok = rb3[int(addr):int(addr) + 8].hex() == hexstr
print(f"  VIP 判断点已 patch: {ok} (恒真 mov w0,#1;ret)")
print(f"\n✅ 成品: {out}  ({os.path.getsize(out)} bytes)")
