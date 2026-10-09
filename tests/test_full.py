"""全链路：模拟 AI 客户端走完整逆向工作流（真实调用 R2/Blutter/打包）。"""
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from r2b_mcp.server import call_tool

APK = "/var/minis/workspace/flutter_mcp/test.apk"


def t(name, args):
    r = call_tool(name, args)
    txt = r["content"][0]["text"]
    print(f"[{name}] {txt[:180]}")
    print()
    return json.loads(txt)


print("=== 1) Apk_Open（解压+检测+Blutter）===")
r = t("Apk_Open", {"file": APK})
apk_sid = r["session_id"]
print("stack=", r.get("stack"), "so_list=", r.get("so_list"), "blutter=", r.get("blutter"))
blutter_sid = r.get("blutter_sid")

print("=== 2) Blutter 秒解析产物（独立会话）===")
t("Blutter_Classes", {"session_id": blutter_sid, "filter": "MyGame"})
t("Blutter_Functions", {"session_id": blutter_sid, "filter": "Go_"})
t("Blutter_PP_Table", {"session_id": blutter_sid, "filter": "vip"})
t("Blutter_Strings", {"session_id": blutter_sid, "filter": "http"})

print("=== 3) R2 打开 libapp.so + 全量伪C ===")
libapp = APK + ".extracted/lib/arm64-v8a/libapp.so"
ro = t("R2_Open", {"so_path": libapp})
r2_sid = ro["session_id"]
print("r2_sid=", r2_sid, "arch=", ro.get("arch"), "funcs=", ro.get("func_count"), "storage=", ro.get("storage"))

# 等后台全量伪C 完成
for _ in range(30):
    st = json.loads(call_tool("R2_PseudoC_Status", {"session_id": r2_sid})["content"][0]["text"])
    print("pseudoc_status:", st.get("status"), "cached=", st.get("cached"), "/", st.get("total"))
    if st.get("status") == "done" or st.get("cached", 0) > 0:
        break
    time.sleep(2)

print("\n=== 4) R2 具体操作 ===")
t("R2_Functions", {"session_id": r2_sid, "keyword": "Go_"})
t("R2_Search_String", {"session_id": r2_sid, "query": "vip"})
# 取一个 Go_ 函数地址出伪C
fns = json.loads(call_tool("R2_Functions", {"session_id": r2_sid, "keyword": "Go_"})["content"][0]["text"]) if False else None
import re
fns = call_tool("R2_Functions", {"session_id": r2_sid, "keyword": "Go_"}).get("content")[0]["text"]
# R2_Functions 返回 list[str]，直接看
print("R2_Functions(Go_):", fns[:200] if isinstance(fns, str) else fns)
