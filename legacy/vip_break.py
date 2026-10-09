"""
engine/vip_break.py — "你说破 VIP → 过程全自动" 的破解编排

组合 识别→定位→算偏移→生成patch字节→服务端绕过→打包，产出**可执行破解方案**：
  - 本地判断点：确切偏移 + arm64 patch 字节（return_true / 分支绕过）
  - 服务端验证：定位验证 API + 生成响应改写 Frida hook（vip:false→true）
  - 打包：重打包 + V1/V2/V3 签名命令
真执行（frida 跑 hook / 装成品）需目标设备，方案里标注执行清单。
"""
import os, json
from typing import Dict, Any, List, Optional
from . import apk, r2_pseudoc, patch, capture, pack_sign

VIP_KEYWORDS = ["isVip", "vip", "isVipUser", "is_vip", "premium", "member",
                "isMember", "isPaid", "hasLicense", "activated", "entitled", "trial"]


def break_vip(apk_path: str, out_dir: str = None,
              keywords: List[str] = None) -> Dict[str, Any]:
    kw = keywords or VIP_KEYWORDS
    out_dir = out_dir or apk_path + ".vipbreak"
    os.makedirs(out_dir, exist_ok=True)
    plan: Dict[str, Any] = {"goal": "破解VIP/绕过验证", "apk": apk_path, "out_dir": out_dir}

    # ① 技术栈 + 目标 so
    s1 = apk.apk_open(apk_path, out_dir)
    plan["stack"] = s1["stack_info"]["stack"]
    so = (s1["stack_info"]["targets"].get("libapp_so") or
          s1["stack_info"]["targets"].get("libil2cpp_so") or [apk_path])[0]
    plan["target_so"] = so
    ext = s1["extract_dir"]

    # ② 定位 VIP 判断点（r2 搜字符串 → 交叉引用出偏移）
    locate = {}
    for k in kw[:8]:
        r = r2_pseudoc.r2_search_string(so, k)
        if r["hits"]:
            locate[k] = r["hits"][:5]
    plan["local_judgments"] = [
        {"keyword": k, "offsets": offs, "note": "这些偏移处是 VIP 判断的字符串引用，r2 xrefs(axt) 找判断函数"}
        for k, offs in locate.items()
    ]

    # ③ 生成 patch 字节（对每个命中的偏移，给出 arm64 改写建议）
    patch_plan = []
    for k, offs in list(locate.items())[:6]:
        for off in offs[:1]:
            p = patch.plan_vip_patch(so, k, off, op="bypass_check")
            patch_plan.append(p)
    plan["patch_bytes"] = patch_plan
    plan["patch_summary"] = {
        "count": len(patch_plan),
        "example": patch_plan[0] if patch_plan else None,
        "note": "offset+bytes 确认后写 so（patch.apply / r2_write_patch）"}

    # ④ 服务端验证绕过
    api = capture.locate_verify_api(so, ext)
    domain = api["domains"][0] if api["domains"] else "example.com"
    hook = capture.hook_response_rewrite(domain, out=os.path.join(out_dir, "vip_resp_hook.js"))
    plan["server_bypass"] = {
        "verify_api_candidates": api["verify_api_candidates"][:10],
        "domain": domain,
        "hook_script": hook["script"],
        "rewrites": hook["rewrites"],
        "frida_cli": hook["frida_cli"],
    }

    # ⑤ 打包签名（生成命令；真重打包需先 patch 落盘）
    pk = pack_sign.make_keystore(os.path.join(out_dir, "keystore.jks"))
    plan["pack_sign"] = {
        "keystore": pk["keystore"], "alias": pk["alias"],
        "commands": [
            "zip 重打包(替换patched so) → signed.apk",
            f"jarsigner -digest SHA256 -signedjar final.apk repacked.apk {pk['keystore']} {pk['alias']} -storepass {pk['storepass']}",
            "(有apksigner则加 V2/V3) apksigner sign --ks ... final.apk",
        ],
    }

    # ⑥ 执行清单（哪些需真机）
    plan["runbook"] = [
        "1. 真机/模拟器装目标 App",
        "2. 本地判断: 按 patch_bytes 写 so 重打包，或 Frida 运行时 patch",
        "3. 服务端验证: frida -U -f <pkg> -l " + os.path.basename(hook["script"]),
        "4. 验证: Frida hook 读 isVip 返回值 / 抓包看 vip 响应被改写",
        "5. 打包: 按 pack_sign.commands 出成品 APK",
    ]
    plan["verified"] = False
    plan["note"] = "方案已生成；本地 patch 字节+服务端 hook 脚本就绪。真执行(装包/frida跑/验证)需目标设备"

    json.dump(plan, open(os.path.join(out_dir, "vip_break_plan.json"), "w"),
              ensure_ascii=False, indent=1, default=str)
    plan["plan_file"] = os.path.join(out_dir, "vip_break_plan.json")
    return plan
