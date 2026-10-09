#!/usr/bin/env python3
"""
tools/gen_tools_data.py — 从工具总表生成安卓端的 app/assets/tools_data.json

数据源是 r2b_mcp/categories.py（分类单一事实来源）与 tools_registry.py（描述），
不手写。工具数变化时重跑本脚本即可。

    python3 tools/gen_tools_data.py
"""
import os
import sys
import json
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 每个大类的展示信息（图标字符 + 主题色 + 说明）
ENGINE_META = {
    "R2":      ("\U0001f50e",  "#00897B", "ic_cat_r2", "Radare2", "二进制静态分析引擎",
                "核心用途：so/dex 反汇编、函数分析、交叉引用、全量伪C、打补丁。",
                "适用场景：静态逆向、算法还原、内存读写、搜串定位。",
                "工作流：R2_Open → R2_Functions / R2_Search_String → R2_Pseudo_C → R2_Patch。",
                "边界：依赖 radare2，未安装时本类全部不可用。"),
    "Blutter": ("\U0001f50e",  "#1565C0", "ic_cat_blutter", "Blutter", "Flutter / Dart 逆向",
                "核心用途：解析 libapp.so，提取 Dart 类、函数、字符串与对象池。",
                "适用场景：Flutter 应用逆向、定位 VIP 判断、还原业务逻辑。",
                "工作流：Blutter_Analyze → Blutter_Classes / Blutter_Strings → Blutter_To_Frida。",
                "边界：仅 Android arm64；未接真实引擎时类结构为启发式推断。"),
    "Fr":      ("\U0001f438",  "#EF6C00", "ic_cat_frida", "Frida", "动态 Hook 与运行时验证",
                "核心用途：注入 JS 脚本 hook 函数、读写内存、绕过证书校验。",
                "适用场景：动态验证猜想、抓包、绕过反调试与 SSL Pinning。",
                "工作流：Fr_Open → Fr_Script / Fr_Hook → Fr_Attach 观察输出。",
                "边界：需设备 root 并运行 frida-server；未运行只产出脚本。"),
    "Il2Cpp":  ("\u26a1",  "#6A1B9A", "ic_cat_il2cpp", "Il2Cpp", "Unity IL2CPP 符号还原",
                "核心用途：解析 global-metadata.dat，还原 C# 类、方法、字段。",
                "适用场景：Unity 游戏逆向、定位关键逻辑函数。",
                "工作流：Il2Cpp_Open → Il2Cpp_Classes / Il2Cpp_Methods → 定位偏移。",
                "边界：metadata 不含类型签名，字段类型恒为 unknown。"),
    "Ub":      ("\u2699",  "#2E7D32", "ic_cat_unidbg", "Unidbg", "离线模拟执行",
                "核心用途：无需真机模拟调用 so 中的函数，验证算法。",
                "适用场景：离线跑加密函数、补环境调用 JNI。",
                "工作流：Ub_Open → Ub_Dlopen → Ub_Call 调用目标函数。",
                "边界：需 java 与 unidbg.jar；复杂 so 需补环境。"),
    "Nav":     ("\U0001f9ed",  "#00838F", "ic_cat_nav", "Nav", "控制流导航与反混淆",
                "核心用途：调用图、环检测、混淆特征识别、补丁候选。",
                "适用场景：理清函数调用链、识别控制流平坦化。",
                "工作流：Nav_Load → Nav_Function / Nav_Export_Graph → Nav_Patch_Candidates。",
                "边界：依赖 radare2 会话。"),
    "Pentest": ("\U0001f510",  "#C62828", "ic_cat_pentest", "Pentest", "鉴权与流量安全分析",
                "核心用途：提取鉴权头、密钥、端点、证书绑定与 C2 特征。",
                "适用场景：安全审计、接口梳理、密钥硬编码检查。",
                "工作流：Pentest_Auth_* / Pentest_Key_* → Pentest_Endpoint_* 。",
                "边界：静态提取为主，动态验证需配合 Frida。"),
    "Apk":     ("\U0001f4e6",  "#5D4037", "ic_cat_apk", "Apk", "APK 解包与重打包",
                "核心用途：解包、识别技术栈、替换 so、重签名打包。",
                "适用场景：补丁落地、回编译安装验证。",
                "工作流：Apk_Open → Apk_Patch / Apk_Pack → Apk_Install。",
                "边界：无 apksigner 时只支持 V1 签名。"),
    "Misc":    ("\U0001f4c1",  "#455A64", "ic_cat_misc", "Os / 项目", "系统与工程辅助",
                "核心用途：文件读写、命令执行、日志、工程状态管理。",
                "适用场景：环境操作、批量处理、结果归档。",
                "工作流：Os_* 直接调用，无需会话。",
                "边界：Shell_Command 受权限限制。"),
    "Engine":  ("\U0001f527",  "#37474F", "ic_cat_engine", "Engine", "引擎管理与自检",
                "核心用途：查看引擎状态、配置调用方式、清点缺失资产。",
                "适用场景：首次部署排查、引擎补货。",
                "工作流：Engine_Inventory → Engine_Fetch_Plan → Engine_Set。",
                "边界：只做检测与配置，不自动下载。"),
}


# 参数 schema：从 tools_registry 的 SPEC 拿（形态 name, desc, props, required），
# 用来在 UI 上生成输入表单，不再靠手填 JSON。
try:
    from r2b_mcp.tools_registry import SPEC
except Exception:
    SPEC = None

_SCHEMA = {}
if SPEC:
    for item in SPEC:
        try:
            _SCHEMA[str(item[0])] = {
                "props": item[2] if len(item) > 2 else {},
                "required": list(item[3]) if len(item) > 3 else [],
            }
        except Exception:
            pass


def _with_params(t):
    """工具条目 + 参数 schema，供 UI 生成输入表单。"""
    nm = t.get("name", "")
    d = {"name": nm, "desc": t.get("description", "")}
    meta = _SCHEMA.get(nm)
    if meta:
        props = meta.get("props") or {}
        req = meta.get("required") or []
        params = []
        for k, v in props.items():
            if not isinstance(v, dict):
                continue
            params.append({
                "name": k,
                "type": v.get("type", "string"),
                "desc": v.get("description", ""),
                "required": k in req,
            })
        if params:
            d["params"] = params
    return d


from r2b_mcp.categories import category_of, CATEGORIES


def main():
    from r2b_mcp.tools_registry import build_tools
    tools = build_tools()

    # 按大类聚合
    grouped = defaultdict(list)
    for t in tools:
        grouped[category_of(t["name"])].append(t)

    engines = []
    for cat in CATEGORIES:
        items = sorted(grouped.get(cat, []), key=lambda x: x["name"])
        if not items:
            continue
        icon, color, icon_res, name, subtitle, core, scene, flow, limit = ENGINE_META.get(
            cat, (cat[:2].upper(), "#546E7A", "ic_cat_engine", cat, "", "", "", "", ""))
        engines.append({
            "name": name,
            "key": cat,
            "icon": icon,
            "icon_res": icon_res,
            "color": color,
            "subtitle": subtitle,
            "core": core,
            "scene": scene,
            "flow": flow,
            "limit": limit,
            "count": len(items),
            "tools": [_with_params(t) for t in items],
        })

    data = {"tool_total": len(tools), "engines": engines}

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "app", "assets", "tools_data.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    print(f"✓ 已生成 {out}")
    print(f"  工具总数 {len(tools)} / 大类 {len(engines)}")
    for e in engines:
        print(f"    {e['name']:12s} {e['count']:>3} 个")
    return out


if __name__ == "__main__":
    main()
