"""
r2b_mcp/categories.py — 分类体系与引擎映射（单一事实来源）

背景：原工程分类是 `name.split("_")[0]` 硬切，切出 19 个前缀，
但 README 只列了 8 行，且数量全错（R2 写 79 实际 87、Il2Cpp 写 14 实际 30、
Pentest_* 12 个完全没列、Os_*+散列 15 个被塞进一行）。
README 合计 225，实际 276，差 51 个工具没有归类。

本模块把 19 个前缀收敛成 **8 大类 + Misc**，并声明每类的引擎与可用性来源。
README / 文档一律从此生成，不再手写。

用法：
    from r2b_mcp.categories import CATEGORIES, summarize, engine_matrix
    print(summarize())
"""
from typing import Dict, Any, List

# 大类定义：id -> 展示名 / 归属前缀 / 引擎模块 / 是否真跑
CATEGORIES: Dict[str, Dict[str, Any]] = {
    "R2": {
        "title": "Radare2 静态分析",
        "prefixes": ["R2"],
        "engine": "engine/r2_engine.py",
        "real": True,
        "note": "真跑 radare2；含 28 个 R2_Locate_* 关键词定位",
    },
    "Fr": {
        "title": "Frida 动态注入",
        "prefixes": ["Fr"],
        "engine": "engine/frida_engine.py",
        "real": False,
        "note": "缺 frida-server 时降级出 JS 脚本，需真机执行",
    },
    "Blutter": {
        "title": "Flutter / Dart 解析",
        "prefixes": ["Blutter"],
        "engine": "engine/blutter_engine.py",
        "real": True,
        "note": "ELF 真解析，秒级出函数符号",
    },
    "Il2Cpp": {
        "title": "Unity IL2CPP 还原",
        "prefixes": ["Il2Cpp"],
        "engine": "engine/il2cpp_engine.py",
        "real": True,
        "note": "metadata 真解析，导出 C# 三件套",
    },
    "Ub": {
        "title": "Unidbg 离线模拟",
        "prefixes": ["Ub"],
        "engine": "engine/ub_engine.py",
        "real": False,
        "note": "需 unidbg.jar + java，设 R2B_UNIDBG_JAR 后可真跑",
    },
    "Nav": {
        "title": "导航 / 调用图",
        "prefixes": ["Nav"],
        "engine": "engine/nav_engine.py",
        "real": True,
        "note": "基于 r2 axt/axf 真跑",
    },
    "Pentest": {
        "title": "渗透测试",
        "prefixes": ["Pentest"],
        "engine": "engine/pentest_engine.py",
        "real": True,
        "note": "鉴权/端点/密钥/证书绑定/C2/SSL绕过/流量重放",
    },
    "Apk": {
        "title": "APK 解包 / 打包签名",
        "prefixes": ["Apk"],
        "engine": "engine/apk_engine.py",
        "real": True,
        "note": "真打包 + V1 jarsigner；缺 apksigner 则无 V2/V3",
    },
    "Engine": {
        "title": "外部引擎管理",
        "prefixes": ["Engine"],
        "engine": "engine/engine_mgmt.py + external_engine.py",
        "real": True,
        "note": "引擎资产的探测/配置/自检，放 so 后用这类工具接入",
    },
    "Misc": {
        "title": "系统 / 杂项",
        "prefixes": ["Os", "Project", "Find", "Apply", "Rename", "Scan",
                     "Shell", "File", "Sqlite", "Address", "Read"],
        "engine": "engine/misc_engine.py + tools_extra.py",
        "real": True,
        "note": "文件系统、shell、logcat、项目存档等 11 个离散前缀",
    },
}

_PREFIX_TO_CAT: Dict[str, str] = {
    p: cat for cat, meta in CATEGORIES.items() for p in meta["prefixes"]
}


def category_of(tool_name: str) -> str:
    """工具名 -> 大类 id（不在表内则归 Misc）。"""
    prefix = tool_name.split("_")[0]
    return _PREFIX_TO_CAT.get(prefix, "Misc")


def summarize() -> Dict[str, Any]:
    """统计各大类的实际工具数（动态读 build_tools，不写死）。"""
    from r2b_mcp.tools_registry import build_tools

    tools = build_tools()
    counts: Dict[str, int] = {c: 0 for c in CATEGORIES}
    for t in tools:
        counts[category_of(t["name"])] += 1
    return {
        "total": len(tools),
        "categories": [
            {"id": c, "title": CATEGORIES[c]["title"],
             "count": counts[c], "engine": CATEGORIES[c]["engine"],
             "real": CATEGORIES[c]["real"], "note": CATEGORIES[c]["note"]}
            for c in CATEGORIES if counts[c] > 0
        ],
    }


def format_summary() -> str:
    s = summarize()
    lines = [f'工具总数 {s["total"]} / 大类 {len(s["categories"])}', ""]
    lines.append(f'{"类":10s}{"数量":>5s}  {"引擎":28s}状态')
    for c in s["categories"]:
        flag = "✅真跑" if c["real"] else "⚠️降级"
        lines.append(f'{c["id"]:10s}{c["count"]:>5d}  {c["engine"]:28s}{flag}')
    tot = sum(c["count"] for c in s["categories"])
    lines.append("")
    lines.append(f'合计 {tot}' + ("  ✓ 与总数一致" if tot == s["total"] else "  ✗ 有工具未归类"))
    return "\n".join(lines)


def engine_matrix() -> List[Dict[str, Any]]:
    """引擎可用性矩阵：大类 -> 依赖的外部程序 -> 当前是否具备。"""
    import shutil
    deps = {
        "R2": ["r2", "radare2"],
        "Fr": ["frida", "frida-server"],
        "Blutter": [],
        "Il2Cpp": [],
        "Ub": ["java"],
        "Nav": ["r2", "radare2"],
        "Pentest": [],
        "Apk": ["jarsigner", "apksigner", "keytool"],
        "Misc": [],
    }
    out = []
    for c, meta in CATEGORIES.items():
        miss = [d for d in deps.get(c, []) if not shutil.which(d)]
        out.append({
            "category": c, "title": meta["title"], "engine": meta["engine"],
            "deps": deps.get(c, []), "missing": miss,
            "ready": not miss,
        })
    return out


if __name__ == "__main__":
    print(format_summary())
    print()
    print("=== 引擎可用性 ===")
    for e in engine_matrix():
        st = "就绪" if e["ready"] else f'缺 {e["missing"]}'
        print(f'  {e["category"]:10s} {st}')
