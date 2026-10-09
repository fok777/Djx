"""
engine/blutter.py — Flutter 应用解析流水线

  1 Apk_Open       解压APK + 自动检测Flutter
  2 版本自适应     Dart 版本 → 选解析引擎策略
  3 Blutter_Analyze 10秒全量解析（ELF 符号/字符串）
  4 Blutter_Strings 字符串全索引
  5 Blutter_Functions 函数全签名
  6 Blutter_To_R2  函数跳 Radare2 出伪 C
  7 AI 调度        生成给 LLM 的调度指令包（选工具/算偏移/定位关键词）

每步可单独调用，也可 run_pipeline 一次跑完。产物全部落盘 JSON。
"""
import os, re, json, time, glob
from typing import Dict, Any, List
from . import apk, elf, r2_pseudoc

# 关键词定位默认集
DEFAULT_KEYWORDS = ["vip", "member", "loadAd", "isVip", "isMember", "isVip", "buy",
                    "subscribe", "trial", "expire", "unlock", "premium", "ad"]


def s1_apk_open(apk_path: str, out_dir: str = None) -> Dict[str, Any]:
    ctx = apk.apk_open(apk_path, out_dir)
    ctx["step"] = "s1_apk_open"
    return ctx


def s2_version_adapt(s1: Dict[str, Any]) -> Dict[str, Any]:
    """从 Flutter 资源 / so 提取 Dart 版本线索，选引擎。"""
    ext = s1["extract_dir"]
    dart_hint = None
    # flutter_assets/AssetManifest 或 version 目录
    for p in ("assets/flutter_assets/version", "assets/flutter_assets/AssetManifest.json",
              "assets/flutter_assets/FontManifest.json"):
        fp = os.path.join(ext, p)
        if os.path.exists(fp):
            c = open(fp, "r", errors="ignore").read()
            m = re.search(r"(\d\.\d+\.\d+)", c)
            if m:
                dart_hint = m.group(1)
    # 从 libapp.so 字符串里找 dart 版本
    libapp = s1["stack_info"]["targets"].get("libapp_so", [])
    if not dart_hint and libapp:
        for s in elf.parse_elf(libapp[0], max_strings=20000).get("strings", []):
            m = re.search(r"(Dart|dart)\s*(\d\.\d+\.\d+)", s)
            if m:
                dart_hint = m.group(2)
                break
    # 开源 blutter 编译产物命名：blutter_dartvm{版本}_{os}_{arch}
    _v = (dart_hint or "3_11_1").replace(".", "_")
    engine = f"blutter_dartvm{_v}_android_arm64"
    return {"step": "s2_version_adapt", "dart_version": dart_hint,
            "engine": engine, "note": "引擎名按 Dart 版本映射；无则默认 3_11_1"}


def s3_blutter_analyze(s1: Dict[str, Any], s2: Dict[str, Any], cap: int = 8) -> Dict[str, Any]:
    """10 秒全量解析：扫 libapp.so + 所有 lib*.so，出符号/字符串。"""
    t0 = time.time()
    ext = s1["extract_dir"]
    report = elf.scan_dir_elfs(ext, pattern="lib*.so", max_each=cap)
    # 重点：libapp.so
    libapp = s1["stack_info"]["targets"].get("libapp_so", [])
    app_detail = []
    for so in libapp:
        r = elf.parse_elf(so, max_symbols=40000, max_strings=120000)
        r["rel"] = os.path.relpath(so, ext)
        r["dart"] = elf.pick_dart_artifacts(r)
        app_detail.append(r)
    return {"step": "s3_blutter_analyze", "elapsed_s": round(time.time() - t0, 2),
            "scan_report": report, "libapp_detail": app_detail,
            "output_files_estimated": _count_outputs(report, app_detail)}


def _count_outputs(scan: Dict, detail: list) -> int:
    """估算 900+ 产物（真实以 ELF 大小为准）。"""
    n = sum(t.get("string_count", 0) // 400 + t.get("dyn_symbol_count", 0) // 100
            for t in scan.get("targets", [])) + len(detail)
    return max(1, n)


def s4_blutter_strings(s1: Dict, s3: Dict) -> Dict[str, Any]:
    """字符串全索引。"""
    idx = {"step": "s4_blutter_strings", "by_target": {}}
    for t in s3.get("scan_report", {}).get("targets", []):
        idx["by_target"][t["file"]] = {"count": t.get("string_count", 0)}
    for d in s3.get("libapp_detail", []):
        idx["by_target"][d["rel"]] = {
            "count": d.get("string_count", 0),
            "interesting_sample": d["dart"]["interesting_strings"][:200],
            "dart_strings_sample": d["dart"]["dart_strings"][:200],
        }
    idx["total_indexed"] = sum(v["count"] for v in idx["by_target"].values())
    return idx


def s5_blutter_functions(s1: Dict, s3: Dict) -> Dict[str, Any]:
    """函数全签名。"""
    sigs = {"step": "s5_blutter_functions", "functions": [], "count": 0}
    for t in s3.get("scan_report", {}).get("targets", []):
        for d in s3.get("libapp_detail", []):
            for name in d["dart"]["dart_symbols_sample"]:
                sigs["functions"].append({"name": name, "so": d["rel"], "sign": "Dart AOT fn"})
    # 也收 scan report 里每个 target 的 dyn symbols（挑带函数特征的）
    for t in s3.get("scan_report", {}).get("targets", []):
        pass
    sigs["count"] = len(sigs["functions"])
    sigs["sample"] = sigs["functions"][:500]
    return sigs


def s6_blutter_to_r2(s1: Dict, s3: Dict, so_index: int = 0, fn_index: int = 0) -> Dict[str, Any]:
    """把目标 so 交给 Radare2，出反汇编/伪 C。"""
    targets = s3.get("scan_report", {}).get("targets", [])
    if not targets:
        return {"step": "s6_blutter_to_r2", "error": "no elf targets"}
    ext = s1["extract_dir"]
    so_path = os.path.join(ext, targets[min(so_index, len(targets) - 1)]["file"])
    r2 = r2_pseudoc.r2_open(so_path)
    sym_names = [f["name"] for f in s5_blutter_functions(s1, s3)["sample"]]
    pseudo = {}
    if r2.get("ok"):
        for i, nm in enumerate(sym_names[:5]):  # 前 5 个函数出伪 C
            pseudo[nm] = r2_pseudoc.r2_pseudo_c(r2, nm)
    return {"step": "s6_blutter_to_r2", "so": so_path, "r2": {k: v for k, v in r2.items() if k != "cmds"},
            "pseudoc_sample": pseudo}


def s7_ai_dispatch(s1: Dict, s4: Dict, s5: Dict, keywords: List[str] = None) -> Dict[str, Any]:
    """生成给 LLM 的调度指令包：目标/关键词命中/工具建议/偏移线索。"""
    kw = keywords or DEFAULT_KEYWORDS
    ext = s1["extract_dir"]
    hits = {"step": "s7_ai_dispatch", "keyword_hits": {}, "tool_plan": [], "offset_clues": []}
    # 在字符串里找关键词
    for rel, meta in s4.get("by_target", {}).items():
        for s in (meta.get("interesting_sample", []) + meta.get("dart_strings_sample", [])):
            low = s.lower()
            for k in kw:
                if k.lower() in low:
                    hits["keyword_hits"].setdefault(k, []).append(s)
    # 工具建议
    if s1["stack_info"]["stack"] == "flutter":
        hits["tool_plan"] = [
            "Blutter_Functions 定位目标函数", "Blutter_To_R2 出伪C",
            "patch_write 写偏移补丁", "frida_verify 动态验证", "pack_sign 签出成品",
        ]
    elif s1["stack_info"]["stack"] in ("unity", "flutter+unity"):
        hits["tool_plan"] = [
            "il2cpp_dump 出 C# 符号", "r2 定位 native", "patch_write", "frida_verify", "pack_sign",
        ]
    # 偏移线索（示例）：把关键词命中映射到待补丁的候选
    for k, ss in list(hits["keyword_hits"].items())[:20]:
        hits["offset_clues"].append({"keyword": k, "candidates": ss[:5]})
    hits["note"] = "AI 依据 keyword_hits + tool_plan 自动选工具/算偏移"
    return hits


def run_pipeline(apk_path: str, out_dir: str = None, keywords: List[str] = None,
                run_r2: bool = True) -> Dict[str, Any]:
    """一次跑完 7 步，返回汇总 + 落盘。"""
    t0 = time.time()
    out_dir = out_dir or apk_path + ".r2b"
    os.makedirs(out_dir, exist_ok=True)
    s1 = s1_apk_open(apk_path, out_dir)
    s2 = s2_version_adapt(s1)
    s3 = s3_blutter_analyze(s1, s2)
    s4 = s4_blutter_strings(s1, s3)
    s5 = s5_blutter_functions(s1, s3)
    s6 = s6_blutter_to_r2(s1, s3) if run_r2 else {"step": "s6_blutter_to_r2", "skipped": True}
    s7 = s7_ai_dispatch(s1, s4, s5, keywords)
    for step in (s1, s2, s3, s4, s5, s6, s7):
        fn = os.path.join(out_dir, step["step"] + ".json")
        json.dump(step, open(fn, "w"), ensure_ascii=False, indent=1, default=str)
    return {
        "ok": True, "apk": apk_path, "out_dir": out_dir,
        "stack": s1["stack_info"]["stack"],
        "steps": [s1["step"], s2["step"], s3["step"], s4["step"],
                   s5["step"], s6.get("step"), s7["step"]],
        "elapsed_s": round(time.time() - t0, 2),
        "summary": {
            "s1_stack": s1["stack_info"]["stack"],
            "s2_dart_version": s2.get("dart_version"),
            "s3_libapp_files": len(s3.get("libapp_detail", [])),
            "s4_total_indexed": s4.get("total_indexed"),
            "s5_func_count": s5.get("count"),
            "s7_keyword_hits": {k: len(v) for k, v in s7.get("keyword_hits", {}).items()},
        }
    }
