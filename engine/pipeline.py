"""
engine/pipeline.py — 全自动流水线（一个 APK 到成品）

  ① 技术栈识别   apk.detect_stack
  ② 秒级解析     blutter.run_pipeline / il2cpp.il2cpp_dump
  ③ 关键词定位   r2 搜串 + blutter.s7_ai_dispatch
  ④ 补丁生成     patch.plan_patches
  ⑤ 动态验证     frida_verify（生成 hook 脚本）
  ⑥ 打包输出     pack_sign（提供 patch_map 时重新打包签名）
"""
import os, json, time
from typing import Dict, Any, List, Optional
from . import apk, blutter, il2cpp, r2_pseudoc, patch, frida_verify, pack_sign, \
    dex, hardened, export_symbols, capture


def run_full_loop(apk_path: str, out_dir: str = None, keywords: List[str] = None,
                  patch_map: Dict[str, str] = None, do_sign: bool = True,
                  patch_op: str = "bypass_check") -> Dict[str, Any]:
    out_dir = out_dir or apk_path + ".r2b"
    os.makedirs(out_dir, exist_ok=True)
    kw = keywords or blutter.DEFAULT_KEYWORDS
    steps: Dict[str, Any] = {}
    t0 = time.time()

    # ① 技术栈识别
    s1 = blutter.s1_apk_open(apk_path, out_dir)
    steps["1_stack"] = {"stack": s1["stack_info"]["stack"],
                        "targets": s1["stack_info"]["targets"]}
    # ①b 壳/加固检测（是否需脱壳）
    hd = hardened.detect_hardened(s1["extract_dir"])
    steps["1b_hardened"] = {"hardened": hd["hardened"], "vendors": hd["vendors"],
                            "needs_unpack": hd["needs_unpack"], "evidence": hd["evidence"][:4]}

    # ② 秒级解析
    stack = s1["stack_info"]["stack"]
    if stack in ("flutter", "flutter+unity") and "libapp.so" in str(s1["stack_info"].get("targets", {}).get("libapp_so", [])):
        p1 = blutter.run_pipeline(apk_path, out_dir, keywords=kw, run_r2=True)
        steps["2_parse"] = {"engine": "blutter", "summary": p1.get("summary"), "stack": p1.get("stack")}
    else:
        p1 = {"summary": {}, "stack": stack}
        steps["2_parse"] = {"engine": "blutter(scan)", "summary": p1.get("summary")}
    if "unity" in stack:
        il = il2cpp.il2cpp_dump(s1["extract_dir"], out_dir + "/il2cpp")
        steps["2_il2cpp"] = {"unity_version": il.get("unity_version"),
                             "type_count": il.get("type_count"),
                             "method_count": il.get("method_count"),
                             "files": il.get("files")}

    # ②b DEX 逆向
    dx = dex.scan_apk_dex(s1["extract_dir"])
    steps["2b_dex"] = {"found": dx["found"],
                       "class_counts": [t.get("class_count", 0) for t in dx["targets"]],
                       "interesting": [t.get("interesting_classes", [])[:5] for t in dx["targets"]]}

    # ③ 关键词定位
    s7 = blutter.s7_ai_dispatch(s1, {"by_target": {}}, {"sample": []}, kw)
    r2offs = {}
    target_so = (s1["stack_info"]["targets"].get("libapp_so") or
                  s1["stack_info"]["targets"].get("libil2cpp_so") or [])
    if target_so:
        for k in kw[:6]:
            r2offs[k] = r2_pseudoc.r2_search_string(os.path.join(s1["extract_dir"], target_so[0]), k)["hits"]
    steps["3_locate"] = {"keyword_hits": {k: len(v) for k, v in s7.get("keyword_hits", {}).items()},
                         "r2_offsets_sample": {k: v[:3] for k, v in r2offs.items()}}

    # ④ 补丁生成
    pseudo = {}
    if target_so:
        pseudo = {target_so[0]: "见 s6_blutter_to_r2"}
    pp = patch.plan_patches(os.path.join(s1["extract_dir"], target_so[0]) if target_so else apk_path,
                            s7.get("keyword_hits", {}), r2offs, pseudo, op=patch_op)
    steps["4_patch"] = {"count": pp["count"], "op": pp["op"],
                        "sample": pp["patches"][:10], "note": pp["note"]}

    # ⑤ 动态验证
    fv = frida_verify.verify(target_so[0] if target_so else apk_path,
                             [k for k in kw][:8])
    cap = capture.capture_verify(
        {"domain": s1["manifest"].get("package_hint", "example.com"),
         "so": target_so[0] if target_so else ""}, os.path.join(out_dir, "capture"))
    steps["5_verify"] = {"frida_cli": fv["frida_cli"], "script": fv["script"],
                         "verified": fv["verified"], "run_hint": fv["run_hint"],
                         "capture": {"mitmproxy": cap["mitmproxy"]["addon"],
                                       "frida_net": cap["frida_net"]["script"]}}

    # ⑥ 打包输出
    if patch_map:
        pk = pack_sign.pack_output(apk_path, patch_map, do_sign=do_sign)
        steps["6_pack"] = {"final": pk.get("final"), "v1": pk.get("v1"),
                           "v2v3": pk.get("v2v3"), "signs": pk.get("signs")}
    else:
        steps["6_pack"] = {"skipped": "未提供 patch_map；确认补丁后传入替换文件即可出成品"}

    # 落盘
    json.dump({"steps": steps, "elapsed_s": round(time.time() - t0, 2),
               "apk": apk_path, "out_dir": out_dir,
               "loop": "①识别→②解析→③定位→④补丁→⑤验证→⑥打包"},
              open(os.path.join(out_dir, "full_loop.json"), "w"),
              ensure_ascii=False, indent=1, default=str)
    return {"ok": True, "apk": apk_path, "out_dir": out_dir, "steps": steps,
            "elapsed_s": round(time.time() - t0, 2)}
