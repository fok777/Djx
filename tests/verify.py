"""验证引擎真实可用：对 test.apk 跑 Blutter 7步 + IL2CPP + 六步闭环。"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import blutter, il2cpp, pipeline, apk, elf

APK = "/var/minis/workspace/flutter_mcp/test.apk"

print("=" * 60)
print("STEP 1-7 · Blutter 秒解析 pipeline")
print("=" * 60)
p = blutter.run_pipeline(APK, "/var/minis/workspace/flutter_mcp/r2b/out_test", run_r2=True)
print("stack =", p["summary"]["s1_stack"])
print("dart_version =", p["summary"]["s2_dart_version"])
print("libapp_files =", p["summary"]["s3_libapp_files"])
print("s4_total_indexed =", p["summary"]["s4_total_indexed"])
print("s5_func_count =", p["summary"]["s5_func_count"])
print("s7_keyword_hits =", p["summary"]["s7_keyword_hits"])

print("\n" + "=" * 60)
print("PART2 · IL2CPP 3件套")
print("=" * 60)
ext = apk.apk_open(APK)
il = il2cpp.il2cpp_dump(ext["extract_dir"], "/var/minis/workspace/flutter_mcp/r2b/out_test/il2cpp")
print("unity_version =", il.get("unity_version"))
print("type_count =", il.get("type_count"), "method_count =", il.get("method_count"),
      "string_count =", il.get("string_count"))
print("methods_sample =", il.get("methods")[:6])
print("files =", il.get("files"))

print("\n" + "=" * 60)
print("PART4 · 六步全闭环 full_loop")
print("=" * 60)
fl = pipeline.run_full_loop(APK, "/var/minis/workspace/flutter_mcp/r2b/out_test/loop",
                           keywords=["vip", "member", "loadAd", "premium"],
                           patch_op="bypass_check")
for k, v in fl["steps"].items():
    print(f"  {k}: {json.dumps(v, ensure_ascii=False)[:160]}")
print("elapsed_s =", fl["elapsed_s"])
print("\n全部 OK ✅" if all([p["ok"], il.get("files"), fl["ok"]]) else "存在未通过项 ❌")
