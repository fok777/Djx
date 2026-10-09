"""
engine/apk.py — APK 解包 + 技术栈识别

真实可用：用 unzip 解包，扫描文件系统特征判断 Flutter / Unity / 原生，
并定位关键产物（libapp.so、libflutter.so、libil2cpp.so、global-metadata.dat）。
"""
import os, re, json, shutil, zipfile
from typing import Dict, Any

# 技术栈特征
FLUTTER_MARKERS = [
    "libflutter.so",          # Flutter 引擎
    "libapp.so",             # Dart AOT 编译产物（关键逆向目标）
    "assets/flutter_assets",  # Flutter 资源目录
    "flutter_assets",
]
UNITY_MARKERS = [
    "libil2cpp.so",          # IL2CPP 编译产物
    "libmono.so",            # Mono
    "global-metadata.dat",    # IL2CPP metadata（藏着 C# 类型/方法）
    "libunity.so",
]
NATIVE_MARKERS = [
    "libapp.so",  # 也可能是纯 native（非 Flutter），需结合 flutter 标记判断
]


def extract_apk(apk_path: str, out_dir: str = None) -> Dict[str, Any]:
    """解压 APK（zip）。返回解包目录和文件清单。"""
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(apk_path)
    out_dir = out_dir or (apk_path + ".extracted")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(apk_path, "r") as z:
        # 安全解包，防 zip-slip
        for info in z.infolist():
            target = os.path.realpath(os.path.join(out_dir, info.filename))
            if not target.startswith(os.path.realpath(out_dir)):
                continue
            z.extract(info, out_dir)
    # 文件清单（相对路径）
    listing = []
    for root, _, files in os.walk(out_dir):
        for f in files:
            p = os.path.join(root, f)
            listing.append(os.path.relpath(p, out_dir))
    return {"apk": os.path.abspath(apk_path), "extract_dir": out_dir,
            "file_count": len(listing), "listing": listing}


def _has(extract_dir: str, rel: str) -> bool:
    return os.path.exists(os.path.join(extract_dir, rel))


def _glob_marker(extract_dir: str, pattern: str) -> list:
    import glob
    return sorted(glob.glob(os.path.join(extract_dir, "**", pattern), recursive=True))


def detect_stack(extract_dir: str) -> Dict[str, Any]:
    """识别技术栈，返回结构化结果。"""
    result: Dict[str, Any] = {
        "stack": "native", "markers": [], "targets": {}, "notes": []
    }
    # 各 marker 是否命中
    flutter_hits = _glob_marker(extract_dir, "libflutter.so") + \
                   _glob_marker(extract_dir, "libapp.so")
    unity_hits = _glob_marker(extract_dir, "libil2cpp.so") + \
                 _glob_marker(extract_dir, "global-metadata.dat")
    metadata_hits = _glob_marker(extract_dir, "global-metadata.dat")

    is_flutter = "libflutter.so" in " ".join(flutter_hits) or \
                 bool(_glob_marker(extract_dir, "flutter_assets")) or \
                 bool(_glob_marker(extract_dir, "libflutter.so"))
    is_unity = "libil2cpp.so" in " ".join(unity_hits) or bool(metadata_hits)

    if is_flutter:
        result["stack"] = "flutter"
        result["markers"] = [os.path.relpath(x, extract_dir) for x in flutter_hits][:10]
        # Dart 版本线索（从 libapp.so 元数据 / flutter 资源里找）
        result["targets"]["libapp_so"] = _glob_marker(extract_dir, "libapp.so")
        result["targets"]["libflutter_so"] = _glob_marker(extract_dir, "libflutter.so")
        result["targets"]["flutter_assets"] = _glob_marker(extract_dir, "flutter_assets")
        result["notes"].append("检测到 Flutter：以 libapp.so(Dart AOT) 为逆向目标")
    if is_unity:
        result["stack"] = "unity" if result["stack"] == "native" else (
            "flutter+unity" if is_flutter else "unity")
        result["targets"]["libil2cpp_so"] = _glob_marker(extract_dir, "libil2cpp.so")
        result["targets"]["global_metadata"] = metadata_hits
        result["notes"].append("检测到 Unity/IL2CPP：用 global-metadata.dat 还原 C# 符号")
    if result["stack"] == "native":
        # 纯 native：列所有 .so
        result["targets"]["native_libs"] = _glob_marker(extract_dir, "lib/**/*.so") or \
            _glob_marker(extract_dir, "lib/*.so")
        result["notes"].append("未识别 Flutter/Unity，按原生 .so 处理")
    return result


def parse_manifest(extract_dir: str) -> Dict[str, Any]:
    """尽力从 AndroidManifest 提取包名/版本（binary xml，用字符串提取兜底）。"""
    manifest = os.path.join(extract_dir, "AndroidManifest.xml")
    info: Dict[str, Any] = {}
    if os.path.exists(manifest):
        raw = open(manifest, "rb").read()
        # binary xml 里包名常以 utf-16 存，尽力抓
        m = re.search(rb"com\.[\x00\w.\-]+", raw)
        if m:
            info["package_hint"] = m.group(0).decode("utf-8", "ignore").strip("\x00")
        m = re.search(rb"(\d+\.\d+(?:\.\d+)+)", raw)
        if m:
            info["version_hint"] = m.group(1).decode()
    # 从目录名/文件名兜底（很多分析目录会带包名）
    return info


def apk_open(apk_path: str, out_dir: str = None) -> Dict[str, Any]:
    """Apk_Open 一步：解包 + 识别 + manifest，返回完整上下文。"""
    ctx = extract_apk(apk_path, out_dir)
    ctx["stack_info"] = detect_stack(ctx["extract_dir"])
    ctx["manifest"] = parse_manifest(ctx["extract_dir"])
    return ctx
