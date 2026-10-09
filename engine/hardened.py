"""
engine/hardened.py — 壳/加固检测（是否需要脱壳才能逆向）

识别常见加固厂商（360/腾讯乐固/爱加密/梆梆/顶像/几维/娜迦），
给出去壳建议。dex 极小 + lib 里有壳厂商 so 是典型壳特征。
"""
import os, glob
from typing import Dict, Any

# 壳厂商特征（lib so 名 / assets 文件 / dex 特征）
VENDOR_SIGNATURES = [
    ("libjiagu.so", "360加固", "lib"),
    ("libshella.so", "360", "lib"),
    ("libtpr*.so", "腾讯乐固", "lib"),
    ("libttNetLib / com.tencent.st", "腾讯", "assets"),
    ("libsec*.so", "爱加密", "lib"),
    ("libbangbang.so / libbb.so", "梆梆", "lib"),
    ("libtopax*.so", "顶像", "lib"),
    ("libjiangriguo*.so", "几维(强固)", "lib"),
    ("libnaga*.so", "娜迦", "lib"),
    ("libdexvmp*.so", "DEX虚拟机保护", "lib"),
    ("libvmp*.so", "VMP", "lib"),
    ("libshell*.so", "通用壳", "lib"),
]


def detect_hardened(extract_dir: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"hardened": False, "vendors": [], "evidence": [],
                            "dex_sizes": [], "needs_unpack": False, "tips": []}
    # 1) dex 大小（壳常把真 dex 藏 native，classes.dex 极小 < 100K）
    dex_files = glob.glob(os.path.join(extract_dir, "*.dex"))
    for d in dex_files:
        out["dex_sizes"].append({"file": os.path.basename(d), "bytes": os.path.getsize(d)})
    small_dex = [d for d in out["dex_sizes"] if d["bytes"] < 100 * 1024]
    # 2) lib 目录里的壳 so
    libs = glob.glob(os.path.join(extract_dir, "lib", "**", "*.so"), recursive=True)
    lib_names = " ".join(os.path.basename(l) for l in libs).lower()
    for so_sig, vendor, _ in VENDOR_SIGNATURES:
        key = so_sig.split(".so")[0].split("/")[0].lower().replace("lib", "lib")
        if key in lib_names:
            out["vendors"].append(vendor)
            out["evidence"].append(f"lib 命中 {so_sig}")
    # 3) assets 里的壳特征
    assets = glob.glob(os.path.join(extract_dir, "assets", "**"), recursive=True)
    asset_names = " ".join(os.path.basename(a) for a in assets).lower()
    for marker, vendor in (("com.tencent.st", "腾讯"), ("tencent_secure", "腾讯"),
                            (".360", "360"), ("sec", "爱加密")):
        if marker in asset_names:
            if vendor not in out["vendors"]:
                out["vendors"].append(vendor)
                out["evidence"].append(f"assets 命中 {marker}")

    # 判定
    out["hardened"] = bool(out["vendors"] or (small_dex and len(small_dex) == len(dex_files) and dex_files))
    out["needs_unpack"] = out["hardened"]
    if out["hardened"]:
        out["tips"] = [
            f"检测到加固: {', '.join(out['vendors']) if out['vendors'] else '未知壳'}",
            "需脱壳：运行时 dump dex（frida-art/dexdump/黑产手法）或 Frida hook 类加载器 dump",
            "本工具后续步骤先对 native so 做符号分析，dex 脱壳后再接 DEX 逆向",
        ]
    elif dex_files:
        out["tips"].append(f"未见明显壳，{len(dex_files)} 个 dex 直接可逆向（dex.py）")
    return out
