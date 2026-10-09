"""
engine/apk_extra.py — Apk_* 补齐的 1 个工具：Apk_Diff

对比两个 APK 的差异：文件增删、大小变化、so / dex / manifest 变化。
用于确认补丁是否生效、或定位两个版本间的改动。
"""
import os
import zipfile
import hashlib
from typing import Dict, Any


def _index(path: str) -> Dict[str, Dict]:
    """读 APK（zip）内条目：名字 -> {size, crc, sha1}。"""
    out: Dict[str, Dict] = {}
    try:
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.is_dir():
                    continue
                try:
                    h = hashlib.sha1(z.read(i.filename)).hexdigest()[:16]
                except Exception:
                    h = None
                out[i.filename] = {"size": i.file_size,
                                   "compress_size": i.compress_size,
                                   "sha1_16": h}
    except (zipfile.BadZipFile, OSError) as e:
        raise ValueError(f"无法读取 {path}: {e}")
    return out


def _buckets(names):
    """把条目按类型分桶，便于按 so / dex / 资源 分别看变化。"""
    b = {"so": [], "dex": [], "manifest": [], "resources": [], "assets": [], "other": []}
    for n in names:
        if n.startswith("lib/"):
            b["so"].append(n)
        elif n.endswith(".dex"):
            b["dex"].append(n)
        elif n.endswith("AndroidManifest.xml"):
            b["manifest"].append(n)
        elif n.startswith("res/"):
            b["resources"].append(n)
        elif n.startswith("assets/"):
            b["assets"].append(n)
        else:
            b["other"].append(n)
    return b


def apk_diff(a: str, b: str, show_unchanged: bool = False) -> Dict[str, Any]:
    """对比两个 APK。a 视为原版，b 视为改后版。"""
    for p in (a, b):
        if not os.path.isfile(p):
            return {"error": f"file not found: {p}"}
    try:
        ia, ib = _index(a), _index(b)
    except ValueError as e:
        return {"error": str(e)}

    na, nb = set(ia), set(ib)
    added = sorted(nb - na)
    removed = sorted(na - nb)
    common = sorted(na & nb)
    changed = [n for n in common
               if ia[n].get("sha1_16") and ib[n].get("sha1_16")
               and ia[n]["sha1_16"] != ib[n]["sha1_16"]]
    same = [n for n in common if n not in set(changed)]

    def delta(n):
        return {"name": n,
                "old_size": ia[n]["size"], "new_size": ib[n]["size"],
                "delta": ib[n]["size"] - ia[n]["size"]}

    ba, bb = _buckets(added), _buckets(removed)
    bc = _buckets(changed)

    out = {
        "a": a, "b": b,
        "a_entries": len(ia), "b_entries": len(ib),
        "summary": {"added": len(added), "removed": len(removed),
                    "changed": len(changed), "unchanged": len(same)},
        "added": added[:200], "removed": removed[:200],
        "changed": [delta(n) for n in changed[:200]],
        "by_type": {
            "so": {"added": ba["so"], "removed": bb["so"], "changed": bc["so"]},
            "dex": {"added": ba["dex"], "removed": bb["dex"], "changed": bc["dex"]},
            "manifest": {"added": ba["manifest"], "removed": bb["manifest"],
                         "changed": bc["manifest"]},
            "resources": {"added": ba["resources"], "removed": bb["resources"],
                          "changed": bc["resources"]},
            "assets": {"added": ba["assets"], "removed": bb["assets"],
                       "changed": bc["assets"]},
            "other": {"added": ba["other"], "removed": bb["other"],
                      "changed": bc["other"]},
        },
    }
    if show_unchanged:
        out["unchanged"] = same[:200]
    # 签名变化提示
    sig_a = [n for n in na if n.startswith("META-INF/")]
    sig_b = [n for n in nb if n.startswith("META-INF/")]
    out["signature"] = {
        "a_files": sig_a[:10], "b_files": sig_b[:10],
        "note": ("META-INF 有变化说明已重新签名"
                 if set(sig_a) != set(sig_b) else "META-INF 未变，可能未重签名"),
    }
    return out
