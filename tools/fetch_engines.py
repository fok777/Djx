#!/usr/bin/env python3
"""
tools/fetch_engines.py — 从官方源补齐/更新引擎资产

从官方源补齐或更新引擎资产。能直接下二进制的就下，
需要编译的（仅 blutter 遇到比现有版本更新的 Dart 时）给出准确命令。

    python3 tools/fetch_engines.py radare2          # 下官方 Android arm64 预编译
    python3 tools/fetch_engines.py frida --ver 17.5.1
    python3 tools/fetch_engines.py unidbg
    python3 tools/fetch_engines.py blutter          # 只能 clone，给出编译步骤
    python3 tools/fetch_engines.py all
    python3 tools/fetch_engines.py status           # 看缺什么

诚实边界：
- radare2 / frida / unidbg 有官方预编译 release，可直接下载。
- blutter **没有 release**，只能 git clone 后按 Dart 版本编译，
  需要 g++>=13 或 clang>=16 + cmake/ninja/libicu/libcapstone，
  首次编译会 checkout Dart 源码，耗时 5~30 分钟。脚本只负责 clone + 提示。
- 下载需要能访问 github.com；沙盒里受限，请在本机跑。
"""
import os
import sys
import json
import shutil
import tarfile
import zipfile
import subprocess
import urllib.request
from typing import Dict, Any, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "assets", "engine")

UA = {"User-Agent": "r2b-fetch/1.0"}
TIMEOUT = 60

# 已知可用的版本（写死兜底，避免依赖 GitHub API 限流）
KNOWN = {
    "radare2": {"ver": "6.2.2"},
    "unidbg": {"ver": "0.9.8"},
}


def dest(sub: str) -> str:
    p = os.path.join(ENGINE, sub)
    os.makedirs(p, exist_ok=True)
    return p


def _get(url: str, out: str) -> bool:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r, open(out, "wb") as f:
            shutil.copyfileobj(r, f)
        return os.path.getsize(out) > 1024
    except Exception as e:
        print(f"    下载失败: {type(e).__name__}: {e}")
        return False


def _api_latest(repo: str) -> Optional[str]:
    """查 GitHub latest release tag；被限流就返回 None。"""
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases/latest", headers=UA)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r).get("tag_name", "").lstrip("v")
    except Exception:
        return None


def _dl(url: str, out: str, label: str) -> bool:
    print(f"  ↓ {label}")
    print(f"    {url}")
    if not _get(url, out):
        return False
    print(f"    ✓ {os.path.getsize(out)/1048576:.1f} MB")
    return True


# ---------------- radare2 ----------------

def fetch_radare2(ver: str = "") -> Dict[str, Any]:
    """官方有 Android 预编译包，含 libr_core.so 等全部 libr_*。"""
    ver = ver or _api_latest("radareorg/radare2") or KNOWN["radare2"]["ver"]
    ver = ver.lstrip("v")
    name = f"radare2-{ver}-android-aarch64.tar.gz"
    url = f"https://github.com/radareorg/radare2/releases/download/{ver}/{name}"
    tmp = os.path.join("/tmp", name)
    out = dest("radare2")
    if not _dl(url, tmp, f"radare2 {ver} android-aarch64"):
        return {"ok": False, "engine": "radare2",
                "hint": "网络不通或版本不存在；手工下载后解压到 "
                        f"{out}。也可用 sys/android-build.sh 配 NDK 自编译。"}
    n = 0
    try:
        with tarfile.open(tmp) as t:
            for m in t.getmembers():
                if not m.isfile():
                    continue
                base = os.path.basename(m.name)
                # 只要 libr_*.so 和 r2 可执行文件，跳过无关
                if not (base.startswith("libr_") or base in ("r2", "radare2",
                                                             "rabin2", "rasm2")):
                    continue
                src = t.extractfile(m)
                if not src:
                    continue
                with open(os.path.join(out, base), "wb") as f:
                    shutil.copyfileobj(src, f)
                n += 1
    except Exception as e:
        return {"ok": False, "engine": "radare2", "error": f"{type(e).__name__}: {e}"}
    return {"ok": n > 0, "engine": "radare2", "files": n, "dir": out,
            "version": ver, "note": "含 libr_core.so 后可 ctypes 直调"}


# ---------------- unidbg ----------------

def fetch_unidbg(ver: str = "") -> Dict[str, Any]:
    ver = ver or KNOWN["unidbg"]["ver"]
    url = f"https://github.com/zhkl0228/unidbg/releases/download/v{ver}/unidbg-{ver}.zip"
    tmp = f"/tmp/unidbg-{ver}.zip"
    out = dest("unidbg")
    if not _dl(url, tmp, f"unidbg {ver}"):
        return {"ok": False, "engine": "unidbg",
                "hint": f"手工下载 https://github.com/zhkl0228/unidbg/releases "
                        f"后把 unidbg-android.jar / unidbg-unicorn2.jar 放进 {out}"}
    n = 0
    try:
        with zipfile.ZipFile(tmp) as z:
            for i in z.infolist():
                if i.is_dir() or not i.filename.endswith(".jar"):
                    continue
                base = os.path.basename(i.filename)
                if not base.startswith("unidbg-"):
                    continue
                with z.open(i) as s, open(os.path.join(out, base), "wb") as d:
                    shutil.copyfileobj(s, d)
                n += 1
    except Exception as e:
        return {"ok": False, "engine": "unidbg", "error": str(e)}
    return {"ok": n > 0, "engine": "unidbg", "files": n, "dir": out, "version": ver}


# ---------------- frida ----------------

def fetch_frida(ver: str = "", abi: str = "arm64") -> Dict[str, Any]:
    """frida-server 与 gadget 都有官方预编译。"""
    if not ver:
        ver = _api_latest("frida/frida") or ""
    if not ver:
        return {"ok": False, "engine": "frida",
                "hint": "需指定版本：--ver 17.5.1（见 "
                        "https://github.com/frida/frida/releases）"}
    ver = ver.lstrip("v")
    out = dest("frida")
    base = f"https://github.com/frida/frida/releases/download/{ver}"
    got = []
    # frida-server: frida-server-{ver}-android-{abi}.xz
    srv = f"frida-server-{ver}-android-{abi}.xz"
    if _dl(f"{base}/{srv}", f"/tmp/{srv}", f"frida-server {ver} {abi}"):
        try:
            subprocess.run(["xz", "-dkf", f"/tmp/{srv}"], check=True, timeout=300)
            raw = f"/tmp/{srv}".replace(".xz", "")
            shutil.move(raw, os.path.join(out, "frida-server"))
            os.chmod(os.path.join(out, "frida-server"), 0o755)
            got.append("frida-server")
        except Exception as e:
            print(f"    解压失败(需 xz): {e}")
    # gadget: frida-gadget-{ver}-android-{abi}.so.xz
    gad = f"frida-gadget-{ver}-android-{abi}.so.xz"
    if _dl(f"{base}/{gad}", f"/tmp/{gad}", f"frida-gadget {ver} {abi}"):
        try:
            subprocess.run(["xz", "-dkf", f"/tmp/{gad}"], check=True, timeout=300)
            raw = f"/tmp/{gad}".replace(".xz", "")
            shutil.move(raw, os.path.join(out, "frida-gadget.so"))
            got.append("frida-gadget.so")
        except Exception as e:
            print(f"    解压失败(需 xz): {e}")
    return {"ok": bool(got), "engine": "frida", "files": got, "dir": out,
            "version": ver}


# ---------------- blutter ----------------

def _blutter_reuse_map(repo_dir: str) -> List[str]:
    """把手上的 libblutter_<ver>.so 映射成官方命名，放进官方仓库的 bin/。

    官方 blutter.py 的 build_and_run() 会先在 bin/ 找
    `blutter_dartvm{ver}_{os}_{arch}` 命名的可执行文件，**找到就跳过编译**
    （README 原话：如果文件存在则跳过构建步骤）。所以把你手上那 23 个
    别人编译好的 .so 按官方命名放进去，官方脚本会直接复用，不用编译。
    """
    import glob
    made = []
    src_dir = os.path.join(os.path.dirname(repo_dir), "")
    bin_dir = os.path.join(repo_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    for so in sorted(glob.glob(os.path.join(src_dir, "libblutter_*.so"))):
        base = os.path.basename(so)
        ver = base[len("libblutter_"):-len(".so")]
        if not ver or ver in ("so",):
            continue
        # libblutter_3_12_1.so -> blutter_dartvm3_12_1_android_arm64
        target = os.path.join(bin_dir, f"blutter_dartvm{ver}_android_arm64")
        if os.path.exists(target):
            continue
        try:
            os.symlink(os.path.abspath(so), target)
            made.append(os.path.basename(target))
        except OSError:
            try:
                shutil.copy2(so, target)
                os.chmod(target, 0o755)
                made.append(os.path.basename(target))
            except OSError:
                pass
    return made


def fetch_blutter(ver: str = "", force_build: bool = False) -> Dict[str, Any]:
    """Blutter：**不需要编译**，你手上 23 个 .so 就是别人编译好的成品。

    官方仓库（worawit/blutter）确实没有 GitHub Release —— 源码即分发。
    但 blutter.py 的机制是：bin/ 里有对应版本的可执行文件就**跳过编译**。
    所以把这 23 个 libblutter_<ver>.so 按官方命名链进 bin/ 即可直接复用。
    只有遇到比 3.12.1 更新的 Dart 版本，才需要真的编译。
    """
    import glob
    out = dest("blutter")
    have = sorted(os.path.basename(p) for p in glob.glob(os.path.join(out, "libblutter_*.so")))
    if have:
        vers = sorted({h[len("libblutter_"):-3] for h in have})
        r: Dict[str, Any] = {
            "ok": True, "engine": "blutter", "need_compile": False,
            "have": len(have), "versions": vers,
            "dir": out,
            "usage": f"<exe> -i libapp.so -o outdir（如 {out}/libblutter_3_12_1.so）",
            "note": "已有编译好的成品，直接用即可，不必编译",
        }
        if not force_build:
            return r
    if force_build:
        print("  --force-build：仍要 clone 源码自行编译")
    repo = os.path.join(out, "repo")
    if os.path.isdir(os.path.join(repo, ".git")):
        print("  已 clone，git pull")
        subprocess.run(["git", "-C", repo, "pull"], timeout=300)
    else:
        print("  git clone https://github.com/worawit/blutter")
        r2 = subprocess.run(["git", "clone", "--depth", "1",
                             "https://github.com/worawit/blutter", repo], timeout=900)
        if r2.returncode != 0:
            return {"ok": False, "engine": "blutter", "hint": "clone 失败，检查网络"}
    made = _blutter_reuse_map(repo)
    return {"ok": True, "engine": "blutter", "dir": repo,
            "reused_into_bin": made,
            "note": (f"已把 {len(made)} 个现有 .so 按官方命名链进 bin/，"
                     "官方 blutter.py 会直接复用、跳过编译") if made
                    else "clone 完成；bin/ 为空，运行时会自动编译（首次 5~30 分钟）",
            "build_only_if": "目标 Dart 版本 > 你手上最高版本时才需要编译",
            "build_steps": [
                "# 依赖（Debian sid/trixie 或 gcc>=13 的 Ubuntu）",
                "apt install python3-pyelftools python3-requests git cmake \\",
                "     ninja-build build-essential pkg-config libicu-dev libcapstone-dev",
                "",
                f"cd {repo}",
                "python3 blutter.py path/to/lib/arm64-v8a out_dir",
            ]}


# ---------------- 状态诊断 ----------------

def status() -> Dict[str, Any]:
    """列各引擎当前有什么、缺什么、去哪补。"""
    def ls(sub, pat="*"):
        import glob
        d = os.path.join(ENGINE, sub)
        if not os.path.isdir(d):
            return []
        return [os.path.basename(p) for p in glob.glob(os.path.join(d, pat))]

    rep: Dict[str, Any] = {"engine_root": ENGINE, "items": {}}

    # radare2
    r2 = ls("radare2")
    core = [f for f in r2 if f.startswith("libr_core.so")]
    librs = [f for f in r2 if f.startswith("libr_")]
    rep["items"]["radare2"] = {
        "have": len(r2), "libr_count": len(librs),
        "has_core": bool(core),
        "complete": len(librs) >= 15 and bool(core),
        "missing": [] if core else ["libr_core.so 等全部 libr_*（当前只有 bridge）"],
        "fix": "python3 tools/fetch_engines.py radare2",
    }
    # blutter
    bl = ls("blutter", "*.so")
    rep["items"]["blutter"] = {
        "have": len(bl),
        "complete": len(bl) > 0,
        "versions": sorted(bl)[:30],
        "fix": "Dart 版本对不上时：python3 tools/fetch_engines.py blutter",
    }
    # frida
    fr = ls("frida")
    rep["items"]["frida"] = {
        "have": fr, "complete": "frida-server" in fr,
        "fix": "python3 tools/fetch_engines.py frida --ver <版本>",
    }
    # unidbg
    ub = ls("unidbg", "*.jar")
    rep["items"]["unidbg"] = {
        "have": ub,
        "complete": bool([f for f in ub if "android" in f]),
        "latest_known": KNOWN["unidbg"]["ver"],
        "fix": "python3 tools/fetch_engines.py unidbg",
    }
    rep["missing_engines"] = [k for k, v in rep["items"].items()
                              if not v.get("complete")]
    return rep


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opt = {a.split("=", 1)[0].lstrip("-"): (a.split("=", 1)[1] if "=" in a else True)
           for a in sys.argv[1:] if a.startswith("--")}
    what = args[0] if args else "status"
    ver = str(opt.get("ver", "")) if opt.get("ver") is not True else ""
    abi = str(opt.get("abi", "arm64"))

    if what == "status":
        import pprint
        pprint.pprint(status())
        return
    if what == "all":
        for fn in (fetch_radare2, fetch_unidbg, fetch_blutter):
            print(f"\n=== {fn.__name__} ===")
            print(json.dumps(fn(), ensure_ascii=False, indent=1)[:600])
        return
    fn = {"radare2": fetch_radare2, "unidbg": fetch_unidbg,
          "frida": fetch_frida, "blutter": fetch_blutter}.get(what)
    if not fn:
        print(__doc__)
        return
    r = fn(ver) if what in ("radare2", "unidbg", "blutter") else fn(ver, abi)
    print(json.dumps(r, ensure_ascii=False, indent=1))
    if r.get("build_steps"):
        print("\n编译步骤：")
        for s in r["build_steps"]:
            print("  " + s)


if __name__ == "__main__":
    main()
