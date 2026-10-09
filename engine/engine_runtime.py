"""engine/engine_runtime.py — 内置引擎资产定位（自包含路线）。
App 启动把 assets/engine/ 解压到 filesDir/engine 后，引擎工具优先从内置目录加载
radare2 / frida-server / frida-gadget / blutter / unidbg，缺失才回落系统 PATH。

radare2 / frida-server / frida-gadget / blutter / unidbg 全部是开源项目，
公开可获取。放进去后本模块负责定位 + 版本匹配，缺失才回落系统 PATH。"""
import os, glob, shutil
from typing import Dict, Any, Optional


def engine_root(env: str = "") -> Optional[str]:
    cand = []
    if env and os.path.isdir(env):
        cand.append(env)
    cand.append(os.environ.get("R2B_ENGINE_ROOT", ""))
    cand.append("/var/minis/workspace/flutter_mcp/r2b/assets/engine")
    for c in cand:
        if c and os.path.isdir(c):
            return c
    return None


def _first(pattern: str) -> Optional[str]:
    root = engine_root()
    if not root:
        return None
    hits = glob.glob(os.path.join(root, pattern))
    return hits[0] if hits else None


def locate_radare2() -> Optional[str]:
    """radare2 可执行文件。找不到就返回 None，由 r2_engine 退到 ctypes。"""
    for pat in ("radare2/r2", "radare2/radare2", "radare2/bin/r2",
                "radare2/r2*", "radare2/radare2*"):
        for h in sorted(glob.glob(os.path.join(engine_root() or "", pat))):
            if os.path.isfile(h) and os.access(h, os.X_OK):
                try:
                    with open(h, "rb") as fh:
                        if fh.read(4) == b"\x7fELF":
                            return h
                except OSError:
                    pass
    return shutil.which("r2") or shutil.which("radare2")


def locate_r2_bridge() -> Optional[str]:
    """JNI 桥 libr2aibridge.so。注意：它只导出
    Java_com_r2aibridge_R2Core_{initR2Core,openFile,executeCommand,closeR2Core,testR2}，
    DT_NEEDED 依赖 libr_core.so —— **不含 radare2 本体**，
    必须配套放 libr_core.so / libr_anal.so 等才能加载。
    Android App 走 JNI 调它；Python 端走 libr_core.so 直调。"""
    for pat in ("radare2/libr2aibridge.so", "radare2/*bridge*.so", "*/libr2aibridge.so"):
        p = _first(pat)
        if p:
            return p
    return None


def locate_frida_server() -> Optional[str]:
    return _first("frida/frida-server*") or shutil.which("frida-server")


def locate_frida_gadget() -> Optional[str]:
    """gadget so（注入到目标 App 的 .so 形式 Frida）。"""
    return (_first("frida/gadget*.so") or _first("frida/libfrida-gadget*.so")
            or _first("frida/*.so"))


def locate_blutter(dart_ver: str = "") -> Optional[str]:
    """定位 Blutter 引擎。有**两种形态**，都要支持：

    形态 A（Android 打包常见）：libblutter_<版本>.so
        名字叫 .so 但其实是**带 .interp 的 PIE 可执行文件**（内含 main，
        linker64 为解释器）—— 这样命名是为了塞进 APK 的 lib/<abi>/ 目录。
        直接执行即可：`./libblutter_3_12_1.so -i libapp.so -o outdir`
        （实测确认：ELF type=ET_DYN，有 .interp=/system/bin/linker64，
          有 main 符号。是 arm64，x86 机器上 dlopen 不了。）

    形态 B（官方仓库）：blutter/blutter.py + bin/blutter_dartvm{ver}_{os}_{arch}
        python3 blutter.py <lib/arm64-v8a目录> <outdir>

    按版本精确匹配优先，匹配不到退到通用名/入口脚本。
    """
    root = engine_root()
    if not root:
        return None

    def _pick(patterns, skip_ext=(".py", ".txt", ".md", ".json", ".js")):
        for pat in patterns:
            for h in sorted(glob.glob(os.path.join(root, pat))):
                if not os.path.isfile(h) or h.endswith(skip_ext):
                    continue
                try:
                    with open(h, "rb") as fh:
                        if fh.read(4) != b"\x7fELF":
                            continue        # 只认 ELF（可执行文件/共享库）
                except OSError:
                    continue
                return h
        return None

    if dart_ver:
        norm = (dart_ver.replace(".", "_").replace(" ", "").replace("-", "_"))
        # 形态 A：libblutter_3_12_1.so（版本号也吃 "3.12.1" 与 "3_12_1" 两种写法）
        p = _pick([f"blutter/libblutter_{norm}.so",
                   f"blutter/libblutter_{norm}*.so",
                   f"blutter/*{norm}*.so"])
        if p:
            return p
        # 形态 B：bin/blutter_dartvm3.4.2_android_arm64
        p = _pick([f"blutter/bin/blutter_dartvm{norm}*",
                   f"blutter/blutter_dartvm{norm}*",
                   f"blutter/*{norm}*"])
        if p:
            return p

    # 无版本或版本未命中：通用名
    # 注意 libblutter.so(3.0MB) 与 libblutter_3_10.so 同尺寸，是老兜底版；
    # 优先挑体积最大的（通常是最新/最全的），避免拿到过小的旧引擎
    cands = []
    for pat in ("blutter/libblutter.so", "blutter/*.so"):
        for h in glob.glob(os.path.join(root, pat)):
            if os.path.isfile(h):
                try:
                    with open(h, "rb") as fh:
                        if fh.read(4) != b"\x7fELF":
                            continue
                except OSError:
                    continue
                cands.append(h)
    if cands:
        return max(cands, key=lambda x: os.path.getsize(x))
    p = _pick(["blutter/bin/blutter*", "blutter/blutter_dartvm*", "blutter/blutter"])
    if p:
        return p
    # 官方入口脚本（会自动按版本编译）
    for pat in ("blutter/blutter.py", "blutter.py", "*/blutter.py"):
        q = _first(pat)
        if q:
            return q
    return None


def locate_blutter_dir() -> Optional[str]:
    """Blutter 项目根目录（含 blutter.py 的那层），subprocess 模式需要它做 cwd。"""
    root = engine_root()
    if not root:
        return None
    p = _first("blutter/blutter.py")
    if p:
        return os.path.dirname(p)
    exe = locate_blutter()
    if exe and os.path.basename(exe) == "blutter":
        return os.path.dirname(os.path.dirname(exe))  # bin/ 的上一层
    return None


def locate_unidbg() -> Optional[str]:
    return _first("unidbg/unidbg.jar") or _first("unidbg/*.jar")


def status() -> Dict[str, Any]:
    """内置引擎资产自检：每项是否已内置(在 engine_root 内) / 缺失需放入。"""
    root = engine_root()
    items = {
        "radare2": locate_radare2(),
        "frida_server": locate_frida_server(),
        "frida_gadget": locate_frida_gadget(),
        "blutter": locate_blutter(),
        "unidbg": locate_unidbg(),
    }
    rep: Dict[str, Any] = {"engine_root": root, "items": {}}
    for k, p in items.items():
        rep["items"][k] = {
            "path": p,
            "builtin": bool(p and root and str(p).startswith(str(root))),
            "absent": p is None,
        }
    builtin = [k for k, v in rep["items"].items() if v["builtin"]]
    missing = [k for k, v in rep["items"].items() if v["absent"]]
    rep["builtin_items"] = builtin
    rep["missing"] = missing
    rep["note"] = ("已内置: " + (",".join(builtin) or "无")
                   + "；缺失需放入 assets/engine/: " + (",".join(missing) or "无"))
    return rep
