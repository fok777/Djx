"""
engine/r2_ctypes.py — 没有 r2 可执行文件时，用 ctypes 直接调 libr_core.so

适用场景：手上只有 radare2 拆出来的 .so（libr_core.so / libr_anal.so / ...），
没有（或跑不了）r2 可执行文件。常见于 Android / Termux / 被打包进 App 的情形。

原理：radare2 的 r2 命令行本身只是 libr_core 的一个薄壳，核心能力全在库里：
    RCore *r_core_new(void);
    int    r_core_file_open(RCore*, const char *file, int flags, int mode);
    char  *r_core_cmd_str(RCore*, const char *cmd);   // 返回 malloc 串，需 free
    int    r_core_loadlibs(RCore*, int where, const char *path);
    void   r_core_free(RCore*);
所以直接调这些，等价于 `r2 -q -c "<cmds>" <file>`。

用法：
    from engine.r2_ctypes import available, cmd
    available()                      # {'ok': True, 'core': '.../libr_core.so'}
    cmd("/path/lib.so", "aa; aflj")  # {"ok":.., "out":.., "err":.., "rc":..}

已知形态（实测用户提供的资产）：
- `libr_core.so` 等一批 libr_*.so：radare2 本体，开源可自行编译
- `libr2aibridge.so`：JNI 桥，导出 Java_com_r2aibridge_R2Core_{initR2Core,
  openFile, executeCommand, closeR2Core, testR2}，DT_NEEDED 依赖 libr_core.so。
  即：它**不含** radare2 本体，必须配套放 libr_core.so 等才能加载。
  Android App 走 JNI 调它即可，本模块（Python/ctypes）走 libr_core.so 直调。

诚实边界：
- 子进程模式可以 timeout 后 kill；ctypes 是进程内阻塞调用，无法中断。
  超时只能"放弃等待"（线程留在后台），不能真正杀掉，见 cmd() 的实现。
- 库必须 ABI 匹配（arm64 的 .so 不能在 x86 上跑），否则 dlopen 失败。
"""
import os
import ctypes
import glob
import threading
from typing import Dict, Any, Optional, List

# 加载顺序：被依赖的在前。缺失的会自动跳过。
_DEP_ORDER = [
    "libr_util.so", "libr_socket.so", "libr_fs.so", "libr_magic.so",
    "libr_hash.so", "libr_crypto.so", "libr_cons.so", "libr_lang.so",
    "libr_reg.so", "libr_syscall.so", "libr_io.so", "libr_bp.so",
    "libr_bin.so", "libr_arch.so", "libr_asm.so", "libr_anal.so",
    "libr_parse.so", "libr_flag.so", "libr_debug.so", "libr_egg.so",
    "libr_esil.so", "libr_core.so",
]

_GLOBAL = ctypes.RTLD_GLOBAL
_load_lock = threading.Lock()
_state: Dict[str, Any] = {"dir": None, "core": None, "lib": None, "error": None,
                          "preloaded": [], "sessions": {}}


# ---------- 定位与加载 ----------

def find_lib_dir(hint: str = "") -> Optional[str]:
    """找含 libr_core.so 的目录。hint 可以是目录，也可以是某个 .so 的完整路径。"""
    cands: List[str] = []
    if hint:
        if os.path.isdir(hint):
            cands.append(hint)
        else:
            cands.append(os.path.dirname(hint))
    cands.append(os.environ.get("R2B_R2_LIBDIR", ""))
    try:
        from . import engine_runtime as ER
        root = ER.engine_root()
        if root:
            cands.append(os.path.join(root, "radare2"))
            cands.append(root)
    except Exception:
        pass
    for c in cands:
        if c and os.path.isdir(c) and glob.glob(os.path.join(c, "libr_core.so*")):
            return c
    # 系统库路径兜底
    for c in ("/usr/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu",
              "/data/data/com.termux/files/usr/lib"):
        if os.path.isdir(c) and glob.glob(os.path.join(c, "libr_core.so*")):
            return c
    return None


def _preload(d: str) -> List[str]:
    """按依赖顺序 RTLD_GLOBAL 预加载，让后加载的库能解析到前者的符号。"""
    loaded = []
    if d not in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
        os.environ["LD_LIBRARY_PATH"] = d + os.pathsep + os.environ.get("LD_LIBRARY_PATH", "")
    for name in _DEP_ORDER:
        for p in sorted(glob.glob(os.path.join(d, name + "*"))):
            if not os.path.isfile(p):
                continue
            try:
                ctypes.CDLL(p, mode=_GLOBAL)
                loaded.append(os.path.basename(p))
            except OSError:
                pass
            break
    return loaded


def _libc():
    try:
        return ctypes.CDLL("libc.so.6")
    except OSError:
        try:
            return ctypes.CDLL("libc.so")
        except OSError:
            return None


def load(dir_hint: str = "") -> Dict[str, Any]:
    """加载 libr_core.so 并绑定核心 API。结果缓存在 _state。"""
    with _load_lock:
        if _state["lib"] is not None:
            return {"ok": True, **{k: _state[k] for k in ("dir", "core")},
                    "preloaded": _state["preloaded"], "cached": True}
        d = find_lib_dir(dir_hint)
        if not d:
            return {"ok": False,
                    "error": "找不到 libr_core.so；设置 R2B_R2_LIBDIR 或放到 "
                             "<engine_root>/radare2/"}
        pre = _preload(d)
        core_path = None
        for p in sorted(glob.glob(os.path.join(d, "libr_core.so*"))):
            if os.path.isfile(p):
                core_path = p
                break
        if not core_path:
            return {"ok": False, "error": f"{d} 下没有 libr_core.so"}
        try:
            lib = ctypes.CDLL(core_path, mode=_GLOBAL)
        except OSError as e:
            return {"ok": False, "error": f"dlopen 失败: {e}", "path": core_path}

        # 绑定
        lib.r_core_new.restype = ctypes.c_void_p
        lib.r_core_new.argtypes = []
        try:
            lib.r_core_init.argtypes = [ctypes.c_void_p]
            lib.r_core_init.restype = ctypes.c_int
        except AttributeError:
            pass
        lib.r_core_free.argtypes = [ctypes.c_void_p]
        lib.r_core_free.restype = None
        lib.r_core_cmd_str.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.r_core_cmd_str.restype = ctypes.c_void_p   # 手动 string_at + free
        try:
            lib.r_core_file_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                             ctypes.c_int, ctypes.c_int]
            lib.r_core_file_open.restype = ctypes.c_int
        except AttributeError:
            pass
        try:
            lib.r_core_loadlibs.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
            lib.r_core_loadlibs.restype = ctypes.c_int
        except AttributeError:
            pass

        _state.update({"dir": d, "core": core_path, "lib": lib,
                       "preloaded": pre, "error": None})
        return {"ok": True, "dir": d, "core": core_path, "preloaded": pre}


def available(dir_hint: str = "") -> Dict[str, Any]:
    """自检：能不能用 ctypes 这条路。"""
    r = load(dir_hint)
    if not r.get("ok"):
        return {"ok": False, "reason": r.get("error")}
    # 真的 new 一个 core 验证
    c = _new_core()
    if not c:
        return {"ok": False, "reason": "r_core_new() 返回空（ABI 可能不匹配）"}
    _free_core(c)
    return {"ok": True, "core": r["core"], "dir": r["dir"],
            "preloaded": r.get("preloaded", []),
            "note": "可用；走 ctypes 直调 libr_core，无需 r2 可执行文件"}


# ---------- Core 会话 ----------

def _new_core():
    lib = _state.get("lib")
    if not lib:
        return None
    try:
        c = lib.r_core_new()
    except Exception:
        return None
    if not c:
        return None
    try:
        lib.r_core_loadlibs(c, -1, None)   # R_CORE_LOADLIBS_ALL
    except Exception:
        pass
    return c


def _free_core(c):
    lib = _state.get("lib")
    try:
        lib.r_core_free(c)
    except Exception:
        pass


def _session(so: str):
    """同一文件复用一个 RCore（避免每次都重新分析）。"""
    s = _state["sessions"]
    if so in s:
        return s[so]
    c = _new_core()
    if not c:
        return None
    lib = _state["lib"]
    ok = False
    try:
        ok = bool(lib.r_core_file_open(c, so.encode(), 0, 0))
    except Exception:
        ok = False
    if not ok:
        # 退而求其次：用命令打开文件
        try:
            lib.r_core_cmd_str(c, b"o " + so.encode())
        except Exception:
            pass
    s[so] = c
    return c


def _run(c, cmds: str) -> str:
    lib = _state["lib"]
    out = []
    for one in str(cmds).split(";"):
        one = one.strip()
        if not one:
            continue
        p = lib.r_core_cmd_str(c, one.encode())
        if not p:
            continue
        try:
            out.append(ctypes.string_at(p).decode("utf-8", "ignore"))
        finally:
            libc = _libc()
            if libc:
                try:
                    libc.free(ctypes.c_void_p(p))
                except Exception:
                    pass
    return "\n".join(out)


def cmd(so: str, cmds: str, timeout: int = 90) -> Dict[str, Any]:
    """等价于 r2 -q -c "<cmds>" <so>。返回结构与 r2_engine._r2 一致。"""
    r = load()
    if not r.get("ok"):
        return {"ok": False, "out": "", "err": r.get("error", "load failed"), "rc": -2}
    try:
        c = _session(so)
    except Exception as e:
        return {"ok": False, "out": "", "err": f"{type(e).__name__}: {e}", "rc": -1}
    if not c:
        return {"ok": False, "out": "", "err": "r_core_new 失败", "rc": -1}

    box: Dict[str, Any] = {}

    def work():
        try:
            box["out"] = _run(c, cmds)
            box["ok"] = True
        except Exception as e:
            box["ok"] = False
            box["err"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return {"ok": False, "out": "", "err": f"ctypes 调用超时({timeout}s)，"
                                               "线程无法中断，仍在后台运行", "rc": -3}
    return {"ok": box.get("ok", False), "out": box.get("out", ""),
            "err": box.get("err", ""), "rc": 0 if box.get("ok") else 1}


def close_session(so: str = None) -> Dict[str, Any]:
    """释放 RCore（so=None 则全释放）。"""
    s = _state["sessions"]
    if so:
        c = s.pop(so, None)
        if c:
            _free_core(c)
        return {"closed": bool(c), "file": so}
    n = len(s)
    for c in list(s.values()):
        _free_core(c)
    s.clear()
    return {"closed_all": True, "count": n}


def info() -> Dict[str, Any]:
    """当前加载状态。"""
    return {"loaded": _state["lib"] is not None,
            "dir": _state["dir"], "core": _state["core"],
            "preloaded": _state["preloaded"],
            "sessions": list(_state["sessions"])}


def check_deps(dir_hint: str = "") -> Dict[str, Any]:
    """检查 libr_core.so 及其依赖是否齐全（缺哪个会 dlopen 失败）。"""
    d = find_lib_dir(dir_hint) or dir_hint
    if not d or not os.path.isdir(d):
        return {"ok": False, "error": f"目录不存在: {dir_hint}"}
    have = {os.path.basename(p) for p in glob.glob(os.path.join(d, "*.so*"))}
    present, missing = [], []
    for name in _DEP_ORDER:
        hit = [h for h in have if h == name or h.startswith(name + ".")]
        (present if hit else missing).append(name)
    core_ok = bool([h for h in have if h.startswith("libr_core.so")])
    return {"dir": d, "libr_core": core_ok,
            "present": present, "missing": missing,
            "ok": core_ok and not missing[:len(_DEP_ORDER) - 1] or core_ok,
            "note": ("libr_core.so 已就位" if core_ok else "缺 libr_core.so，无法加载")
                    + (f"；还缺 {missing}" if missing else "")}
