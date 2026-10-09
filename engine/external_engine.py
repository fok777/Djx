"""
engine/external_engine.py — 外部引擎接入层（放进去即用）

背景：engine_runtime.locate_*() 只能**找到** so 的路径，但没有任何代码去
**调用**它。结果：so 放进 assets/engine/ 后 status() 显示"已内置"，
解析结果却还是启发式的——真实引擎根本没跑。本模块补上调用这一环。

三种调用模式（按你的 so 实际情况选，配在 assets/engine/engines.json）：

1. subprocess —— so 配套有可执行程序/脚本（最通用）
   例：blutter（开源）官方用法 python3 blutter.py <lib/arm64-v8a目录> <outdir>
2. ctypes     —— 直接 dlopen so 调导出函数
   需要知道入口函数名与参数/返回约定，可先用 probe() 列出导出符号再填
3. module     —— so 是 Python 扩展模块，可直接 import

不知道调用约定时先 probe()，它会列出导出符号并猜出入口函数。

用法：
    from engine.external_engine import invoke, probe, status
    status()                      # 各引擎是否已接入、能否调用
    probe("blutter")              # 列出 so 导出符号 + 猜测入口
    invoke("blutter", libapp=...) # 调真实引擎，失败抛异常由上层降级
"""
import os
import glob
import json
import ctypes
import subprocess
import shutil
from typing import Dict, Any, List, Optional

from . import engine_runtime

CONFIG_NAME = "engines.json"


# ---------- 配置 ----------

def config_path() -> Optional[str]:
    root = engine_runtime.engine_root()
    return os.path.join(root, CONFIG_NAME) if root else None


def load_config() -> Dict[str, Any]:
    """读 engines.json；不存在返回空配置（此时靠自动探测）。"""
    p = config_path()
    if not p or not os.path.isfile(p):
        return {}
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"_error": f"配置读取失败: {e}"}


def save_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    p = config_path()
    if not p:
        return {"error": "engine_root 未设置，无法写配置"}
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        json.dump(cfg, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        return {"written": p, "engines": list(cfg.get("engines", {}))}
    except OSError as e:
        return {"error": f"写入失败: {e}"}


def _entry(name: str) -> Dict[str, Any]:
    return (load_config().get("engines", {}) or {}).get(name, {}) or {}


# ---------- 资产定位 ----------

def locate(name: str, hint: str = "") -> Optional[str]:
    """定位引擎资产，优先内置目录，回落 PATH。"""
    if name == "blutter":
        return engine_runtime.locate_blutter(hint)
    if name == "radare2":
        return engine_runtime.locate_radare2()
    if name == "frida_server":
        return engine_runtime.locate_frida_server()
    if name == "frida_gadget":
        return engine_runtime.locate_frida_gadget()
    if name == "unidbg":
        return engine_runtime.locate_unidbg()
    # 自定义引擎：直接按 glob 找
    cfg = _entry(name)
    pat = cfg.get("glob")
    if pat:
        root = engine_runtime.engine_root()
        if root:
            hits = glob.glob(os.path.join(root, pat))
            if hits:
                return hits[0]
    return None


# ---------- 导出符号探测 ----------

def _exported_symbols(so: str, limit: int = 200) -> List[Dict]:
    """用 pyelftools 读动态符号表，列出导出函数。"""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return [{"error": "未装 pyelftools，无法读符号表"}]
    out = []
    try:
        with open(so, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not isinstance(sec, SymbolTableSection):
                    continue
                if sec.name not in (".dynsym", ".symtab"):
                    continue
                for sym in sec.iter_symbols():
                    if not sym.name:
                        continue
                    info = sym.entry.get("st_info", {})
                    if info.get("type") != "STT_FUNC":
                        continue
                    if sym.entry.get("st_shndx") == "SHN_UNDEF":
                        continue  # 未定义=导入，跳过
                    out.append({"name": sym.name,
                                "addr": hex(sym.entry.get("st_value", 0)),
                                "size": sym.entry.get("st_size", 0)})
                if out:
                    break
    except Exception as e:
        return [{"error": f"{type(e).__name__}: {e}"}]
    seen, uniq = set(), []
    for s in out:
        if s["name"] not in seen:
            seen.add(s["name"])
            uniq.append(s)
    return uniq[:limit]


_ENTRY_HINTS = ["blutter", "analyze", "analyse", "parse", "run", "main",
                "entry", "init", "dump", "load", "decode", "extract"]


def probe(name: str, so: str = None) -> Dict[str, Any]:
    """探测引擎：能否加载 / 导出符号 / 猜测入口函数。用于填 engines.json。"""
    path = so or locate(name)
    if not path or not os.path.isfile(path):
        return {"engine": name, "found": False,
                "hint": f"未找到资产，放到 {engine_runtime.engine_root()} 下对应子目录"}

    info: Dict[str, Any] = {"engine": name, "path": path, "found": True,
                            "size": os.path.getsize(path),
                            "mode": _entry(name).get("mode")}

    # ELF 类：先判形态（.so 可能实为可执行文件），再列导出符号
    if path.endswith(".so") or _is_elf(path):
        kind = _elf_kind(path)
        info["elf_kind"] = kind
        if kind.get("is_executable"):
            info["executable"] = True
            info["warning"] = (
                "这个 .so 实为 PIE 可执行文件（含 main，.interp="
                + str(kind.get("interp")) + "），不是共享库。"
                "请配 mode=subprocess 直接执行它，不要 ctypes dlopen")
            info["suggested_cmd"] = ["{exe}", "-i", "{libapp}", "-o", "{outdir}"]
        syms = _exported_symbols(path)
        info["exported_symbols"] = syms[:60]
        info["symbol_count"] = len(syms)
        guesses = []
        for s in syms:
            n = (s.get("name") or "").lower()
            if any(h in n for h in _ENTRY_HINTS):
                guesses.append(s)
        info["guessed_entrypoints"] = guesses[:15]
        # 试 dlopen
        try:
            lib = ctypes.CDLL(path)
            info["dlopen"] = True
            ok = []
            for g in guesses[:10]:
                if hasattr(lib, g["name"]):
                    ok.append(g["name"])
            info["ctypes_accessible"] = ok
        except OSError as e:
            info["dlopen"] = False
            info["dlopen_error"] = str(e)
    else:
        info["executable"] = os.access(path, os.X_OK)
        try:
            p = subprocess.run([path, "--help"], capture_output=True,
                               text=True, timeout=10)
            info["help_output"] = (p.stdout or p.stderr)[:800]
        except Exception as e:
            info["help_error"] = f"{type(e).__name__}: {e}"

    info["config_hint"] = {
        "mode": "ctypes 或 subprocess 或 module",
        "entry": "入口函数名（ctypes 模式必填）",
        "argtypes": "如 ['c_char_p','c_char_p']（ctypes 模式）",
        "restype": "如 c_char_p 或 c_int（ctypes 模式）",
        "cmd": "如 ['{exe}','{libapp}','{outdir}']（subprocess 模式）",
    }
    return info


def _elf_kind(path: str) -> Dict[str, Any]:
    """判断 ELF 形态：普通共享库 / 实为可执行文件（.so 命名）。"""
    out: Dict[str, Any] = {"is_executable": False, "interp": None,
                           "machine": None, "has_main": False}
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
        if head[:4] != b"\x7fELF":
            return out
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as fh:
            e = ELFFile(fh)
            out["machine"] = e.get_machine_arch()
            out["elf_class"] = e.elfclass
            interp = e.get_section_by_name(".interp")
            if interp is None:
                return out
            out["interp"] = interp.data().decode(errors="ignore").strip("\x00").strip()
            out["is_executable"] = True
            st = e.get_section_by_name(".symtab") or e.get_section_by_name(".dynsym")
            if st is not None:
                for sym in st.iter_symbols():
                    if sym.name == "main":
                        out["has_main"] = True
                        break
    except Exception as ex:
        out["error"] = f"{type(ex).__name__}: {ex}"
    return out


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


# ---------- 调用 ----------

def invoke(name: str, timeout: int = 120, **kwargs) -> Dict[str, Any]:
    """调用真实引擎。失败返回 {'error':...}，由上层决定是否降级。"""
    cfg = _entry(name)
    path = cfg.get("path") or locate(name, kwargs.get("dart_version", ""))
    if not path:
        return {"error": f"引擎 {name} 未找到资产或配置"}

    mode = cfg.get("mode")
    if not mode:
        return {"error": f"引擎 {name} 未配置 mode（ctypes/subprocess/module），"
                         f"先跑 probe('{name}') 看导出符号再填 engines.json"}

    try:
        if mode == "subprocess":
            return _invoke_subprocess(name, path, cfg, timeout, kwargs)
        if mode == "ctypes":
            return _invoke_ctypes(name, path, cfg, kwargs)
        if mode == "module":
            return _invoke_module(name, cfg, kwargs)
        return {"error": f"未知 mode: {mode}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "engine": name, "path": path}


def _fmt(tpl, kwargs) -> List[str]:
    return [x.format(**{k: (v if v is not None else "") for k, v in kwargs.items()})
            for x in tpl]


def _invoke_subprocess(name, path, cfg, timeout, kwargs) -> Dict:
    cmd = cfg.get("cmd")
    if not cmd:
        return {"error": "subprocess 模式需在 engines.json 配 cmd 模板"}
    exe = cfg.get("exe") or path
    args = _fmt(cmd, {**kwargs, "exe": exe})
    use_shell = cfg.get("shell", False)
    try:
        p = subprocess.run((" ".join(args) if use_shell else args),
                           capture_output=True, text=True, timeout=timeout,
                           shell=use_shell, cwd=cfg.get("cwd") or None)
        return {"engine": name, "ok": p.returncode == 0, "rc": p.returncode,
                "stdout": p.stdout[-8000:], "stderr": (p.stderr or "")[-2000:],
                "cmd": args,
                "outdir": kwargs.get("outdir")}
    except subprocess.TimeoutExpired:
        return {"error": f"引擎执行超时 ({timeout}s)", "engine": name}


def _invoke_ctypes(name, path, cfg, kwargs) -> Dict:
    entry = cfg.get("entry")
    if not entry:
        return {"error": "ctypes 模式需配 entry（入口函数名）"}
    try:
        lib = ctypes.CDLL(path)
    except OSError as e:
        return {"error": f"dlopen 失败: {e}"}
    fn = getattr(lib, entry, None)
    if fn is None:
        return {"error": f"so 中没有导出函数 {entry}；用 probe() 看真实符号名"}
    at = cfg.get("argtypes")
    if at:
        m = {"c_char_p": ctypes.c_char_p, "c_int": ctypes.c_int,
             "c_uint": ctypes.c_uint, "c_long": ctypes.c_long,
             "c_void_p": ctypes.c_void_p, "c_size_t": ctypes.c_size_t,
             "c_double": ctypes.c_double}
        fn.argtypes = [m.get(a, ctypes.c_char_p) for a in at]
    rt = cfg.get("restype")
    if rt:
        fn.restype = {"c_char_p": ctypes.c_char_p, "c_int": ctypes.c_int,
                      "c_void_p": ctypes.c_void_p, "c_long": ctypes.c_long}.get(
                          rt, ctypes.c_int)
    order = cfg.get("args") or []
    vals = []
    for a in order:
        v = kwargs.get(a)
        vals.append(v.encode() if isinstance(v, str) else v)
    raw = fn(*vals)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "ignore")
    return {"engine": name, "ok": True, "entry": entry, "result": raw,
            "outdir": kwargs.get("outdir")}


def _invoke_module(name, cfg, kwargs) -> Dict:
    import importlib
    mod = cfg.get("module")
    if not mod:
        return {"error": "module 模式需配 module 名"}
    try:
        m = importlib.import_module(mod)
    except ImportError as e:
        return {"error": f"import {mod} 失败: {e}"}
    fn = getattr(m, cfg.get("entry", "main"), None)
    if not callable(fn):
        return {"error": f"{mod} 中没有 {cfg.get('entry','main')}"}
    return {"engine": name, "ok": True, "result": fn(**kwargs)}


# ---------- 自检 ----------

def status() -> Dict[str, Any]:
    """各引擎：资产是否存在 / 是否已配调用方式 / 是否可调用。"""
    root = engine_runtime.engine_root()
    cfg = load_config().get("engines", {}) or {}
    names = ["blutter", "radare2", "frida_server", "frida_gadget", "unidbg"]
    names += [k for k in cfg if k not in names]
    rep: Dict[str, Any] = {"engine_root": root,
                           "config": config_path(),
                           "config_exists": bool(config_path() and os.path.isfile(config_path())),
                           "items": {}}
    for n in names:
        p = locate(n)
        c = cfg.get(n, {})
        rep["items"][n] = {
            "asset": p,
            "has_asset": bool(p),
            "mode": c.get("mode"),
            "configured": bool(c.get("mode")),
            "callable": bool(p and c.get("mode")),
            "path_fallback": (shutil.which(n.replace("_", "-")) if not p else None),
        }
    ready = [k for k, v in rep["items"].items() if v["callable"]]
    asset_only = [k for k, v in rep["items"].items() if v["has_asset"] and not v["configured"]]
    rep["ready"] = ready
    rep["asset_without_config"] = asset_only
    rep["note"] = (
        ("可调用: " + ",".join(ready)) if ready else "尚无引擎可调用"
    ) + (("；⚠ 有资产但未配调用方式: " + ",".join(asset_only)) if asset_only else "")
    return rep


def install_guide() -> Dict[str, Any]:
    """告诉用户每种引擎该放哪、命名规则、怎么配。"""
    root = engine_runtime.engine_root()
    return {
        "engine_root": root,
        "env_var": "R2B_ENGINE_ROOT（不设则用内置 assets/engine）",
        "layout": {
            "blutter/": "git clone https://github.com/worawit/blutter 后的整个目录；"
                        "可执行文件在 bin/blutter_dartvm{版本}_{os}_{arch}，"
                        "入口脚本是 blutter.py（推荐用它，会自动按版本编译）",
            "radare2/": "r2 或 radare2 可执行",
            "frida/": "frida-server（设备端）+ gadget*.so / libfrida-gadget*.so",
            "unidbg/": "unidbg.jar（含依赖），开源 github.com/zhkl0228/unidbg",
        },
        "steps": [
            "1) 把 so/二进制放进对应子目录",
            "2) python -m engine.external_engine 或调 Engine_Probe 探测导出符号",
            "3) 把 mode/entry/argtypes/cmd 写进 assets/engine/engines.json",
            "4) Engine_Status 确认 callable=true，之后 Blutter_* 自动走真实引擎",
        ],
        "note": "没配调用方式前，Blutter_* 仍走启发式（结果带 heuristic:true）",
    }
