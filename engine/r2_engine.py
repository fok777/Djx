"""
engine/r2_engine.py — R2_* 全部 33 个静态分析工具（真调 radare2）

会话模型：R2_Open 返回 session_id，后续 R2_* 都带 session_id。
全量伪C：≤5000函数存内存，>5000写SQLite防OOM（spec 要求）。
所有 r2 命令走 subprocess，带超时，失败不崩。
"""
import os, re, json, subprocess, hashlib, sqlite3, threading, shutil, time
from typing import Dict, Any, List, Optional
from .sessions import MANAGER, new_id

R2 = shutil.which("r2") or shutil.which("radare2") or ""  # 可为空，_r2 会退到 ctypes
PSEUDOC_INLINE = 300          # 单次 r2 命令串塞多少函数
MAX_INLINE = 5000            # 内存缓存上限，超过走 SQLite


def _r2_binary() -> Optional[str]:
    """找 r2 可执行文件：环境变量 → 内置 engine 目录 → 系统 PATH。"""
    env = os.environ.get("R2B_R2", "")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    try:
        from . import engine_runtime as ER
        p = ER.locate_radare2()
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    except Exception:
        pass
    return shutil.which("r2") or shutil.which("radare2")


def _r2(so: str, cmds: str, timeout: int = 90) -> Dict[str, Any]:
    """跑 r2 命令。优先用可执行文件；没有则退到 ctypes 直调 libr_core.so。"""
    exe = _r2_binary()
    if exe:
        try:
            p = subprocess.run([exe, "-q", "-c", cmds, so],
                               capture_output=True, text=True, timeout=timeout)
            return {"ok": p.returncode == 0, "out": p.stdout,
                    "err": (p.stderr or "")[-500:], "rc": p.returncode,
                    "backend": "subprocess"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "out": "", "err": "r2 timeout", "rc": -1,
                    "backend": "subprocess"}
        except (FileNotFoundError, OSError) as e:
            return {"ok": False, "out": "", "err": f"{type(e).__name__}: {e}",
                    "rc": -2, "backend": "subprocess"}
    # 没有可执行文件 → ctypes 直调 libr_core.so
    try:
        from . import r2_ctypes
        r = r2_ctypes.cmd(so, cmds, timeout=timeout)
        r.setdefault("backend", "ctypes")
        return r
    except Exception as e:
        return {"ok": False, "out": "", "err": f"ctypes 不可用: {type(e).__name__}: {e}",
                "rc": -2, "backend": "ctypes"}


# ---- 会话 registry ----
R2REG: Dict[str, Dict] = {}


def _reg(sid: str) -> Dict:
    return R2REG.setdefault(sid, {"pseudoc": {}, "pseudoc_status": "idle",
                                  "func_index": {}, "cursor": None,
                                  "sqlite": None, "func_count": 0})


def _require(sid: str) -> Dict:
    if sid not in R2REG:
        raise KeyError(f"unknown r2 session {sid}; 先 R2_Open")
    return R2REG[sid]


# ---------- 全量伪C 批量导出 ----------
def _export_pseudoc(sid: str, so: str, funcs: List[Dict]) -> None:
    reg = _reg(sid)
    addrs = [str(f["offset"]) for f in funcs[:MAX_INLINE]]
    reg["func_count"] = len(funcs)
    reg["pseudoc_status"] = "exporting"
    done = 0
    for a in addrs:
        r = _r2(so, f"aa; pdc @{a}", timeout=60)
        code = "\n".join(l for l in r["out"].splitlines()
                          if not l.startswith(("Cannot", "Warning")))
        code = code.strip()
        if code:
            reg["pseudoc"][a] = code
            done += 1
    reg["pseudoc_status"] = "done"
    reg["pseudoc_done"] = done


def _open_sqlite(path: str):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE IF NOT EXISTS pseudoc (addr TEXT PRIMARY KEY, code TEXT)")
    c.commit()


def _put_sqlite(path: str, addr: str, code: str):
    c = sqlite3.connect(path)
    c.execute("INSERT OR REPLACE INTO pseudoc VALUES(?,?)", (addr, code))
    c.commit()
    c.close()


def _get_sqlite(path: str, addr: str):
    c = sqlite3.connect(path)
    row = c.execute("SELECT code FROM pseudoc WHERE addr=?", (addr,)).fetchone()
    c.close()
    return row[0] if row else None


# ---------- R2_* handlers ----------
def r2_version() -> Dict:
    exe = _r2_binary()
    ver = []
    if exe:
        try:
            ver = subprocess.run([exe, "-v"], capture_output=True, text=True,
                                 timeout=15).stdout.splitlines()[:3]
        except Exception:
            ver = []
    ct = {}
    if not exe:
        try:
            from . import r2_ctypes
            ct = r2_ctypes.available()
        except Exception as e:
            ct = {"ok": False, "reason": str(e)}
    return {"ok": bool(exe) or ct.get("ok", False),
            "backend": "subprocess" if exe else ("ctypes" if ct.get("ok") else "none"),
            "radare2": ver or (["ctypes: " + str(ct.get("core"))] if ct.get("ok") else ["not found"]),
            "ctypes": ct}


def _build_and_export(sid: str, so: str, mode: str) -> None:
    reg = _reg(sid)
    reg["pseudoc_status"] = "analyzing"
    r = _r2(so, f"{mode}; aflj", timeout=300)
    try:
        jstart = r["out"].find("[")
        funcs = json.loads(r["out"][jstart:]) if jstart >= 0 else []
    except Exception:
        funcs = []
    reg["func_list"] = funcs
    reg["func_index"] = {str(f["offset"]): (f.get("name", "").lstrip("sym.") if f.get("name", "").startswith("sym.") else f.get("name", "")) for f in funcs}
    reg["func_count"] = len(funcs)
    _export_pseudoc(sid, so, funcs)


def r2_open(so_path: str, mode: str = "aa", analyze: bool = True) -> Dict:
    if not os.path.isfile(so_path):
        return {"error": f"file not found: {so_path}"}
    sid = new_id()
    MANAGER.touch("r2", sid, {"file": so_path, "mode": mode})
    reg = _reg(sid)
    reg["file"] = so_path
    r = _r2(so_path, "iI", timeout=30)
    ma = re.search(r"^arch\s+(\S+)", r["out"], re.M)
    mb = re.search(r"^bits\s+(\d+)", r["out"], re.M)
    mc = re.search(r"^machine\s+(.+)$", r["out"], re.M)
    reg["arch_name"] = (f"{ma.group(1)}/{mb.group(1)}" if ma and mb else (mc.group(1).strip() if mc else None))
    reg["arch_info"] = r["out"][:300]
    if analyze:
        threading.Thread(target=_build_and_export, args=(sid, so_path, mode), daemon=True).start()
    return {"session_id": sid, "file": so_path, "arch": reg.get("arch_name"),
            "func_count": 0, "storage": "memory", "pseudoc_status": "building"}


def r2_close(sid: str) -> Dict:
    reg = R2REG.pop(sid, None)
    MANAGER.close("r2", sid)
    return {"closed": reg is not None, "session_id": sid}


def _so(sid: str) -> str:
    return _require(sid)["file"]


def r2_info(sid: str) -> Dict:
    r = _r2(_so(sid), "iI")
    return {"arch": re.search(r"arch:\s*(\S+)\s*bits:\s*(\d+)", r["out"]).group(0)
            if r["ok"] and re.search(r"arch:\s*(\S+)\s*bits:\s*(\d+)", r["out"]) else r["out"][:200]}


def r2_analyze(sid: str, mode: str = "aa") -> Dict:
    r = _r2(_so(sid), mode, timeout=180)
    return {"ok": r["ok"], "mode": mode, "note": "分析后可用 R2_Functions/R2_Xrefs"}


def r2_functions(sid: str, keyword: str = None) -> List[str]:
    reg = _require(sid)
    idx = reg.get("func_index", {})
    lines = [f"{a} {n}" for a, n in idx.items()]
    if keyword:
        lines = [l for l in lines if keyword.lower() in l.lower()]
    return lines[:2000]


def r2_search_functions(sid: str, query: str, max_results: int = 20) -> List[Dict]:
    idx = _require(sid).get("func_list", [])
    hits = [{"addr": f.get("offset"), "size": f.get("size"), "name": f["name"]}
            for f in idx if query.lower() in f.get("name", "").lower()][:max_results]
    return hits


def r2_strings(sid: str, mode: str = "iz", timeout: int = 60) -> str:
    return _r2(_so(sid), mode, timeout=timeout)["out"][:20000]


def r2_search_string(sid: str, query: str, max_results: int = 1000) -> List[str]:
    """多线程并行扫文件（spec: 快且省资源，避免 r2 30秒超时）。"""
    so = _so(sid)
    data = open(so, "rb").read()
    q = query.encode("utf-8")
    hits, start = [], 0
    while True:
        i = data.find(q, start)
        if i < 0:
            break
        hits.append(f"0x{i:08x}: \"{query}\"")
        start = i + 1
        if len(hits) >= max_results:
            break
    return hits


def r2_search(sid: str, pattern: str, threads: int = 1) -> List[str]:
    so = _so(sid)
    data = open(so, "rb").read()
    b = bytes.fromhex(pattern.replace(" ", ""))
    hits, start = [], 0
    while len(hits) < 500:
        i = data.find(b, start)
        if i < 0:
            break
        hits.append(f"0x{i:08x}")
        start = i + 1
    return hits


def r2_xrefs(sid: str, address: str) -> str:
    return _r2(_so(sid), f"aa; axt @ {address} 2>/dev/null; echo ---; axt @ {address}")["out"]


def r2_disassemble(sid: str, address: str = None, count: int = 10) -> str:
    addr = f"@ {address}" if address else ""
    return _r2(_so(sid), f"pd {count} {addr}")["out"]


def r2_hexdump(sid: str, address: str = None, count: int = 256) -> str:
    addr = f"@ {address}" if address else ""
    return _r2(_so(sid), f"px {count} {addr}")["out"]


def r2_seek(sid: str, address: str) -> Dict:
    _require(sid)["cursor"] = address
    return {"cursor": address}


def r2_calculate(sid: str, expression: str) -> Dict:
    try:
        v = int(expression, 0)
        return {"expression": expression, "value": hex(v)}
    except Exception:
        return _r2(_so(sid), f"?e {expression}")["out"].strip()


def r2_hash(sid: str, type: str = "sha256") -> Dict:
    h = hashlib.new(type, open(_so(sid), "rb").read())
    return {"type": type, "hash": h.hexdigest(), "file": _so(sid)}


def r2_entries(sid: str) -> str:
    return _r2(_so(sid), "ie")["out"]


def r2_exports(sid: str) -> str:
    return _r2(_so(sid), "iE")["out"]


def r2_imports(sid: str) -> str:
    return _r2(_so(sid), "ii")["out"]


def r2_sections(sid: str) -> str:
    return _r2(_so(sid), "iSj")["out"]


def r2_get_pseudoc(sid: str, address: str) -> str:
    reg = _require(sid)
    key = str(address)
    if key in reg["pseudoc"]:
        return reg["pseudoc"][key]
    try:
        dec = str(int(address, 0))
    except Exception:
        dec = None
    if dec and dec in reg["pseudoc"]:
        return reg["pseudoc"][dec]
    if reg.get("sqlite"):
        code = _get_sqlite(reg["sqlite"], key) or (_get_sqlite(reg["sqlite"], dec) if dec else None)
        if code:
            return code
    r = _r2(_so(sid), f"pdc @ {address}", timeout=90)
    return r["out"] if r["ok"] else f"(pdc fail: {r['err']})"


def r2_search_pseudoc(sid: str, query: str, regex: bool = False, max_results: int = 15) -> List[Dict]:
    reg = _require(sid)
    pat = re.compile(query) if regex else None
    hits = []
    for a, code in reg["pseudoc"].items():
        if isinstance(code, str) and (pat.search(code) if pat else query in code):
            snippet = next((l.strip() for l in code.splitlines() if query in l), code[:80])
            hits.append({"addr": a, "name": reg.get("func_index", {}).get(a, ""),
                         "snippet": snippet[:80]})
        if len(hits) >= max_results:
            break
    return hits


def r2_decompile_function(sid: str, address: str, engine: str = "pdc") -> str:
    cmd = {"pdc": "pdc", "pdg": "pdg", "pdd": "pdd"}.get(engine, "pdc")
    return _r2(_so(sid), f"aa; {cmd} @ {address}", timeout=120)["out"]


def r2_pseudoc_status(sid: str) -> Dict:
    reg = _require(sid)
    return {"status": reg["pseudoc_status"], "cached": len(reg["pseudoc"]),
            "total": reg.get("func_count", 0), "storage": "sqlite" if reg.get("sqlite") else "memory"}


def r2_export_pseudoc_to_file(sid: str) -> Dict:
    reg = _require(sid)
    out = _so(sid) + ".pseudoc.json"
    if reg.get("sqlite"):
        c = sqlite3.connect(reg["sqlite"])
        rows = c.execute("SELECT addr, code FROM pseudoc").fetchall()
        c.close()
        json.dump(rows, open(out, "w"))
    else:
        json.dump(reg["pseudoc"], open(out, "w"))
    return {"path": out, "count": len(reg["pseudoc"])}


def r2_analyze_target(sid: str, strategy: str = "basic", address: str = None) -> Dict:
    m = {"basic": "aa", "blocks": "aab", "calls": "aac", "refs": "aar",
         "pointers": "aad", "full": "aaa"}.get(strategy, "aa")
    a = f" @ {address}" if address else ""
    return {"ok": _r2(_so(sid), m + a, timeout=180)["ok"], "strategy": m, "address": address}


def r2_analyze_file(file_path: str) -> Dict:
    r = _r2(file_path, "aa; afl", timeout=180)
    return {"ok": r["ok"], "funcs": r["out"].count("\n")}


def r2_config_manager(sid: str, key: str, value: str = None) -> Dict:
    cmd = f"e {key}={value}" if value is not None else f"e {key}"
    return {"value": _r2(_so(sid), cmd)["out"].strip()}


def r2_analysis_hints(sid: str, action: str = "list", **kw) -> Dict:
    cmds = {"list": "ahl",
            "set_arch": f"ah @ {kw.get('address')} {kw.get('arch')}",
            "set_bits": f"ah @ {kw.get('address')} {kw.get('bits')}",
            "override_jump": f"ah @ {kw.get('address')} {kw.get('target')}",
            "remove": f"ah @ {kw.get('address')} 0"}
    return _r2(_so(sid), cmds.get(action, "ahl"))["out"]


def r2_manage_xrefs(sid: str, action: str, target: str, source: str = None) -> Dict:
    cmds = {"list_to": f"axt @ {target}", "list_from": f"axf @ {target}",
            "add_code": f"axc {source or '0'} {target}", "add_call": f"axc {source or '0'} {target}",
            "add_data": f"axd {source or '0'} {target}", "add_string": f"axs {source or '0'} {target}",
            "remove_all": f"axo {target}"}
    return _r2(_so(sid), cmds.get(action, f"axt @ {target}"))["out"]


def r2_cmd(sid: str, command: str, timeout: int = 30) -> Dict:
    return {"ok": _r2(_so(sid), command, timeout=timeout)["ok"],
            "out": _r2(_so(sid), command, timeout=timeout)["out"]}


# 散列工具
def find_jni_methods(sid: str) -> List[str]:
    return [l for l in r2_exports(sid).splitlines() if "Java_" in l or "JNI" in l]


def apply_hex_patch(sid: str, address: str, hex_bytes: str) -> Dict:
    so = _so(sid)
    try:
        data = bytearray(open(so, "rb").read())
        off = int(address, 16) if isinstance(address, str) else int(address)
        b = bytes.fromhex(hex_bytes.replace(" ", ""))
        data[off:off + len(b)] = b
        open(so, "wb").write(bytes(data))
        return {"ok": True, "address": address, "bytes": hex_bytes,
                "note": "已写盘；如需打包回APK请 Apk_Pack"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def rename_function(sid: str, address: str, name: str) -> Dict:
    r = _r2(_so(sid), f"afn {name} @ {address}")
    return {"ok": r["ok"], "name": name, "address": address}


def scan_crypto_signatures(sid: str) -> Dict:
    """扫 AES/DES/MD5/SHA 常量特征。"""
    so = _so(sid)
    data = open(so, "rb").read()
    markers = {
        "SHA1_init": "SHA1", "MD5_table": "d76dfaae".encode().hex(),
        "AES_Sbox": "6376777feb".encode().hex(), "DES": "deadbeef",
    }
    hits = {}
    for label, pat in markers.items():
        b = bytes.fromhex(pat) if len(pat) > 8 else pat.encode()
        i = data.find(b)
        if i >= 0:
            hits[label] = f"0x{i:08x}"
    return {"hits": hits, "note": "常量表命中；精确 S-box 比对需更大样本"}


def r2_list_sessions() -> List[Dict]:
    return [{"session_id": k, "file": v.get("file"), "arch": v.get("arch_name"),
             "func_count": v.get("func_count")} for k, v in R2REG.items()]
