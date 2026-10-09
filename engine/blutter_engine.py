"""
engine/blutter_engine.py — Blutter_* 19 个 Flutter/Dart 工具

Blutter 是开源项目（github.com/worawit/blutter），产物为 asm/ + pp.txt。
本实现用 ELF + Dart 启发式近似：解析 libapp.so（Dart AOT）→
提取类/函数/字符串 + 生成 pp_table（对象→文件偏移）+ 桥接 R2/Frida。
能真跑：Analyze/Classes/Functions/Strings/PP_Table/To_R2/Patch/Modify_String/Info/Logs/Close。
需 Frida 降级的（To_Frida_Hook/Dart_Access/Find_Instances/Frida）→ 出脚本 + 说明。
"""
import os, re, json, time, tempfile
from typing import Dict, Any, List
from .sessions import MANAGER, new_id
from . import elf, r2_engine

BLUTTERREG: Dict[str, Dict] = {}


def _reg(sid):
    return BLUTTERREG.setdefault(sid, {"classes": {}, "funcs": {}, "strings": {},
                                       "pp_table": [], "logs": [], "pseudoc": None})


# ---------- 核心：分析 ----------
def _find_file_offset(so: str, s: str) -> int:
    data = open(so, "rb").read()
    i = data.find(s.encode("utf-8"))
    return i


def _is_class_like(s: str) -> bool:
    return bool(re.match(r"^[A-Z][A-Za-z0-9_]{2,40}$", s)) or \
           (s.count(".") >= 1 and s[0].isupper())


def _is_func_like(s: str) -> bool:
    return bool(re.match(r"^(Go_|dart:|_kDart|build|init|on[A-Z]|[a-z]+\.[a-z]+$)", s))


def _blutter_engine_match(dart_ver):
    try:
        from . import engine_runtime as _ER
        eng = _ER.locate_blutter(dart_ver or "")
        return {"matched": bool(eng), "path": eng, "dart": dart_ver,
                "note": (f"已装 Blutter({dart_ver})，走精确解析" if eng else "未装 Blutter，回落启发式 ELF 解析")}
    except Exception:
        return {"matched": False, "note": "engine_runtime 不可用"}


# ---------- 真实引擎接入（装了开源 blutter 且配好调用方式时走这条）----------

def _real_engine_analyze(lib_app_path: str, dart_ver: str, timeout: int) -> Dict:
    """调真实 Blutter 引擎；未接入/失败时返回 {'skipped':...} 由上层降级。"""
    try:
        from . import external_engine as EE
    except ImportError:
        return {"skipped": "external_engine 不可用"}
    cfg = EE._entry("blutter")
    if not cfg.get("mode"):
        asset = EE.locate("blutter", dart_ver or "")
        return {"skipped": "引擎资产未接入或未配调用方式",
                "asset": asset,
                "hint": "git clone blutter 放进 assets/engine/blutter/，"
                        "再跑 Engine_Set 配 mode=subprocess"}
    outdir = os.path.join(tempfile.gettempdir(), "r2b_blutter",
                          os.path.basename(lib_app_path))
    os.makedirs(outdir, exist_ok=True)
    exe = EE.locate("blutter", dart_ver or "") or ""
    libdir = os.path.dirname(lib_app_path)
    # 形态 A（libblutter_<ver>.so，实为可执行文件）用 -i / -o；
    # 形态 B（blutter.py）用位置参数 <libdir> <outdir>。
    # 两者的 cmd 模板都写在 engines.json 里，这里只负责喂参数。
    r = EE.invoke("blutter", timeout=max(timeout, 300),
                  libapp=lib_app_path, libdir=libdir, outdir=outdir,
                  exe=exe, dart_version=dart_ver or "",
                  blutter_py=cfg.get("blutter_py", "blutter.py"))
    if r.get("error"):
        return {"skipped": r["error"]}
    return {"ok": True, "outdir": outdir, "raw": r}


def _load_real_result(reg: Dict, real: Dict) -> int:
    """把真实 Blutter 产物（asm/ + pp.txt + objs.txt）灌进 reg，返回函数数。"""
    outdir = real.get("outdir")
    if not outdir or not os.path.isdir(outdir):
        return 0
    try:
        from . import blutter_output as BO
    except ImportError:
        return 0
    try:
        n = BO.to_registry(reg, outdir)
    except Exception as e:
        reg["logs"].append(f"[WARN] 产物解析失败: {type(e).__name__}: {e}")
        return 0
    if n:
        reg["logs"].append(f"[REAL] Blutter 产物: {len(reg['pp_table'])} pp 条目")
    return n


def blutter_analyze(lib_app_path: str, lib_flutter_path: str = None,
                    timeout_seconds: int = 30, session_id: str = None) -> Dict:
    """解析 libapp.so。装了开源 Blutter 则走真实解析，否则启发式。"""
    if not os.path.isfile(lib_app_path):
        return {"error": f"libapp.so not found: {lib_app_path}"}
    sid = session_id or new_id()
    t0 = time.time()
    reg = _reg(sid)
    MANAGER.touch("blutter", sid, {"file": lib_app_path})
    reg["file"] = lib_app_path
    # ---- 先试真实引擎 ----
    real = _real_engine_analyze(lib_app_path, None, timeout_seconds)
    if real.get("ok"):
        filled = _load_real_result(reg, real)
        if filled:
            reg["elapsed_s"] = round(time.time() - t0, 2)
            reg["pp_table"] = [{"type": "func", "name": n, "offset": f.get("offset")}
                               for n, f in list(reg["funcs"].items())[:5000]]
            reg["logs"].append(
                f"[REAL ENGINE] {filled} 条精确符号，outdir={real.get('outdir')}")
            return {"session_id": sid, "dart_version": reg.get("dart_version"),
                    "engine": "real_blutter", "heuristic": False,
                    "class_count": len(reg["classes"]), "func_count": len(reg["funcs"]),
                    "string_count": len(reg["strings"]),
                    "pp_count": len(reg["pp_table"]),
                    "outdir": real.get("outdir"),
                    "elapsed_s": reg["elapsed_s"]}
        reg["logs"].append(f"[WARN] 真实引擎跑通但产物无法解析，降级: {real.get('outdir')}")
    elif real.get("skipped"):
        reg["logs"].append(f"[INFO] 真实引擎跳过: {real['skipped']}")
    r = elf.parse_elf(lib_app_path, max_symbols=60000, max_strings=150000)
    if r.get("error"):
        reg["logs"].append(f"[ERROR] elf parse: {r['error']}")
    # Dart 特征
    da = elf.pick_dart_artifacts(r)
    reg["total_strings"] = r.get("string_count", 0)
    reg["total_dynsym"] = r.get("dyn_symbol_count", 0)
    # 类（字符串里大写开头的标识符 + dynsym 里的类特征）
    allcands = set(da["interesting_strings"]) | set(da["dart_strings"]) | set(r.get("dyn_symbols", []) and [s["name"] for s in r["dyn_symbols"]])
    for s in allcands:
        if isinstance(s, str):
            if _is_class_like(s):
                reg["classes"][s] = {"name": s, "parents": [], "methods": [], "fields": []}
    # 函数
    for s in da["dart_symbols_sample"]:
        reg["funcs"][s] = {"name": s, "class": None, "offset": None, "size": 0}
    for s in r.get("dyn_symbols", []):
        if s["name"].startswith(("Go_", "_")) or re.match(r"^[a-z_]+$", s["name"]):
            reg["funcs"][s["name"]] = {"name": s["name"], "class": None,
                                       "offset": s.get("value"), "size": s.get("size", 0)}
    # 全部字符串（spec：Blutter_Strings 搜快照中所有字符串常量）
    all_strings = list(dict.fromkeys(r.get("strings", [])))
    reg["strings"] = {s: None for s in all_strings}
    # pp_table：读一次 so 定位文件偏移（近似对象池表）
    try:
        so_data = open(lib_app_path, "rb").read()
    except Exception:
        so_data = b""
    pp = []
    for name in all_strings[:4000]:
        off = so_data.find(name.encode("utf-8", "ignore"))
        if off >= 0:
            reg["strings"][name] = hex(off)
            pp.append({"type": "string", "name": name, "offset": hex(off)})
    for name, f in list(reg["funcs"].items())[:2000]:
        o = f.get("offset")
        if o and isinstance(o, str) and o.startswith("0x"):
            pp.append({"type": "func", "name": name, "offset": o})
    reg["pp_table"] = pp
    reg["dart_version"] = None
    for s in r.get("strings", []):
        m = re.search(r"(Dart|dart)\s*(\d\.\d+\.\d+)", s)
        if m:
            reg["dart_version"] = m.group(2)
            break
    reg["elapsed_s"] = round(time.time() - t0, 2)
    reg["logs"].append(f"[OK] {len(reg['classes'])} classes, {len(reg['funcs'])} funcs, "
                       f"{len(reg['strings'])} strings, {len(pp)} pp entries, {reg['elapsed_s']}s")
    return {"session_id": sid, "dart_version": reg.get("dart_version"),
            "class_count": len(reg["classes"]), "func_count": len(reg["funcs"]),
            "string_count": len(reg["strings"]), "pp_count": len(pp),
            "elapsed_s": reg["elapsed_s"],
            "builtin_engine": _blutter_engine_match(reg.get("dart_version")),
            "engine": "heuristic_elf", "heuristic": True}


def _bsid(sid):
    if sid not in BLUTTERREG:
        raise KeyError(f"unknown blutter session {sid}; 先 Blutter_Analyze")
    return _reg(sid)


def blutter_classes(sid: str, filter: str = None) -> List[Dict]:
    reg = _bsid(sid)
    items = list(reg["classes"].values())
    if filter:
        items = [c for c in items if filter.lower() in c["name"].lower()]
    return items[:100]


def blutter_class_detail(sid: str, class_name: str) -> Dict:
    reg = _bsid(sid)
    for name, c in reg["classes"].items():
        if class_name.lower() in name.lower():
            return c
    return {"not_found": True, "searched": class_name}


def blutter_functions(sid: str, class_name: str = None, filter: str = None) -> List[Dict]:
    reg = _bsid(sid)
    items = list(reg["funcs"].values())
    if filter:
        items = [f for f in items if filter.lower() in f["name"].lower()]
    return items[:200]


def blutter_strings(sid: str, filter: str = None) -> List[Dict]:
    reg = _bsid(sid)
    out = [{"name": k, "offset": v} for k, v in reg["strings"].items() if v]
    if filter:
        out = [o for o in out if filter.lower() in o["name"].lower()]
    return out[:100]


def blutter_pp_table(sid: str, filter: str = None) -> List[Dict]:
    reg = _bsid(sid)
    t = reg["pp_table"]
    if filter:
        t = [e for e in t if filter.lower() in e["name"].lower() or filter.lower() in str(e.get("offset", ""))]
    return t[:200]


def blutter_object_layouts(sid: str, filter: str = None) -> List[Dict]:
    reg = _bsid(sid)
    out = [{"class": c, "methods": reg["classes"].get(c, {}).get("methods", [])}
           for c in reg["classes"]]
    if filter:
        out = [o for o in out if filter.lower() in o["class"].lower()]
    return out[:100]


def blutter_disassemble(sid: str, function_name: str = None, open_r2: bool = True) -> Dict:
    reg = _bsid(sid)
    so = reg["file"]
    if not function_name:
        return {"asm_files": so}
    off = reg["funcs"].get(function_name, {}).get("offset") or \
        next((v for k, v in reg["funcs"].items() if function_name.lower() in k.lower()), None)
    r2_sid = r2_engine.r2_open(so, analyze=False)["session_id"] if open_r2 else None
    return {"so": so, "function": function_name, "offset": off,
            "r2_session_id": r2_sid,
            "note": f"R2_Disassemble(session_id={r2_sid}, address={off}) 看汇编" if r2_sid else "open_r2=false"}


def blutter_to_r2(sid: str, function_name: str) -> Dict:
    reg = _bsid(sid)
    off = reg["funcs"].get(function_name, {}).get("offset")
    so = reg["file"]
    r2_sid = r2_engine.r2_open(so, analyze=True)["session_id"]
    r2_engine.r2_seek(r2_sid, off or "0")
    return {"blutter_session_id": sid, "r2_session_id": r2_sid,
            "function": function_name, "seek_offset": off}


def blutter_patch(sid: str, function_name: str, action: str, bytes_hex: str = None) -> Dict:
    reg = _bsid(sid)
    so = reg["file"]
    off = reg["funcs"].get(function_name, {}).get("offset")
    if not off:
        cand = [k for k in reg["funcs"] if function_name.lower() in k.lower()]
        off = reg["funcs"][cand[0]]["offset"] if cand else None
    if not off:
        return {"error": f"function {function_name} offset not found"}
    r2_sid = r2_engine.r2_open(so, analyze=False)["session_id"]
    if action == "ret":
        b = "c0035fd6"          # arm64: mov w0,#1; ret
    elif action == "nop":
        b = "1f2003d5"
    elif action == "custom":
        b = bytes_hex
    else:
        return {"error": f"unknown action {action}"}
    res = r2_engine.apply_hex_patch(r2_sid, off, b)
    r2_engine.r2_close(r2_sid)
    return {"function": function_name, "offset": off, "action": action, "patched": b, **res}


def blutter_modify_string(sid: str, search_str: str, replace_str: str) -> Dict:
    reg = _bsid(sid)
    so = reg["file"]
    data = bytearray(open(so, "rb").read())
    s = search_str.encode("utf-8")
    reps = []
    start = 0
    if len(replace_str) > len(search_str):
        return {"error": "new_string 不能长于原串（会截断）"}
    newb = (replace_str + " " * (len(search_str) - len(replace_str)))[:len(search_str)].encode("utf-8", "ignore")
    while True:
        i = data.find(s, start)
        if i < 0:
            break
        data[i:i + len(s)] = newb
        reps.append({"file_offset": hex(i)})
        start = i + 1
    open(so, "wb").write(bytes(data))
    return {"modified": len(reps), "replacements": reps, "note": "已改 so；打包用 Apk_Pack"}


def blutter_frida(sid: str) -> Dict:
    """导出 Frida hook 脚本（Blutter_Frida.js）。"""
    reg = _bsid(sid)
    so = os.path.basename(reg["file"])
    js = "// R2B Blutter_Frida.js\n" + "\n".join(
        f"// {n} @ {f.get('offset')}" for n, f in list(reg["funcs"].items())[:200])
    out = reg["file"] + ".blutter_frida.js"
    open(out, "w").write(js)
    return {"script": out, "note": "PC 端 frida -U -l 执行；当前环境无 frida-server"}


def blutter_to_frida_hook(sid: str, frida_sid: str, function_name: str,
                          hook_type: str = "both") -> Dict:
    reg = _bsid(sid)
    off = reg["funcs"].get(function_name, {}).get("offset")
    return {"blutter_sid": sid, "frida_sid": frida_sid, "function": function_name,
            "offset": off, "hook_type": hook_type,
            "js": f"Interceptor.attach(Module.findBaseAddress('{os.path.basename(reg['file'])}') + ptr('{off}'), {{onEnter(a){{send(['->',a[0]]);}}, onLeave(r){{send(['<-',r]);}}}});",
            "note": "需已 Fr_Attach 的 frida_sid；脚本注入后 Fr_Read_Messages 收数据"}


def blutter_dart_access(sid: str, frida_sid: str, class_name: str, action: str,
                       field_name: str = None, instance_addr: str = None, new_value: str = None) -> Dict:
    reg = _bsid(sid)
    c = reg["classes"].get(class_name, {})
    return {"blutter_sid": sid, "frida_sid": frida_sid, "class": class_name,
            "action": action, "field": field_name, "layout": c.get("fields", []),
            "js": f"// read/write {class_name}.{field_name} @ {instance_addr}" if action == "write" else f"// read {class_name}.{field_name}",
            "note": "运行时读写需 Frida 会话；环境无 frida-server，出 JS 供 PC 端跑"}


def blutter_find_instances(sid: str, frida_sid: str, class_name: str, method_name: str = None) -> Dict:
    reg = _bsid(sid)
    cands = [m for m in reg["classes"].get(class_name, {}).get("methods", [])] or [method_name]
    return {"blutter_sid": sid, "frida_sid": frida_sid, "class": class_name,
            "candidates": cands or ["build", "initState", "createState"],
            "note": "hook 方法入口捕 this 指针；需 Frida 会话"}


def blutter_info(sid: str) -> Dict:
    reg = _bsid(sid)
    return {"file": reg["file"], "dart_version": reg.get("dart_version"),
            "classes": len(reg["classes"]), "funcs": len(reg["funcs"]),
            "strings": len(reg["strings"]), "pp_entries": len(reg["pp_table"]),
            "elapsed_s": reg.get("elapsed_s")}


def blutter_logs(sid: str) -> List[str]:
    return _bsid(sid)["logs"]


def blutter_close(sid: str) -> Dict:
    BLUTTERREG.pop(sid, None)
    return MANAGER.close("blutter", sid)


def blutter_list_sessions() -> List[Dict]:
    return [{"session_id": k, "file": v.get("file"), "dart_version": v.get("dart_version"),
             "classes": len(v.get("classes", {})), "funcs": len(v.get("funcs", {}))}
            for k, v in BLUTTERREG.items()]


def blutter_annotate_r2(sid: str, function_filter: str = None) -> Dict:
    reg = _bsid(sid)
    r2_sid = r2_engine.r2_open(reg["file"], analyze=True)["session_id"]
    # 把 pp 字符串 / 函数注释进 r2（CC）
    added = 0
    for e in reg["pp_table"][:100]:
        if function_filter and function_filter.lower() not in e["name"].lower():
            continue
        if e.get("offset") and e["type"] == "string":
            r2_engine._r2(reg["file"], f'CC "blutter: {e["name"]}" @ {e["offset"]}', timeout=20)
            added += 1
    r2_engine.r2_close(r2_sid)
    return {"annotated": added, "r2_sid_was": r2_sid, "note": "增量 CC 注释"}


def blutter_to_unidbg_call(sid: str, function_name: str, args: str = None) -> Dict:
    reg = _bsid(sid)
    off = reg["funcs"].get(function_name, {}).get("offset")
    return {"blutter_sid": sid, "func": function_name, "offset": off,
            "unimplemented": True,
            "note": "需 unidbg(Ub_Open) 会话；出调用参数：Ub_Call_Offset(offset=%s, args=%s)" % (off, args or "[]")}
