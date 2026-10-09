"""
engine/il2cpp_extra.py — Il2Cpp_* 补齐的 11 个 Unity 结构化工具

现行 il2cpp_engine 有 30 个工具，缺「C# 类型结构」那层：
字段、属性、接口、枚举、结构体布局、内存读取。本模块补齐。

⚠ 诚实边界：global-metadata.dat 携带类型/方法/字符串表，但**不含字段类型
签名与接口实现列表**（那在 libil2cpp.so 的运行时结构里）。本模块基于
metadata 类型表 + so 符号做启发式重建，字段类型多为 unknown。
需要精确结构请配合 Il2CppDumper（设 R2B_IL2CPP_DUMPER）。
"""
import os
import re
import json
from typing import Dict, Any, List

from .sessions import new_id
from .il2cpp_engine import IL2REG, _il

DUMPER = os.getenv("R2B_IL2CPP_DUMPER", "")


def _isid(sid):
    if sid not in IL2REG:
        raise KeyError(f"unknown il2cpp session {sid}; 先 Il2Cpp_Open")
    return _il(sid)


def _mark(d: Dict, how: str) -> Dict:
    d["heuristic"] = True
    d["source"] = how
    return d


def _ns_of(t: str):
    """'Namespace.Class' -> ('Namespace', 'Class')。"""
    if "." in t:
        return t.rsplit(".", 1)[0], t.rsplit(".", 1)[1]
    return "", t


# ---------- 类型结构 ----------

def il2cpp_classes(sid: str, filter: str = None, namespace: str = None,
                   max_results: int = 300) -> Dict:
    """列出所有 C# 类，可按命名空间过滤。"""
    reg = _isid(sid)
    items = []
    for t in reg.get("types", []):
        if not isinstance(t, str):
            t = t.get("name", "") if isinstance(t, dict) else str(t)
        ns, name = _ns_of(t)
        if namespace and namespace.lower() not in ns.lower():
            continue
        if filter and filter.lower() not in t.lower():
            continue
        items.append({"full": t, "namespace": ns, "name": name})
    return _mark({"session_id": sid, "total": len(items),
                  "classes": items[:max_results]}, "metadata type table")


def il2cpp_fields(sid: str, class_name: str = None, filter: str = None,
                  max_results: int = 300) -> Dict:
    """字段列表。从 metadata 字符串与 so 符号里按 Class.field / get_ set_ 推断。"""
    reg = _isid(sid)
    out: List[Dict] = []
    # 1) 字符串里的 Class.field
    for s in reg.get("strings", []):
        if not isinstance(s, str) or "." not in s:
            continue
        owner, field = s.rsplit(".", 1)
        if not field or field[0].isupper():
            continue
        if class_name and class_name.lower() not in owner.lower():
            continue
        if filter and filter.lower() not in field.lower():
            continue
        out.append({"class": owner, "field": field, "type": "unknown",
                    "inferred_from": "string"})
    # 2) so 符号里的 getter/setter → 推断属性字段
    for m in reg.get("methods", []):
        n = m.get("name", "") if isinstance(m, dict) else str(m)
        mm = re.match(r"^(\w+)_(?:get|set)_(\w+)$", n)
        if mm:
            cls, fld = mm.group(1), mm.group(2)
            if class_name and class_name.lower() not in cls.lower():
                continue
            if filter and filter.lower() not in fld.lower():
                continue
            out.append({"class": cls, "field": fld, "type": "unknown",
                        "inferred_from": "getter/setter symbol"})
    seen, uniq = set(), []
    for f in out:
        k = (f["class"], f["field"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return _mark({"session_id": sid, "class": class_name, "total": len(uniq),
                  "fields": uniq[:max_results],
                  "note": "字段类型签名不在 metadata 中，type 恒为 unknown；"
                          "需精确结构请用 Il2CppDumper"},
                 "strings + accessor symbols")


def il2cpp_properties(sid: str, class_name: str = None,
                      filter: str = None) -> Dict:
    """属性列表（get_X / set_X 成对识别）。"""
    reg = _isid(sid)
    props: Dict[str, Dict] = {}
    for m in reg.get("methods", []):
        n = m.get("name", "") if isinstance(m, dict) else str(m)
        mm = re.match(r"^(?:(\w+?)_)?(get|set)_(\w+)$", n)
        if not mm:
            continue
        cls, kind, prop = mm.group(1) or "", mm.group(2), mm.group(3)
        if class_name and class_name.lower() not in cls.lower():
            continue
        if filter and filter.lower() not in prop.lower():
            continue
        key = f"{cls}.{prop}"
        e = props.setdefault(key, {"class": cls, "property": prop,
                                   "getter": None, "setter": None,
                                   "read_only": True})
        e["getter" if kind == "get" else "setter"] = n
        e["read_only"] = e["setter"] is None
    return _mark({"session_id": sid, "class": class_name,
                  "total": len(props),
                  "properties": list(props.values())[:300]},
                 "get_/set_ accessor symbols")


def il2cpp_interfaces(sid: str, class_name: str = None) -> Dict:
    """接口/抽象类型：I 前缀 + 全大写缩写命名 + 无实现方法。"""
    reg = _isid(sid)
    out = []
    for t in reg.get("types", []):
        t = t if isinstance(t, str) else (t.get("name", "") if isinstance(t, dict) else "")
        if not t:
            continue
        _, name = _ns_of(t)
        if not re.match(r"^I[A-Z]", name):
            continue
        if class_name and class_name.lower() not in t.lower():
            continue
        out.append({"interface": t, "name": name})
    return _mark({"session_id": sid, "total": len(out),
                  "interfaces": out[:300],
                  "note": "仅按 I 前缀命名约定识别，metadata 不含 implements 列表"},
                 "naming convention I*")


def il2cpp_enums(sid: str, filter: str = None) -> Dict:
    """枚举类型与成员：Enum 后缀类型 + 全大写成员常量。"""
    reg = _isid(sid)
    enums = []
    for t in reg.get("types", []):
        t = t if isinstance(t, str) else (t.get("name", "") if isinstance(t, dict) else "")
        if not t or not re.search(r"Enum|Flags|State|Type$|Mode$", t):
            continue
        if filter and filter.lower() not in t.lower():
            continue
        _, name = _ns_of(t)
        members = [s for s in reg.get("strings", [])
                   if isinstance(s, str) and re.match(r"^[A-Z][A-Z0-9_]{2,30}$", s)
                   and name.lower()[:6] in s.lower()]
        enums.append({"enum": t, "name": name, "members": members[:30]})
    return _mark({"session_id": sid, "total": len(enums), "enums": enums[:100]},
                 "type-name regex + uppercase members")


def il2cpp_struct(sid: str, class_name: str) -> Dict:
    """结构体/类布局：字段顺序 + 估算偏移（按指针对齐 8 字节近似）。"""
    reg = _isid(sid)
    f = il2cpp_fields(sid, class_name, max_results=100)
    fields = f.get("fields", [])
    off = 0
    layout = []
    for x in fields:
        layout.append({"field": x["field"], "offset": hex(off),
                       "size_guess": 8, "type": "unknown"})
        off += 8
    return _mark({"session_id": sid, "class": class_name,
                  "field_count": len(layout), "layout": layout,
                  "size_guess": off,
                  "warning": "偏移按 8 字节指针对齐估算，非真实布局；"
                             "真实布局需 Il2CppDumper 或运行时 dump"},
                 "8-byte aligned guess")


# ---------- 读取与搜索 ----------

def il2cpp_read(sid: str, address: str, size: int = 256,
                as_type: str = None) -> Dict:
    """读 libil2cpp.so 指定地址（走 r2 hexdump）。"""
    reg = _isid(sid)
    so = reg.get("so")
    if not so or not os.path.isfile(so):
        return {"error": "libil2cpp.so 未就绪", "session_id": sid}
    try:
        from . import r2_engine
        tmp = r2_engine.r2_open(so, analyze=False)
        tsid = tmp.get("session_id")
        out = r2_engine.r2_hexdump(tsid, address, count=size)
        r2_engine.r2_close(tsid)
        return {"session_id": sid, "so": so, "address": address,
                "as_type": as_type, "data": out}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "session_id": sid}


def il2cpp_search(sid: str, query: str, kind: str = None,
                  max_results: int = 100) -> Dict:
    """跨类型/方法/字符串搜索。"""
    reg = _isid(sid)
    q = (query or "").lower()
    hits: List[Dict] = []
    if not kind or kind == "type":
        hits += [{"kind": "type", "name": t if isinstance(t, str) else str(t)}
                 for t in reg.get("types", []) if q in str(t).lower()]
    if not kind or kind == "method":
        for m in reg.get("methods", []):
            n = m.get("name", "") if isinstance(m, dict) else str(m)
            if q in n.lower():
                hits.append({"kind": "method", "name": n,
                             "rva": m.get("rva") if isinstance(m, dict) else None})
    if not kind or kind == "string":
        hits += [{"kind": "string", "name": s}
                 for s in reg.get("strings", []) if q in str(s).lower()]
        hits = hits[:max_results * 3]
    return _mark({"session_id": sid, "query": query, "total": len(hits),
                  "hits": hits[:max_results]}, "substring match")


def il2cpp_to_r2(sid: str, out_dir: str = None, class_name: str = None) -> Dict:
    """导出 r2 脚本：把 C# 符号写成 afn/CC，导入后反汇编可读。"""
    reg = _isid(sid)
    cmds = []
    for m in reg.get("methods", []):
        if isinstance(m, dict):
            n, rva = m.get("name"), m.get("rva")
        else:
            n, rva = str(m), None
        if not n or rva in (None, 0, "0", "pending"):
            continue
        if class_name and class_name.lower() not in n.lower():
            continue
        safe = re.sub(r"[^A-Za-z0-9_]", "_", n)[:60]
        cmds.append(f"afn {safe} {rva}")
        cmds.append(f"CC {safe} @{rva}")
    text = "\n".join(cmds)
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
            p = os.path.join(out_dir, "il2cpp_symbols.r2")
            open(p, "w", encoding="utf-8").write(text)
            return {"session_id": sid, "written": p, "count": len(cmds)}
        except OSError as e:
            return {"error": f"write failed: {e}", "session_id": sid}
    return _mark({"session_id": sid, "count": len(cmds), "r2_commands": cmds[:500]},
                 "metadata rva -> afn/CC")


def il2cpp_script_json(sid: str, out_dir: str = None) -> Dict:
    """产出 Il2CppDumper 风格的 script.json（地址/名字/签名）。"""
    reg = _isid(sid)
    scripts = []
    for m in reg.get("methods", []):
        if isinstance(m, dict):
            n, rva = m.get("name"), m.get("rva")
        else:
            n, rva = str(m), None
        if not n:
            continue
        scripts.append({"Address": rva or 0, "Name": n, "Signature": None})
    data = {
        "ScriptMethod": scripts,
        "ScriptString": [{"Address": 0, "Value": s} for s in reg.get("strings", [])[:5000]
                         if isinstance(s, str)],
        "ScriptMetadata": {"UnityVersion": reg.get("unity_version"),
                           "ImageBase": reg.get("imageBase", 0)},
    }
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
            p = os.path.join(out_dir, "script.json")
            json.dump(data, open(p, "w", encoding="utf-8"), ensure_ascii=False)
            return {"session_id": sid, "written": p,
                    "methods": len(scripts),
                    "strings": len(data["ScriptString"])}
        except OSError as e:
            return {"error": f"write failed: {e}", "session_id": sid}
    return {"session_id": sid, "methods": len(scripts),
            "preview": scripts[:50],
            "hint": "传 out_dir 可落盘为 script.json"}


def il2cpp_version(sid: str) -> Dict:
    """Unity 与 metadata 版本。"""
    reg = _isid(sid)
    binp = reg.get("binary") or {}
    return {"session_id": sid, "unity_version": reg.get("unity_version"),
            "metadata_version": binp.get("version") or binp.get("metadataVersion"),
            "image_base": hex(reg.get("imageBase", 0)),
            "types": len(reg.get("types", [])),
            "methods": len(reg.get("methods", [])),
            "strings": len(reg.get("strings", [])),
            "dumper": DUMPER or None,
            "note": ("已配置 Il2CppDumper，可出精确 RVA" if DUMPER
                     else "未配 R2B_IL2CPP_DUMPER，RVA 为 metadata 推算值")}


# ---------- 别名：工具名小写化与函数名不一致时对齐 ----------
# Il2Cpp_Dump -> il2cpp_dump（复用 engine/il2cpp.py 已有实现）
def il2cpp_dump(sid: str, out_dir: str = None) -> Dict:
    """导出 Il2CppDumper 三件套（复用 engine/il2cpp.write_triad）。"""
    from . import il2cpp
    reg = _isid(sid)
    d = out_dir or "out_test/il2cpp"
    try:
        import os
        os.makedirs(d, exist_ok=True)
        r = il2cpp.write_triad(reg.get("metadata"), reg.get("so"), d)
        return {"session_id": sid, "out_dir": d, **r}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "session_id": sid}
