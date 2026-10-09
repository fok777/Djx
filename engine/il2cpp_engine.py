"""
engine/il2cpp_engine.py — Il2Cpp_* 15 工具（Unity C# 符号全还原）

基于 global-metadata.dat 提取 C# 类型/方法/字符串 + libil2cpp.so 符号，
产出 Il2CppDumper 三件套（script.json / DummyTypes / string.json）。
RVA 精确值需 Il2CppDumper（R2B_IL2CPP_DUMPER）；此处类型/方法/字符串真实，RVA 标 pending。
"""
import os, re, glob, json, shutil
from typing import Dict, Any, List
from .sessions import MANAGER, new_id
from . import il2cpp, elf, il2cpp_binary

IL2REG: Dict[str, Dict] = {}


def _il(sid) -> Dict:
    return IL2REG.setdefault(sid, {"types": [], "methods": [], "strings": [],
                                   "metadata": None, "so": None, "unity_version": None, "classes": {}})


def il2cpp_open(extract_dir: str = None, metadata: str = None, il2cpp_so: str = None) -> Dict:
    sid = new_id()
    reg = _il(sid)
    if metadata is None:
        metadata = il2cpp._find_metadata(extract_dir) if extract_dir else ""
    if il2cpp_so is None:
        il2cpp_so = il2cpp._find_il2cpp_so(extract_dir) if extract_dir else ""
    reg["metadata"] = metadata
    reg["so"] = il2cpp_so
    res = il2cpp.parse_metadata(metadata, il2cpp_so)
    reg["unity_version"] = res.get("unity_version")
    reg["types"] = res.get("types", [])
    reg["methods"] = res.get("methods", [])
    reg["strings"] = res.get("strings", [])
    # 精确 RVA / 类 / 命名空间
    if metadata and os.path.isfile(metadata):
        bp = il2cpp_binary.parse_global_metadata(metadata)
        if bp.get("ok"):
            reg["binary"] = bp
            reg["imageBase"] = bp.get("imageBase", 0)
            reg["methods_rva"] = [m for m in bp.get("methods", []) if m.get("name")]
            if bp.get("types"):
                reg["types"] = [t["name"] for t in bp["types"] if t.get("name")]
            if bp.get("strings"):
                reg["strings"] = list(dict.fromkeys(bp["strings"] + reg["strings"]))
            reg["rva_status"] = "resolved"
    # 类（有命名空间 或 全大写缩写特征）
    for t in reg["types"]:
        if ("." in t and t.count(".") >= 1) or re.search(r"[A-Z][a-z]+(?:[A-Z][a-z]+){1,}$", t):
            reg["classes"][t] = {"name": t, "methods": [], "fields": []}
    MANAGER.projects  # noqa（仅确保 MANAGER 可用；il2cpp 走独立 IL2REG）
    reg["rva_status"] = "resolved" if reg.get("methods_rva") else "pending"
    return {"session_id": sid, "unity_version": res.get("unity_version"),
            "type_count": len(reg["types"]), "method_count": len(reg["methods"]),
            "string_count": len(reg["strings"]),
            "metadata": metadata, "il2cpp_so": il2cpp_so,
            "rva_status": reg["rva_status"], "binary_resolved": bool(reg.get("methods_rva"))}


def _req(sid):
    if sid not in IL2REG:
        raise KeyError(f"unknown il2cpp session {sid}; 先 Il2Cpp_Open")
    return _il(sid)


def il2cpp_types(sid, filter: str = None):
    reg = _req(sid)
    t = reg["types"]
    if filter:
        t = [x for x in t if filter.lower() in x.lower()]
    return {"count": len(t), "types": t[:2000]}


def il2cpp_methods(sid, filter: str = None):
    reg = _req(sid)
    t = [m["name"] for m in reg.get("methods_rva", [])] or reg["methods"]
    if filter:
        t = [x for x in t if filter.lower() in x.lower()]
    return {"count": len(t), "methods": t[:2000],
            "precise": bool(reg.get("methods_rva")), "note": "binary 解析精确" if reg.get("methods_rva") else "字符串启发式"}


def il2cpp_strings(sid, filter: str = None):
    reg = _req(sid)
    t = reg["strings"]
    if filter:
        t = [x for x in t if filter.lower() in x.lower()]
    return {"count": len(t), "strings": t[:3000]}


def il2cpp_class_detail(sid, class_name: str):
    reg = _req(sid)
    m = [k for k in reg["classes"] if class_name.lower() in k.lower()]
    if not m:
        return {"not_found": class_name}
    c = m[0]
    meth = [x for x in reg["methods"] if c in x][:200]
    return {"class": c, "methods": meth, "note": "C# 方法名从 metadata 提取；RVA 需 Il2CppDumper"}


def il2cpp_method_detail(sid, method: str):
    reg = _req(sid)
    hits = [x for x in reg["methods"] if method.lower() in x.lower()][:50]
    return {"method": method, "matches": hits, "rva_status": "pending_il2cpp_dumper"}


def il2cpp_metadata_info(sid):
    reg = _req(sid)
    return {"unity_version": reg.get("unity_version"), "metadata": reg.get("metadata"),
            "il2cpp_so": reg.get("so"), "type_count": len(reg["types"]),
            "method_count": len(reg["methods"]), "string_count": len(reg["strings"])}


def il2cpp_version_detect(sid):
    reg = _req(sid)
    v = reg.get("unity_version")
    mapping = {"0x1d": "Unity ~2019(v29)", "0x1e": "Unity 2020", "0x20": "Unity 2021",
               "0x27": "Unity 6 (roytu fork v39)", "0x23": "Unity 2022"}
    return {"header_magic": v, "unity_guess": mapping.get(v, "未知版本(参考v29=2021/v39=Unity6)"),
            "note": "metadata 头4字节判定版本"}


def il2cpp_so_scan(sid, pattern: str = "lib*.so"):
    """扫 libil2cpp.so 的 native 符号。"""
    reg = _req(sid)
    if not reg.get("so"):
        return {"error": "no il2cpp so"}
    r = elf.parse_elf(reg["so"], max_symbols=20000, max_strings=60000)
    syms = [s["name"] for s in r.get("dyn_symbols", []) if pattern in s["name"].lower() or True][:2000]
    return {"arch": r.get("arch"), "string_count": r.get("string_count"),
            "dyn_symbol_count": r.get("dyn_symbol_count"), "symbols_sample": syms[:100],
            "strings_sample": r.get("strings", [])[:100]}


def il2cpp_rva_patch(sid, method_or_class: str, new_return: str = "ret"):
    """C# 方法/类 → 尝试 RVA 定位 + patch 说明。"""
    reg = _req(sid)
    if shutil.which(il2cpp.IL2CPP_DUMPER_ENV and os.environ.get(il2cpp.IL2CPP_DUMPER_ENV, "")) or os.environ.get(il2cpp.IL2CPP_DUMPER_ENV):
        return {"rva_status": "via_il2cpp_dumper", "note": "Il2CppDumper 已配置，可取精确 RVA 并 patch"}
    return {"target": method_or_class, "rva_status": "pending_il2cpp_dumper",
            "patch_hint": f"C# {method_or_class} 置 {new_return}",
            "note": "精确 RVA 需 Il2CppDumper(设 R2B_IL2CPP_DUMPER)；否则出 DummyTypes 供参考"}


def il2cpp_gameplay_scan(sid, keywords: str = None):
    """游戏逻辑关键词扫描（伤害/血量/武器/命中/命中倍数等）。"""
    reg = _req(sid)
    kws = (keywords or "damage,health,ammo,aim,bullet,enemy,player,weapon,shoot,reload,"
                  "accuracy,headshot,kill,score,mana,stamina,hit,attack,crit,level,coin,currency").split(",")
    kws = [k.strip() for k in kws if k.strip()]
    hits = {}
    for s in reg["strings"] + reg["methods"]:
        low = s.lower()
        for k in kws:
            if k in low:
                hits.setdefault(k, []).append(s)
    return {"keywords_hit": {k: v[:20] for k, v in hits.items()},
            "total": sum(len(v) for v in hits.values()),
            "note": "命中可接 Il2Cpp_RVA_Patch / Fr_Trace 验证"}


def il2cpp_export(sid, out_dir: str = None):
    reg = _req(sid)
    out_dir = out_dir or (reg.get("so") or "il2cpp_out") + ".il2cpp"
    res = {"types": reg["types"], "methods": reg["methods"], "strings": reg["strings"],
           "unity_version": reg.get("unity_version"), "rva_status": "pending_il2cpp_dumper"}
    paths = il2cpp.write_triad(res, out_dir)
    return {"out": out_dir, "files": paths,
            "triad": {"script_json": paths.get("script_json"), "dummy": paths.get("dummy"),
                      "string_json": paths.get("string_json")}}


def il2cpp_close(sid):
    IL2REG.pop(sid, None)
    return {"closed": True, "session_id": sid}


def il2cpp_list_sessions():
    return [{"session_id": k, "unity_version": v.get("unity_version"),
             "types": len(v.get("types", [])), "methods": len(v.get("methods", []))}
            for k, v in IL2REG.items()]


# ============ Il2Cpp 深度扩展（16 工具，按 Unity IL2CPP 逆向完整能力面） ============
def il2cpp_metadata_parse(sid):
    """global-metadata.dat 完整结构尽力解析（magic/blob 偏移/各表数量）。"""
    reg = _req(sid)
    import struct
    data = open(reg["metadata"], "rb").read() if reg.get("metadata") else b""
    res = {"magic": "0x" + data[:4].hex() if len(data) >= 4 else None, "size": len(data)}
    if len(data) >= 4:
        # Il2CppGlobalMetadataHeader：version + 一串 uint32（各 blob 的 offset/size）
        version = struct.unpack("<i", data[:4])[0]
        res["version_int"] = version
        # 各表数量从已提取结果回填
        res["type_count"] = len(reg["types"])
        res["method_count"] = len(reg["methods"])
        res["string_count"] = len(reg["strings"])
    res["note"] = "精确 blob 偏移/RVA 需 Il2CppDumper(按 v%d fork)；本工具出结构概览" % (res.get("version_int", 0))
    return res


def il2cpp_type_defs(sid, filter: str = None):
    """全量类型定义 + 继承启发（基类/泛型识别）。"""
    reg = _req(sid)
    out = []
    for t in reg["types"]:
        base = None
        if "List" in t and "`" in t:
            base = "System.Collections.Generic.List`1"
        elif t.startswith("System.") and "Exception" in t:
            base = "System.Exception"
        elif "MonoBehaviour" in t:
            base = "UnityEngine.MonoBehaviour"
        out.append({"type": t, "base": base, "generic": "`" in t})
    if filter:
        out = [o for o in out if filter.lower() in o["type"].lower()]
    return {"count": len(out), "type_defs": out[:2000]}


def il2cpp_field_defs(sid, filter: str = None):
    """字段名提取（metadata strings 里短标识，近似）。"""
    reg = _req(sid)
    fields = [s for s in reg["strings"]
              if re.match(r"^[a-z_][A-Za-z0-9_]{1,40}$", s) and "." not in s]
    if filter:
        fields = [f for f in fields if filter.lower() in f.lower()]
    return {"fields": list(dict.fromkeys(fields))[:2000], "note": "字段名从 strings blob 近似；精确偏移需 Il2CppDumper"}


def il2cpp_assemblies(sid):
    """程序集/模块前缀统计。"""
    reg = _req(sid)
    from collections import Counter
    pre = Counter()
    for t in reg["types"]:
        top = t.split(".")[0] if "." in t else t
        pre[top] += 1
    return {"assemblies_hint": dict(pre.most_common(50)),
            "note": "顶层命名空间近似程序集；精确程序集引用需 metadata 的 assemblies blob"}


def il2cpp_namespaces(sid):
    """命名空间统计。"""
    reg = _req(sid)
    from collections import Counter
    ns = Counter()
    for t in reg["types"]:
        if "." in t:
            ns[".".join(t.split(".")[:-1])] += 1
    return {"namespaces": dict(ns.most_common(100))}


def il2cpp_symbol_restore(sid):
    """全量 C# 方法 → 可读符号清单（导入 r2/IDA 用）。"""
    reg = _req(sid)
    return {"symbols": list(dict.fromkeys(reg["methods"]))[:5000],
            "count": len(reg["methods"]),
            "note": "可读符号名；RVA 由 Il2CppDumper 补全后 af 到 r2"}


def il2cpp_rva_table(sid):
    """方法 → RVA 表。二进制解析成功则精确，否则 pending。"""
    reg = _req(sid)
    if reg.get("methods_rva"):
        base = reg.get("imageBase", 0)
        return {"rva_status": "resolved", "count": len(reg["methods_rva"]),
                "table": [{"method": m["name"], "rva": m["rva"], "abs": base + m["rva"]}
                          for m in reg["methods_rva"]],
                "note": "精确 RVA 从 global-metadata.dat 二进制解析；r2: af @abs"}
    if os.environ.get(il2cpp.IL2CPP_DUMPER_ENV):
        return {"rva_status": "via_il2cpp_dumper", "note": "设了 R2B_IL2CPP_DUMPER"}
    return {"rva_status": "pending", "methods": len(reg["methods"]),
            "note": "无二进制结构，需 Il2CppDumper 或真实 metadata",
            "table": [{"method": m, "rva": None} for m in reg["methods"][:500]]}


def il2cpp_dummy_dll(sid, out_dir: str = None):
    """生成还原 C# 类型/方法骨架（dummy）。"""
    reg = _req(sid)
    out_dir = out_dir or (reg.get("so") or "il2cpp") + ".dummy"
    import os as _os
    _os.makedirs(out_dir, exist_ok=True)
    p = _os.path.join(out_dir, "DummyTypes.cs")
    with open(p, "w") as f:
        f.write("// R2B Dummy C#（global-metadata.dat 还原）\n")
        for t in reg["types"][:3000]:
            base = t.replace(".", "_")
            f.write(f"class {base}\n{{ /* {t} */\n")
            for m in [m for m in reg["methods"] if t in m][:30]:
                f.write(f"  {m.split('::')[-1].replace('.', '_')}();\n")
            f.write("}\n")
    return {"dummy": p, "types": len(reg["types"]), "methods": len(reg["methods"])}


def il2cpp_csharp_source(sid, out_dir: str = None):
    """生成 C# 源码骨架（类+方法签名）。"""
    reg = _req(sid)
    import os as _os
    out_dir = out_dir or (reg.get("so") or "il2cpp") + ".cs"
    _os.makedirs(out_dir, exist_ok=True)
    p = _os.path.join(out_dir, "CSharpSource.cs")
    with open(p, "w") as f:
        f.write("// R2B 还原 C# 源码骨架（逻辑需人工/Il2CppDumper DummyDLL 补全）\n")
        seen = set()
        for t in reg["types"]:
            ns, name = (t.rsplit(".", 1) + [""])[:2] if "." in t else ("", t)
            key = name
            if key in seen:
                continue
            seen.add(key)
            f.write(f"namespace {ns}\n{{ public class {name}\n{{\n")
            for m in [x for x in reg["methods"] if x.endswith("::" + name) or name in x][:20]:
                f.write(f"  // {m}\n  public object {m.split('::')[-1].replace('.', '_')}();\n")
            f.write("}}\n}\n")
    return {"source": p, "note": "方法体为空壳；真实逻辑需 DummyDLL + Il2CppDumper"}


def il2cpp_import_ida(sid, out_dir: str = None):
    """生成 IDA import 脚本（把 C# 方法名 af 到对应 RVA）。"""
    reg = _req(sid)
    out_dir = out_dir or (reg.get("so") or "il2cpp") + ".ida"
    import os as _os
    _os.makedirs(out_dir, exist_ok=True)
    p = _os.path.join(out_dir, "import_il2cpp.py")
    with open(p, "w") as f:
        f.write("# R2B → IDA 导入脚本（RVA 由 Il2CppDumper script.json 填）\n")
        f.write("import idc\n")
        for m in reg["methods"][:500]:
            nm = m.replace(".", "_").replace("::", "_").replace("`", "T")[:64]
            f.write(f"# idc.SetName(0xRVA_{m.replace('::','_')}, '{nm}', idc.SN_NOCHECK)\n")
    return {"script": p, "note": "填 RVA 后在 IDA 跑；RVA 需 Il2CppDumper"}


def il2cpp_import_r2(sid, out_dir: str = None):
    """生成 r2 导入脚本（ff 函数 + 重命名 C# 方法名）。"""
    reg = _req(sid)
    out_dir = out_dir or (reg.get("so") or "il2cpp") + ".r2"
    import os as _os
    _os.makedirs(out_dir, exist_ok=True)
    p = _os.path.join(out_dir, "import_il2cpp.r2")
    with open(p, "w") as f:
        f.write("# R2B → radare2 导入（RVA 由 Il2CppDumper script.json 填）\n")
        for m in reg["methods"][:500]:
            nm = m.replace(".", "_").replace("::", "_").replace("`", "T")[:64]
            f.write(f"# ff {len(m)} @ RVA_{m.replace('::','_')}\\naf @ RVA_{m.replace('::','_')}\nafn {nm} @ RVA_{m.replace('::','_')}\n")
    return {"script": p, "note": "取消注释+填 RVA 后 r2 -c 导入"}


def il2cpp_find_type(sid, name: str):
    reg = _req(sid)
    hits = [t for t in reg["types"] if name.lower() in t.lower()]
    return {"name": name, "hits": hits[:200]}


def il2cpp_find_method(sid, name: str):
    reg = _req(sid)
    hits = [m for m in reg["methods"] if name.lower() in m.lower()]
    return {"name": name, "hits": hits[:200]}


def il2cpp_find_field(sid, name: str):
    reg = _req(sid)
    hits = [s for s in reg["strings"] if re.match(r"^[a-z_][A-Za-z0-9_]{1,40}$", s) and name.lower() in s.lower()]
    return {"name": name, "hits": list(dict.fromkeys(hits))[:200]}


def il2cpp_cheatable_scan(sid, keywords: str = None):
    """可修改数值关键词（血量/弹药/金币/倍率/概率/经验）。"""
    reg = _req(sid)
    kws = (keywords or "health,life,ammo,bullet,coin,cash,gold,credits,money,price,rate,prob,"
                      "probability,exp,xp,damage,dps,shield,speed,velocity,drop,loot,luck,weapon,"
                      "score,level,kill,magazine,reload,reserve,max_health,mana").split(",")
    kws = [k.strip() for k in kws if k.strip()]
    corpus = list(dict.fromkeys(reg["strings"] + reg["methods"]))
    hits = {}
    for s in corpus:
        low = s.lower()
        for k in kws:
            if k in low:
                hits.setdefault(k, []).append(s)
    return {"cheatable_keywords": {k: v[:15] for k, v in hits.items()},
            "total": sum(len(v) for v in hits.values()),
            "note": "命中后 → Il2Cpp_RVA_Patch / Fr_Trace 验证修改"}


def il2cpp_anticheat_scan(sid, keywords: str = None):
    """校验/反作弊/完整性点（verify/sign/license/root/debug）。"""
    reg = _req(sid)
    kws = (keywords or "verify,check,valid,validate,sign,hash,md5,sha,crypto,encrypt,"
                      "license,activ,trial,integrity,root,jailbreak,debug,cheat,anticheat,hook,protect,guard").split(",")
    kws = [k.strip() for k in kws if k.strip()]
    corpus = list(dict.fromkeys(reg["strings"] + reg["methods"]))
    hits = {}
    for s in corpus:
        low = s.lower()
        for k in kws:
            if k in low:
                hits.setdefault(k, []).append(s)
    return {"anticheat_points": {k: v[:15] for k, v in hits.items()},
            "total": sum(len(v) for v in hits.values()),
            "note": "这些是 patch/绕过的候选点"}
