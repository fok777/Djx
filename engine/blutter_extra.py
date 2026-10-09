"""
engine/blutter_extra.py — Blutter_* 补齐的 34 个结构化查询工具

现行 blutter_engine 已覆盖 32 个工具，但缺少「看清一个类长什么样」那层：
字段、方法、继承、枚举、路由、Widget 等结构化信息。本模块补齐。

⚠ 诚实边界：Dart AOT 快照本身不带完整类元数据，精确重建要靠开源 Blutter
（github.com/worawit/blutter）产出 asm/ 与 pp.txt。未装 Blutter 时，本模块基于
已提取的 classes / funcs / strings 做**启发式重建**——命名约定
（Class.method / Class.field）与字符串特征匹配，能用于定位与导航，
但不保证与源码 100% 一致。每条返回带 `heuristic` 标记。
"""
import re
from typing import Dict, Any, List

from .sessions import new_id
from .blutter_engine import BLUTTERREG, _reg

# ---------- 内部工具 ----------


def _bsid(sid):
    if sid not in BLUTTERREG:
        raise KeyError(f"unknown blutter session {sid}; 先 Blutter_Analyze")
    return _reg(sid)


def _mark(d: Dict, how: str = "heuristic") -> Dict:
    """给结果打上「推断来源」标记，避免把启发式结果当真值。"""
    d["heuristic"] = True
    d["source"] = how
    return d


def _split_owner(name: str):
    """'package.Class.method' -> ('Class', 'method')；解析不出返回 (None, name)。"""
    parts = name.split(".")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, name


def _cls_of(reg: Dict, name: str):
    """按类名取类，支持简写模糊匹配。"""
    if name in reg["classes"]:
        return reg["classes"][name]
    low = name.lower()
    for k, v in reg["classes"].items():
        if k.lower().endswith(low) or low in k.lower():
            return v
    return None


# ---------- 符号与结构 ----------

def blutter_symbols(sid: str, filter: str = None, kind: str = None,
                    max_results: int = 200) -> Dict:
    """列出全部符号（类 + 函数 + 字符串常量），可按类型过滤。"""
    reg = _bsid(sid)
    items: List[Dict] = []
    if not kind or kind == "class":
        items += [{"kind": "class", "name": n} for n in reg["classes"]]
    if not kind or kind == "func":
        items += [{"kind": "func", "name": n, "offset": f.get("offset")}
                  for n, f in reg["funcs"].items()]
    if not kind or kind == "string":
        items += [{"kind": "string", "name": n, "offset": o}
                  for n, o in list(reg["strings"].items())[:5000]]
    if filter:
        fl = filter.lower()
        items = [i for i in items if fl in i["name"].lower()]
    return _mark({"session_id": sid, "kind": kind or "all",
                  "total": len(items), "items": items[:max_results]},
                 "elf_symbols+strings")


def blutter_fields(sid: str, class_name: str = None, filter: str = None) -> Dict:
    """类的字段列表。Dart 字段名常以 _ 或小写开头，且带 Class. 前缀。"""
    reg = _bsid(sid)
    out: List[Dict] = []
    for s in reg["strings"]:
        owner, field = _split_owner(s)
        if not owner or not field:
            continue
        if not (field[:1].islower() or field.startswith("_")):
            continue
        if class_name and class_name.lower() not in owner.lower():
            continue
        if filter and filter.lower() not in field.lower():
            continue
        out.append({"class": owner, "field": field,
                    "offset": reg["strings"].get(s)})
    seen, uniq = set(), []
    for f in out:
        k = (f["class"], f["field"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return _mark({"session_id": sid, "class": class_name,
                  "total": len(uniq), "fields": uniq[:300]},
                 "string naming convention")


def blutter_methods(sid: str, class_name: str = None, filter: str = None) -> Dict:
    """类的方法列表（含符号偏移，可直接给 Fr_Native_Hook）。"""
    reg = _bsid(sid)
    out: List[Dict] = []
    for n, f in reg["funcs"].items():
        owner, meth = _split_owner(n)
        if class_name and owner and class_name.lower() not in owner.lower():
            continue
        if filter and filter.lower() not in n.lower():
            continue
        out.append({"class": owner, "method": meth, "full": n,
                    "offset": f.get("offset"), "size": f.get("size", 0)})
    return _mark({"session_id": sid, "class": class_name,
                  "total": len(out), "methods": out[:300]},
                 "elf dynsym + naming")


def blutter_method_detail(sid: str, method: str) -> Dict:
    """单个方法的详情：偏移、大小、所属类、可 hook 的 Frida 片段。"""
    reg = _bsid(sid)
    hit = None
    for n, f in reg["funcs"].items():
        if n == method or n.endswith("." + method) or method in n:
            hit = (n, f)
            break
    if not hit:
        return {"error": f"method not found: {method}", "session_id": sid}
    n, f = hit
    owner, meth = _split_owner(n)
    return _mark({
        "session_id": sid, "name": n, "class": owner, "method": meth,
        "offset": f.get("offset"), "size": f.get("size", 0),
        "frida": (f"Interceptor.attach(Module.findBaseAddress('libapp.so').add({f.get('offset')}), "
                  f"{{onEnter(a){{send('{meth} enter');}},onLeave(r){{send('{meth} leave');}}}});"
                  if f.get("offset") else None),
    }, "elf dynsym")


def blutter_inherits(sid: str, class_name: str) -> Dict:
    """类的继承链（父→祖父），基于 'Class:Parent' / 'Class extends' 字符串特征。"""
    reg = _bsid(sid)
    chain: List[str] = []
    cur = class_name
    for _ in range(12):
        parent = None
        for s in reg["strings"]:
            if s.startswith(cur + ":") or s.startswith(cur + " extends "):
                parent = s.split(":", 1)[-1].replace("extends ", "").strip()
                break
        if not parent or parent in chain:
            break
        chain.append(parent)
        cur = parent
    return _mark({"session_id": sid, "class": class_name,
                  "chain": chain, "depth": len(chain)},
                 "string pattern 'A:B'")


def blutter_superclass(sid: str, class_name: str) -> Dict:
    """直接父类。"""
    r = blutter_inherits(sid, class_name)
    r.pop("heuristic", None)
    return _mark({"session_id": sid, "class": class_name,
                  "superclass": r["chain"][0] if r["chain"] else None},
                 "string pattern 'A:B'")


# ---------- Dart 语言特性 ----------

_DART_KIND_PATTERNS = {
    "enum": (r"^[A-Z][A-Za-z0-9]*\.[A-Z][A-Z0-9_]*$", "全大写成员"),
    "const": (r"^k[A-Z]|^_[A-Z]", "k 前缀常量"),
    "mixin": (r"Mixin$|Mixin[A-Z]", "Mixin 后缀"),
    "extension": (r"^ext\.|^Extension", "Extension 标记"),
    "widget": (r"Widget$|Page$|View$|Screen$", "Widget/Page/View/Screen 后缀"),
    "async": (r"Async$|await|Future|Stream|Isolate", "异步特征"),
    "channel": (r"MethodChannel|EventChannel|BasicMessageChannel|platform_channel",
                "Platform Channel"),
    "isolate": (r"Isolate|spawn|SendPort|ReceivePort", "Isolate 并发"),
    "gc": (r"gc_|Gc|heap_|Heap|alloc", "GC/堆特征"),
    "closure": (r"Closure|closure|lambda|<anonymous>", "闭包特征"),
    "mirror": (r"Mirror|mirrors|reflect", "dart:mirrors 反射"),
    "typeargs": (r"<[A-Za-z0-9_,\s]+>$", "泛型参数"),
    "localizations": (r"[Ll]ocal|i18n|intl|Locale|strings_", "本地化资源"),
    "route": (r"^[A-Za-z0-9_/]*Route|Navigator|pushNamed|onGenerateRoute",
              "路由特征"),
}


def _scan_kind(reg: Dict, key: str, filter: str = None) -> List[Dict]:
    pat, how = _DART_KIND_PATTERNS[key]
    rx = re.compile(pat)
    out = []
    for s in reg["strings"]:
        if rx.search(s):
            if filter and filter.lower() not in s.lower():
                continue
            out.append({"name": s, "offset": reg["strings"].get(s)})
    for n, f in reg["funcs"].items():
        if rx.search(n):
            if filter and filter.lower() not in n.lower():
                continue
            out.append({"name": n, "offset": f.get("offset"), "kind": "func"})
    return out


def _kind_tool(key: str):
    def fn(sid: str, filter: str = None, max_results: int = 200) -> Dict:
        reg = _bsid(sid)
        how = _DART_KIND_PATTERNS[key][1]
        items = _scan_kind(reg, key, filter)
        return _mark({"session_id": sid, "kind": key, "rule": how,
                      "total": len(items), "items": items[:max_results]},
                     f"regex on strings: {how}")
    fn.__name__ = f"blutter_{key}"
    fn.__doc__ = f"扫描 {_DART_KIND_PATTERNS[key][1]} 相关符号。"
    return fn


blutter_enum = _kind_tool("enum")
blutter_const = _kind_tool("const")
blutter_mixin = _kind_tool("mixin")
blutter_extension = _kind_tool("extension")
blutter_widgets = _kind_tool("widget")
blutter_async = _kind_tool("async")
blutter_channel = _kind_tool("channel")
blutter_isolate = _kind_tool("isolate")
blutter_gc = _kind_tool("gc")
blutter_closure = _kind_tool("closure")
blutter_mirror = _kind_tool("mirror")
blutter_type_args = _kind_tool("typeargs")
blutter_localizations = _kind_tool("localizations")


def blutter_routes(sid: str, filter: str = None) -> Dict:
    """路由表：'/xxx' 形式路径 + Navigator 调用点。"""
    reg = _bsid(sid)
    routes, nav = [], []
    for s in reg["strings"]:
        if re.match(r"^/[A-Za-z0-9_\-/{}\[\]]{1,60}$", s):
            if filter and filter.lower() not in s.lower():
                continue
            routes.append({"route": s, "offset": reg["strings"].get(s)})
        elif "Navigator" in s or "pushNamed" in s:
            nav.append({"call": s, "offset": reg["strings"].get(s)})
    return _mark({"session_id": sid, "total": len(routes),
                  "routes": routes[:300], "navigator_calls": nav[:100]},
                 "regex ^/path + Navigator")


def blutter_implement(sid: str, class_name: str) -> Dict:
    """类实现了哪些接口 / 重写了哪些方法（基于 Class.method 命名聚合）。"""
    reg = _bsid(sid)
    c = _cls_of(reg, class_name)
    meths = [n for n in reg["funcs"] if n.lower().startswith(class_name.lower() + ".")]
    return _mark({"session_id": sid, "class": class_name,
                  "found": bool(c), "implemented_methods": meths[:200],
                  "count": len(meths)}, "func name prefix")


# ---------- 包 / 依赖 ----------

def blutter_package(sid: str, filter: str = None) -> Dict:
    """按 package: 前缀聚合出依赖包清单。"""
    reg = _bsid(sid)
    pkgs: Dict[str, int] = {}
    for s in reg["strings"]:
        m = re.match(r"^(package|dart|flutter):([a-z0-9_]+)", s)
        if m:
            key = f"{m.group(1)}:{m.group(2)}"
            pkgs[key] = pkgs.get(key, 0) + 1
            continue
        if "/" in s and s.count("/") >= 2 and not s.startswith("/"):
            head = s.split("/")[0]
            if re.match(r"^[a-z][a-z0-9_]{1,30}$", head):
                pkgs[head] = pkgs.get(head, 0) + 1
    items = [{"package": k, "refs": v} for k, v in
             sorted(pkgs.items(), key=lambda x: -x[1])]
    if filter:
        items = [i for i in items if filter.lower() in i["package"].lower()]
    return _mark({"session_id": sid, "total": len(items), "packages": items[:200]},
                 "string prefix aggregation")


def blutter_imports(sid: str, filter: str = None) -> Dict:
    """import 语句级别的依赖字符串。"""
    reg = _bsid(sid)
    out = []
    for s in reg["strings"]:
        if s.startswith(("package:", "dart:", "flutter:", "import ")):
            if filter and filter.lower() not in s.lower():
                continue
            out.append({"import": s, "offset": reg["strings"].get(s)})
    return _mark({"session_id": sid, "total": len(out), "imports": out[:300]},
                 "string prefix")


def blutter_lib(sid: str, filter: str = None) -> Dict:
    """native 库引用（.so 名）。"""
    reg = _bsid(sid)
    out = []
    for s in reg["strings"]:
        if s.endswith(".so") or "/lib" in s and s.endswith(".so"):
            if filter and filter.lower() not in s.lower():
                continue
            out.append({"lib": s, "offset": reg["strings"].get(s)})
    return _mark({"session_id": sid, "total": len(out), "libs": out[:200]},
                 "string suffix .so")


def blutter_plugin(sid: str, filter: str = None) -> Dict:
    """Flutter 插件（含 Plugin/Channel 注册点）。"""
    reg = _bsid(sid)
    out = []
    for s in reg["strings"]:
        if re.search(r"Plugin|registerWith|GeneratedPluginRegistrant", s):
            if filter and filter.lower() not in s.lower():
                continue
            out.append({"plugin": s, "offset": reg["strings"].get(s)})
    return _mark({"session_id": sid, "total": len(out), "plugins": out[:200]},
                 "regex Plugin/registerWith")


# ---------- 运行时 / 快照 ----------

def blutter_snapshot(sid: str) -> Dict:
    """AOT 快照元信息：版本、段大小、字符串/符号计数。"""
    reg = _bsid(sid)
    f = reg.get("file")
    size = None
    try:
        import os
        size = os.path.getsize(f) if f and __import__("os").path.isfile(f) else None
    except Exception:
        pass
    return _mark({
        "session_id": sid, "file": f, "file_size": size,
        "dart_version": reg.get("dart_version"),
        "classes": len(reg["classes"]), "funcs": len(reg["funcs"]),
        "strings": len(reg["strings"]), "pp_entries": len(reg["pp_table"]),
        "analyze_elapsed_s": reg.get("elapsed_s"),
    }, "elf header + parse stats")


def blutter_aot(sid: str) -> Dict:
    """判断是否 AOT 编译（含 _kDartIsolateSnapshotInstructions 等标志）。"""
    reg = _bsid(sid)
    flags = [s for s in reg["strings"]
             if "_kDart" in s or "SnapshotInstructions" in s or "IsolateSnapshot" in s]
    return _mark({"session_id": sid, "aot": bool(flags),
                  "flags": flags[:20],
                  "dart_version": reg.get("dart_version")},
                 "dart snapshot symbols")


def blutter_heap(sid: str, filter: str = None) -> Dict:
    """堆相关符号（分配/GC 入口），供内存分析定位。"""
    return blutter_gc(sid, filter)


def blutter_stack_trace(sid: str, filter: str = None) -> Dict:
    """异常/堆栈相关符号，用于定位崩溃点与 try-catch。"""
    reg = _bsid(sid)
    out = []
    for s in reg["strings"]:
        if re.search(r"Stack|Trace|Exception|Error|catch|throw", s):
            if filter and filter.lower() not in s.lower():
                continue
            out.append({"name": s, "offset": reg["strings"].get(s)})
    return _mark({"session_id": sid, "total": len(out), "items": out[:200]},
                 "regex Stack|Exception|Error")


# ---------- 查询 / 导航 ----------

def blutter_search(sid: str, query: str, kind: str = None,
                   max_results: int = 100) -> Dict:
    """跨类/函数/字符串统一搜索。"""
    reg = _bsid(sid)
    q = (query or "").lower()
    hits: List[Dict] = []
    if not kind or kind == "class":
        hits += [{"kind": "class", "name": n} for n in reg["classes"] if q in n.lower()]
    if not kind or kind == "func":
        hits += [{"kind": "func", "name": n, "offset": f.get("offset")}
                 for n, f in reg["funcs"].items() if q in n.lower()]
    if not kind or kind == "string":
        for n, o in reg["strings"].items():
            if q in n.lower():
                hits.append({"kind": "string", "name": n, "offset": o})
                if len(hits) >= max_results * 5:
                    break
    return _mark({"session_id": sid, "query": query,
                  "total": len(hits), "hits": hits[:max_results]}, "substring match")


def blutter_resolve(sid: str, address: str) -> Dict:
    """地址 → 符号（反查 pp_table 与函数偏移）。"""
    reg = _bsid(sid)
    a = (address or "").lower().rstrip("l")
    for e in reg["pp_table"]:
        if str(e.get("offset", "")).lower().rstrip("l") == a:
            return _mark({"session_id": sid, "address": address, "symbol": e}, "pp_table")
    try:
        ia = int(address, 16)
    except (ValueError, TypeError):
        return {"error": f"bad address: {address}", "session_id": sid}
    best = None
    for n, f in reg["funcs"].items():
        o = f.get("offset")
        if isinstance(o, str) and o.startswith("0x"):
            try:
                iv = int(o, 16)
            except ValueError:
                continue
            if iv <= ia and (best is None or iv > best[1]):
                best = (n, iv)
    if best:
        return _mark({"session_id": sid, "address": address,
                      "nearest_func": best[0], "func_offset": hex(best[1]),
                      "delta": hex(ia - best[1])}, "nearest symbol")
    return {"session_id": sid, "address": address, "symbol": None,
            "note": "未命中 pp_table 与函数表"}


def blutter_annotate(sid: str, filter: str = None) -> Dict:
    """批量生成 r2 注释脚本（afn/CC），把 Dart 符号写回反汇编。"""
    reg = _bsid(sid)
    cmds = []
    for e in reg["pp_table"]:
        if e.get("type") != "func":
            continue
        n, o = e.get("name"), e.get("offset")
        if not n or not o:
            continue
        if filter and filter.lower() not in n.lower():
            continue
        safe = re.sub(r"[^A-Za-z0-9_]", "_", n)[:60]
        cmds.append(f"afn {safe} {o}")
        cmds.append(f"CC {safe} @{o}")
    return _mark({"session_id": sid, "count": len(cmds),
                  "r2_commands": cmds[:1000]}, "pp_table -> afn/CC")


def blutter_inspect(sid: str, target: str) -> Dict:
    """给一个名字，自动判断它是类/方法/字段/字符串并给出对应详情。"""
    reg = _bsid(sid)
    if target in reg["classes"]:
        return _mark({"session_id": sid, "target": target, "type": "class",
                      **blutter_class_detail_view(reg, target)}, "registry lookup")
    if target in reg["funcs"]:
        return blutter_method_detail(sid, target)
    if target in reg["strings"]:
        return _mark({"session_id": sid, "target": target, "type": "string",
                      "offset": reg["strings"][target]}, "registry lookup")
    hits = blutter_search(sid, target, max_results=10)
    return _mark({"session_id": sid, "target": target, "type": "unknown",
                  "fuzzy_hits": hits.get("hits", [])}, "fuzzy fallback")


def blutter_class_detail_view(reg: Dict, name: str) -> Dict:
    """类的聚合视图（字段 + 方法 + 父类），供 inspect 复用。"""
    fields = blutter_fields_by_class(reg, name)
    meths = [n for n in reg["funcs"] if n.lower().startswith(name.lower() + ".")]
    parent = None
    for s in reg["strings"]:
        if s.startswith(name + ":"):
            parent = s.split(":", 1)[-1].strip()
            break
    return {"class": name, "fields": fields[:100], "methods": meths[:100],
            "superclass": parent}


def blutter_fields_by_class(reg: Dict, class_name: str) -> List[str]:
    out = []
    for s in reg["strings"]:
        owner, field = _split_owner(s)
        if owner and owner.lower() == class_name.lower() and \
           (field[:1].islower() or field.startswith("_")):
            out.append(field)
    return sorted(set(out))


def blutter_version_adapt(sid: str) -> Dict:
    """Dart 版本适配：报告版本并给出对应解析策略。"""
    reg = _bsid(sid)
    v = reg.get("dart_version")
    try:
        from . import engine_runtime as ER
        eng = ER.locate_blutter(v or "")
    except Exception:
        eng = None
    return _mark({"session_id": sid, "dart_version": v,
                  "matched_engine": eng,
                  "strategy": ("已装 Blutter，走精确解析" if eng
                               else "启发式 ELF 解析（类结构部分为推测）")},
                 "engine_runtime.locate_blutter")


def blutter_list_extra_sessions() -> Dict:
    """列出 blutter 会话（补齐版，含统计）。"""
    return {"sessions": [{"sid": k, "file": v.get("file"),
                          "classes": len(v.get("classes", {})),
                          "funcs": len(v.get("funcs", {})),
                          "strings": len(v.get("strings", {}))}
                         for k, v in BLUTTERREG.items()]}


# ---------- 别名：工具名小写化与函数名不一致时对齐 ----------
# Blutter_StackTrace -> blutter_stacktrace（而非 blutter_stack_trace）
blutter_stacktrace = blutter_stack_trace
# Blutter_TypeArgs -> blutter_typeargs（而非 blutter_type_args）
blutter_typeargs = blutter_type_args
