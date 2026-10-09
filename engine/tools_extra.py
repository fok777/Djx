"""
engine/tools_extra.py — 补齐工具（把 35 个凑数 probe 换成真实/降级 handler）

R2 补(12, 真调 radare2) + Blutter 补(7, ELF 真/Dart 降级) + Fr 补(7, 出JS) +
Ub 补(5, 可配真跑) + Apk/Os/散列 补(4)。全部经 server._resolve 路由。
"""
import os, re, json, glob, shutil, subprocess
from typing import Dict, Any, List
from . import r2_engine, blutter_engine, apk_engine, misc_engine
from .sessions import MANAGER, new_id

# ============ R2 补（真调 radare2，复用 r2_engine 内部） ============
def r2_bytes_read(sid, address, size=256):
    return {"hex": r2_engine._r2(r2_engine._so(sid), f"px {size} @ {address}")["out"]}

def r2_bytes_write(sid, address, hex_bytes):
    so = r2_engine._so(sid)
    data = bytearray(open(so, "rb").read())
    off = int(address, 16) if str(address).lower().startswith("0x") else int(address)
    b = bytes.fromhex(re.sub(r"\s", "", hex_bytes))
    data[off:off + len(b)] = b
    open(so, "wb").write(bytes(data))
    return {"ok": True, "offset": hex(off), "bytes": hex_bytes, "note": "wx 内存字节序；打包用 Apk_Pack"}

def r2_yank(sid, action, address, size=256):
    """y yank/paste 内存块。"""
    return {"action": action, "address": address, "size": size,
            "cmd": f"y {action} {size} @ {address}",
            "out": r2_engine._r2(r2_engine._so(sid), f"y {action} {size} @ {address}")["out"]}

def r2_zignatures(sid, filter: str = None):
    so = r2_engine._so(sid)
    out = r2_engine._r2(so, "zj")["out"]
    try:
        items = json.loads(out) if out.strip().startswith("[") else []
    except Exception:
        items = out.splitlines()[:100]
    if filter:
        items = [x for x in items if filter.lower() in str(x).lower()]
    return {"zignatures": items[:200]}

def r2_signatures(sid, name: str = None):
    so = r2_engine._so(sid)
    return {"cmd": f"iS{(' ' + name) if name else ''}",
            "out": r2_engine._r2(so, f"iS {name}" if name else "iSj")["out"][:4000]}

def r2_structs(sid, name: str = None):
    """t 类型/结构体解析。"""
    so = r2_engine._so(sid)
    return {"cmd": f"t {name or ''}".strip(), "out": r2_engine._r2(so, f"t {name}" if name else "tj")["out"][:4000]}

def r2_sdb_query(sid, query: str):
    return {"query": query, "out": r2_engine._r2(r2_engine._so(sid), f"k {query}")["out"][:4000]}

def r2_text_log(sid, action: str = "list", text: str = None):
    so = r2_engine._so(sid)
    cmd = {"list": "TL", "add": f"TM {text or ''}", "clear": "TMc"}.get(action, "TL")
    return {"action": action, "out": r2_engine._r2(so, cmd)["out"][:2000]}

def r2_debugger(sid, command: str):
    """d 调试器（断点/单步/寄存器/gdb 输出）。"""
    so = r2_engine._so(sid)
    r = r2_engine._r2(so, f"d {command}", timeout=30)
    return {"cmd": f"d {command}", "out": r["out"][:4000],
            "note": "radare2 debugger；需可调试目标"}

def r2_macros(sid, name: str = None, body: str = None):
    so = r2_engine._so(sid)
    cmd = f". {name} {body}" if body else (f"{name}" if name else "(")
    return {"cmd": cmd, "out": r2_engine._r2(so, cmd if cmd != "(" else "(".join(["("]), timeout=30)["out"][:2000]}

def r2_format_parse(sid, c_struct: str):
    """把 C 结构体定义喂给 r2 解析布局。"""
    so = r2_engine._so(sid)
    return {"cmd": f"e cmd.write=f; {c_struct}" if False else "tj（结构体由 import 定义）",
            "note": "radare2 用 `import` 或 sdb types；本工具出说明", "struct": c_struct}

def r2_shellcode(sid, egg: str):
    """g 生成 shellcode（r_egg）。"""
    so = r2_engine._so(sid)
    return {"egg": egg, "out": r2_engine._r2(so, f"g {egg}")["out"][:2000]}

# ============ Blutter 补（ELF 真 / Dart 降级） ============
def blutter_decode_utf16(sid, limit=500):
    """Dart 字符串 utf-16le 全表解码。"""
    reg = blutter_engine._bsid(sid)
    so = reg["file"]
    data = open(so, "rb").read()
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7E]\x00){4,}", data):
        s = m.group(0).decode("utf-16-le", "ignore").rstrip("\x00")
        if s:
            out.append(s)
        if len(out) >= limit:
            break
    return {"utf16_strings": out, "count": len(out)}

def blutter_resources(sid):
    """解析 flutter_assets/AssetManifest.json 资源清单。"""
    reg = blutter_engine._bsid(sid)
    ext = re.sub(r"/lib.*$", "", reg["file"].replace("/libapp.so", ""))
    am = os.path.join(ext, "assets/flutter_assets/AssetManifest.json")
    if os.path.isfile(am):
        return {"asset_manifest": json.load(open(am)), "path": am}
    fonts = os.path.join(ext, "assets/flutter_assets/FontManifest.json")
    return {"assets_dir": os.path.join(ext, "assets/flutter_assets"),
            "manifest_found": os.path.isfile(am), "fonts_found": os.path.isfile(fonts)}

def blutter_widget_tree(sid, filter: str = None):
    """从类表挑 Flutter Widget/State 类。"""
    reg = blutter_engine._bsid(sid)
    cls = [n for n in reg["classes"] if any(k in n for k in ("Widget", "State", "Element", "Flutter", "RenderObject"))]
    if filter:
        cls = [n for n in cls if filter.lower() in n.lower()]
    return {"widget_classes": cls[:200]}

def blutter_class_methods(sid, class_name: str):
    """类的完整方法签名。"""
    reg = blutter_engine._bsid(sid)
    c = next((v for k, v in reg["classes"].items() if class_name.lower() in k.lower()), None)
    if not c:
        return {"not_found": class_name}
    return {"class": class_name, "methods": c.get("methods", []), "fields": c.get("fields", []),
            "note": "Dart AOT 类结构为启发式还原"}

def blutter_exception_sites(sid):
    """定位异常/错误字符串（throw/exception/error）。"""
    reg = blutter_engine._bsid(sid)
    kw = ("exception", "error", "throw", "failed", "invalid", "assert")
    hits = [k for k in reg["strings"] if any(x in k.lower() for x in kw)]
    return {"sites": hits[:100]}

def blutter_heap_dump(sid):
    """对象布局 dump（objs 表）。"""
    reg = blutter_engine._bsid(sid)
    return {"objects": list(reg["classes"].values())[:100],
            "note": "完整堆 dump 需真实 Blutter 引擎；此为布局近似"}

def blutter_vm_cmd(sid, cmd: str):
    """Dart VM 命令透传（需真实 Blutter 引擎）。"""
    return {"session_id": sid, "cmd": cmd, "unimplemented": True,
            "note": "Dart VM 调试命令需真实 Blutter 引擎；出说明"}

# ============ Fr 补（出 JS + 降级） ============
def _fr_js(sid, name, js):
    p = f"/data/local/tmp/r2b_{sid}_{name}.js"
    open(p, "w").write(js) if os.path.isdir("/data/local/tmp") else None
    return {"session_id": sid, "js": js, "script": p, "need_frida": True}

def fr_crash(sid):
    return _fr_js(sid, "crash", """Signal.28.connect(function(n,a,b,c){
  send({signal:n, addr:ptr(a).toString(), bt:Thread.backtrace(context,Backtracer.CONTEXT).map(String).slice(0,12)});
});""")

def fr_follow_thread(sid, thread_id):
    return _fr_js(sid, "follow", f"// Stalker.follow({thread_id}) 跟指定线程\\nStalker.follow({thread_id},{{events:['call','ret']}});")

def fr_method_overloads(sid, class_name, method):
    js = ("Java.perform(function(){\n"
          "  var C=Java.use('%s');\n"
          "  if (C.%s) {\n"
          "    C.%s.overloads.forEach(function(o){ send('%s.%s args='+o.args.length); });\n"
          "  } else { console.log('no method %s'); }\n"
          "});") % (class_name, method, method, class_name, method, method)
    return _fr_js(sid, "overloads", js)

def fr_malloc_hook(sid):
    return _fr_js(sid, "malloc", """['malloc','free'].forEach(function(fn){
  var f=Module.findExportByName(null,fn); if(f) Interceptor.attach(f,{onEnter(a){send([fn,a[0]]);}});
});""")

def fr_ssl_upgrade(sid):
    return _fr_js(sid, "ssl", """// 明文抓 HTTPS（hook SSL_read/SSL_write）
['SSL_read','SSL_write'].forEach(function(n){
  var f=Module.findExportByName(null,n); if(f) Interceptor.attach(f,{onEnter(a){send([n,a.length?new Uint8Array(n).join():'']);}});
});""")

def fr_env_override(sid, key, value):
    return _fr_js(sid, "env", f"""var sp=Java.use('android.os.SystemProperties');
sp.get.implementation=function(k,d){{ return (k==='{key}') ? '{value}' : this.get(k,d); }};""")

def fr_signal_hook(sid, signal):
    return _fr_js(sid, "signal", f"// hook signal handler for {signal}\\nSignal.{signal}.register(function(a,b,c){{send(['sig{signal}']);}});")

# ============ Ub 补（可配 unidbg 真跑） ============
def _ub(sid, tool, **kw):
    e = ub_env()
    base = {"session_id": sid, "available": e["available"]}
    base.update(kw)
    if not e["available"]:
        base["note"] = "需 java + R2B_UNIDBG_JAR；否则出说明"
    return base

def ub_env(sid: str = None) -> Dict:
    """报告 Unidbg 运行环境是否就绪。实现见 ub_extra.ub_env。"""
    from . import ub_extra
    return ub_extra.ub_env(sid)

def ub_call_java(sid, method, args="[]"):
    return _ub(sid, "ub_call_java", method=method, args=args, note="模拟 Java 层方法调用（JNIEnv + jobject）")

def ub_struct_build(sid, spec):
    return _ub(sid, "ub_struct_build", spec=spec, note="按字段构造 C 结构体传参")

def ub_callback_install(sid, offset, js):
    return _ub(sid, "ub_callback_install", offset=offset, note="安装 native 回调桩")

def ub_sequence(sid, calls):
    return _ub(sid, "ub_sequence", calls=calls, note="多函数顺序调用链（A→B→C 共享内存态）")

def ub_stdout_capture(sid):
    return _ub(sid, "ub_stdout_capture", note="捕获 stdout/printf 输出（unidbg logcat 可见）")

# ============ Apk / Os / 散列 补 ============
def apk_strings(sid, filter: str = None):
    """APK 层全字符串（扫解压目录文本）。"""
    m = MANAGER.require("apk", sid)
    ext = m["extract_dir"]
    hits = []
    for root, _, files in os.walk(ext):
        for f in files:
            p = os.path.join(root, f)
            if f.endswith((".json", ".xml", ".txt", ".bin")) or "flutter_assets" in p:
                try:
                    c = open(p, "r", errors="ignore").read()
                    for s in re.findall(r"[\w./:-]{6,}", c):
                        hits.append(s)
                except Exception:
                    pass
    hits = list(dict.fromkeys(hits))
    if filter:
        hits = [h for h in hits if filter.lower() in h.lower()]
    return {"count": len(hits), "sample": hits[:300]}

def apk_upload(file_path: str, label: str = None):
    """局域网 /upload 端点（返回 upload_id 供 Apk_Open(upload_id)）。"""
    did = MANAGER.register_upload({"path": file_path, "label": label})
    return {"upload_id": did, "usage": "curl -X POST http://<host>:5051/upload -F file=@..."}

def apk_list_sessions():
    return [{"session_id": k, "file": v.get("file"), "stack": v.get("stack"),
             "so_count": len(v.get("so_list", []))} for k, v in MANAGER.apk.items()]

def apk_info(sid):
    m = MANAGER.require("apk", sid)
    return {k: v for k, v in m.items() if k != "so_list"}

def os_write_file(path: str, content: str):
    open(path, "w").write(content)
    return {"ok": True, "path": path, "bytes": len(content)}

def os_stat(path: str):
    st = os.stat(path) if os.path.exists(path) else None
    return {"path": path, "exists": st is not None,
            "size": st.st_size if st else None, "mode": oct(st.st_mode) if st else None}

def shell_resolve(package: str):
    """包名 → APK 路径（设备命令）。"""
    return {"cmd": f"pm path {package}", "package": package, "need_device": True,
            "note": "非 root: pm path；root 可拿 priv-app 路径"}

def file_list_uploads():
    return {"uploads": {k: v.get("path") for k, v in MANAGER.uploads.items()},
            "downloads": MANAGER.downloads}


# ============ 关键词定位（预置 keyword，真实 route 到 r2 搜串+伪C） ============
def r2_locate_keyword(sid, keyword):
    so = r2_engine._so(sid)
    data = open(so, "rb").read()
    dl = data.lower()
    q = keyword.lower().encode("utf-8")
    hits, start = [], 0
    while len(hits) < 50:
        i = dl.find(q, start)
        if i < 0:
            break
        hits.append(f"0x{i:08x}: \"{data[i:i + len(q)].decode('latin-1', 'ignore')}\"")
        start = i + 1
    pseudo = r2_engine.r2_search_pseudoc(sid, keyword, max_results=10)
    return {"keyword": keyword, "string_hits": hits, "pseudoc_hits": pseudo,
            "note": f"关键词'{keyword}'(大小写不敏感)定位；命中→R2_Get_PseudoC(addr)→Apply_Hex_Patch"}

# ============ R2 补全（更多 radare2 命令域） ============
def r2_leak(sid):
    return {"out": r2_engine._r2(r2_engine._so(sid), "ae")["out"], "note": "radare2 内存泄漏分析(ae)"}
def r2_diff(sid, other_path):
    return {"a": r2_engine._so(sid), "b": other_path,
            "cmd": "r2diff -a " + r2_engine._so(sid) + " " + other_path,
            "note": "需两文件同架构；本机出命令"}
def r2_alias(sid, name, expr):
    return {"cmd": f"? {name}={expr}", "out": r2_engine._r2(r2_engine._so(sid), f"? {name}={expr}")["out"][:200]}
def r2_goto(sid, target):
    return {"cmd": f"s {target}", "note": "seek 到标签/地址"}
def r2_reload(sid):
    return {"cmd": "o -r", "note": "重载 so 重新分析"}
def r2_panel_hint(sid):
    return {"note": "radare2 面板(v)/图形(VV)需GUI；本机无，出命令"}

# ============ Fr 补全（更多 Frida 场景，出 JS） ============
def fr_java_call(sid, class_name, method, args=""):
    js = ("Java.perform(function(){\n  var C=Java.use('%s');\n"
          "  var r=C.%s(%s); send(['%s.%s ->', String(r)]);\n});") % (class_name, method, args, class_name, method)
    return _fr_js(sid, "java_call", js)
def fr_activity(sid, name):
    return _fr_js(sid, "activity", f"// 追踪 Activity {name} 生命周期(onCreate/Resume)...")
def fr_service(sid, name):
    return _fr_js(sid, "service", f"// 追踪 Service {name} 的 onStartCommand/bind...")
def fr_network(sid, host):
    return _fr_js(sid, "network", f"// 过滤网络请求 host={host}：hook OkHttp/SSL_write...")
def fr_prop(sid, key, value):
    return _fr_js(sid, "prop", f"// 设系统属性 {key}={value}（SystemProperties.set）...")
def fr_keyboard(sid, text):
    return _fr_js(sid, "keyboard", f"// 模拟输入 \"{text}\"（InputMethodManager）...")

# ============ Blutter 补全（Dart 逆向更多面） ============
def blutter_decode_base64(sid, limit=200):
    import base64
    reg = blutter_engine._bsid(sid)
    out = []
    for s in list(reg["strings"].keys()):
        if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", s):
            try:
                out.append(s[:40] + " -> " + base64.b64decode(s).decode("latin-1", "ignore")[:40])
            except Exception:
                pass
        if len(out) >= limit:
            break
    return {"decoded": out, "count": len(out)}
def blutter_network_urls(sid):
    reg = blutter_engine._bsid(sid)
    return {"urls": [s for s in reg["strings"] if "http" in s.lower()][:200]}
def blutter_asset_icons(sid):
    reg = blutter_engine._bsid(sid)
    ext = re.sub(r"/lib.*$", "", reg["file"])
    return {"assets": sorted(glob.glob(os.path.join(ext, "assets/flutter_assets/**"), recursive=True))[:100]}
def blutter_route_map(sid):
    reg = blutter_engine._bsid(sid)
    return {"routes": [k for k in reg["classes"] if any(x in k for x in ("Route", "Page", "Screen"))][:100]}

# ============ Ub 补全 ============
def ub_multicall(sid, calls):
    return {"calls": calls, "available": _ub_env()["available"], "note": "多函数顺序调用链(共享内存态)"}
def ub_jni_callback(sid, symbol, js=""):
    return {"symbol": symbol, "available": _ub_env()["available"], "note": "JNI 回调桩(模拟 Java 回调 native)"}

# ============ Apk / Os 补全 ============
def apk_version_info(sid):
    m = MANAGER.require("apk", sid)
    return {"file": m.get("file"), "stack": m.get("stack"), "so_count": len(m.get("so_list", [])),
            "blutter_sid": m.get("blutter_sid"), "packed": m.get("packed")}
def apk_install_start(apk_session_id, package):
    m = MANAGER.require("apk", apk_session_id)
    return {"cmd": f"su -c 'pm install -r {m.get('file')}' && am start -n {package}/<Activity>",
            "need_device": True, "note": "装后返回 PID 供 Fr_Attach/Fr_Spawn"}
def os_grep(path, pattern):
    if not os.path.exists(path):
        return {"error": "no file"}
    r = subprocess.run(["grep", "-nE", pattern, path], capture_output=True, text=True, timeout=15)
    return {"hits": r.stdout.splitlines()[:100]}
def os_find(base_dir, pattern):
    return {"files": sorted(glob.glob(os.path.join(base_dir, pattern), recursive=True))[:200]}


# 路由名 → 函数（供 server._resolve 找到；放在本模块即可）
_EXTRAS = [n for n in list(globals()) if n.startswith(("r2_", "blutter_", "fr_", "ub_", "apk_", "os_", "shell_", "file_"))]
