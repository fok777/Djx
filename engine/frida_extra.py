"""
engine/frida_extra.py — Fr_* 补齐的 8 个运行时操作工具

现行 frida_engine 有 33 个工具，缺内存读写、堆栈、Java eval、
gadget 模式、重载枚举这几块。本模块补齐。

⚠ 诚实边界：本环境通常无 frida-server。缺失时**不假装 hook 成功**，
一律产出可直接用 `frida -U -l script.js` 执行的 JS，并标 `"executed": false`。
"""
from typing import Dict, Any, List

from . import frida_engine
from .frida_engine import FRIDAREG, _fr_avail


def _fsid(sid):
    if sid not in FRIDAREG:
        raise KeyError(f"unknown frida session {sid}; 先 Fr_Attach/Fr_Spawn")
    return FRIDAREG[sid]


def _wrap(sid: str, name: str, js: str, note: str = None) -> Dict:
    """统一返回：能跑就跑，不能跑就给脚本。"""
    armed = _fr_avail().get("armed")
    out = {"session_id": sid, "tool": name,
           "executed": bool(armed),
           "environment": _fr_avail()}
    if armed:
        try:
            out["result"] = frida_engine.fr_eval(sid, js)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            out["js"] = js
    else:
        out["js"] = js
        out["run_with"] = "frida -U -f <pkg> -l script.js --no-pause"
        out["note"] = note or "无 frida-server，产出脚本供真机执行"
    return out


# ---------- 内存 ----------

def fr_read_bytes(sid: str, address: str, size: int = 64) -> Dict:
    """读进程内存。"""
    js = f'''
var ptr = ptr("{address}");
var buf = Memory.readByteArray(ptr, {size});
send({{op:"read_bytes", addr:"{address}", size:{size},
      hex: Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("")}});
'''
    return _wrap(sid, "Fr_Read_Bytes", js,
                 "读内存需真机 frida；脚本里可改 address 为模块基址+偏移")


def fr_patch_bytes(sid: str, address: str, hex_bytes: str,
                   restore: str = None) -> Dict:
    """改进程内存（运行时 patch，重启失效；持久化要用 Apply_Hex_Patch）。"""
    hb = (hex_bytes or "").replace(" ", "")
    js = f'''
var ptr = ptr("{address}");
Memory.protect(ptr, Process.pointerSize * 4, 'rwx');
var orig = Memory.readByteArray(ptr, {max(1, len(hb)//2)});
Memory.writeByteArray(ptr, [{", ".join(f"0x{hb[i:i+2]}" for i in range(0, len(hb), 2)) or "0x0"}]);
send({{op:"patch_bytes", addr:"{address}", wrote:{len(hb)//2}}});
'''
    if restore:
        rh = restore.replace(" ", "")
        js += f'''
// 恢复: Memory.writeByteArray(ptr("{address}"),
//   [{", ".join(f"0x{rh[i:i+2]}" for i in range(0, len(rh), 2))}]);
'''
    return _wrap(sid, "Fr_Patch_Bytes", js,
                 "运行时 patch，进程重启即失效；改 so 要用 Apply_Hex_Patch 后重打包")


def fr_heap_scan(sid: str, pattern: str = None, max_results: int = 50) -> Dict:
    """扫堆内存找字符串/字节模式。"""
    tgt = pattern or ""
    js = f'''
var found = 0;
Process.enumerateRanges('rw-').forEach(function (r) {{
  if (found >= {max_results}) return;
  try {{
    Memory.scan(r.base, r.size, "{tgt}").length && Memory.scan(r.base, r.size, "{tgt}", {{
      onMatch: function (a, s) {{
        send({{op:"heap_scan", addr:a.toString(), preview:Memory.readUtf8String(a, 32)}});
        found++;
        if (found >= {max_results}) return 'stop';
      }},
      onComplete: function () {{}}
    }});
  }} catch (e) {{}}
}});
send({{op:"heap_scan_done", hits:found}});
'''
    return _wrap(sid, "Fr_Heap_Scan", js,
                 "pattern 支持 Frida 的 Memory.scan 格式，如 '13 37 ?? ff' 或 '41 42'")


def fr_stack_trace(sid: str, address: str = None, depth: int = 16) -> Dict:
    """抓调用栈（native 用 Thread.backtrace，Java 用 Exception 栈）。"""
    if address:
        js = (
            'Interceptor.attach(ptr("' + address + '"), {\n'
            '  onEnter: function (a) {\n'
            '    send({op:"stack_trace", addr:"' + address + '",\n'
            '          bt: Thread.backtrace(this.context, Backtracer.ACCURATE)\n'
            '             .map(DebugSymbol.fromAddress).join("\\n")});\n'
            '  }\n'
            '});\n'
        )
    else:
        js = (
            'Java.perform(function () {\n'
            '  send({op:"java_stack",\n'
            '        bt: Java.use("java.lang.Exception").$new()\n'
            '            .getStackTrace()\n'
            '            .map(function (s) { return s.toString(); })\n'
            '            .join("\\n")});\n'
            '});\n'
        )
    return _wrap(sid, "Fr_StackTrace", js,
                 "传 address 抓该调用点的栈；不传则抓当前 Java 栈")


# ---------- Java 层 ----------

def fr_eval_java(sid: str, code: str, wrap_perform: bool = True) -> Dict:
    """执行一段 Java 层 JS 代码（Java.perform 内）。"""
    body = code or ""
    js = (f'Java.perform(function () {{\n{body}\n}});' if wrap_perform else body)
    return _wrap(sid, "Fr_Eval_Java", js,
                 "Java.perform 内执行；可用 Java.use('com.x.Y') 拿类")


def fr_overload(sid: str, class_name: str, method: str,
                dump_args: bool = True) -> Dict:
    """枚举方法的所有重载并逐个 hook（Java 重载必须指定 overload）。"""
    js = f'''
Java.perform(function () {{
  var C = Java.use("{class_name}");
  var ov = C["{method}"].overloads;
  send({{op:"overload_count", cls:"{class_name}", m:"{method}", n:ov.length}});
  ov.forEach(function (o, i) {{
    send({{op:"overload", i:i, sig:o.argumentTypes.map(function(t){{return t.className;}}).join(",")}});
    o.implementation = function () {{
      {'send({op:"args", args:[].slice.call(arguments).map(String).join(" | ")});' if dump_args else ''}
      var r = this["{method}"].apply(this, arguments);
      send({{op:"ret", ret:String(r)}});
      return r;
    }};
  }});
}});
'''
    return _wrap(sid, "Fr_Overload", js,
                 "Java 方法重载必须 .overload('...') 指定签名，本脚本自动全枚举")


# ---------- 枚举 / gadget ----------

def fr_enumerate_export(sid: str, module_name: str = None,
                        filter: str = None, max_results: int = 300) -> Dict:
    """枚举模块导出函数（含地址，可直接 hook）。"""
    mod = module_name or ""
    flt = filter or ""
    js = f'''
var mods = "{mod}" ? [Process.getModuleByName("{mod}")]
                   : Process.enumerateModules();
var out = [];
mods.forEach(function (m) {{
  m.enumerateExports().forEach(function (e) {{
    if ("{flt}" && e.name.indexOf("{flt}") < 0) return;
    if (out.length >= {max_results}) return;
    out.push({{module:m.name, name:e.name, addr:e.address.toString(), type:e.type}});
  }});
}});
send({{op:"exports", count:out.length, items:out}});
'''
    return _wrap(sid, "Fr_Enumerate_Export", js,
                 "不传 module_name 则枚举所有已加载模块")


def fr_gadget(sid: str = None, mode: str = "listen",
              package: str = None) -> Dict:
    """Frida Gadget 模式（免 root，把 libfrida-gadget.so 打进 APK）。"""
    pkg = package or "com.target"
    guide = {
        "mode": mode,
        "steps": [
            "1) 下载对应 abi 的 libfrida-gadget.so，放进 jniLibs/<abi>/",
            "2) 在入口 Activity 的 static {} 或 Application.onCreate 加 System.loadLibrary('frida-gadget')",
            "3) 重打包 + 签名（Apk_Pack）",
            "4) 安装后 adb forward tcp:27042 tcp:27042",
            "5) frida -R 连接（listen 模式）",
        ],
        "config": {
            "listen": '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042}}',
            "script": '{"interaction":{"type":"script","path":"/data/local/tmp/script.js"}}',
        }.get(mode),
        "js_load": "System.loadLibrary('frida-gadget');",
        "note": "Gadget 免 root，但需重打包；签名校验严格的应用可能闪退",
        "package": pkg,
    }
    return {"session_id": sid, **guide, "executed": False,
            "environment": _fr_avail()}


# ---------- 别名：工具名小写化与函数名不一致时对齐 ----------
# Fr_StackTrace -> fr_stacktrace（而非 fr_stack_trace）
fr_stacktrace = fr_stack_trace
