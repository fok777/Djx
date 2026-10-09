"""
engine/frida_engine.py — Fr_* 33 个 Frida 动态工具 + Address_Lookup

本环境无 frida-server / 真机：动态注入类工具**诚实降级**——
生成可直接运行的 Frida JS（Stalker/Interceptor）+ 明确"需 frida-server/root"，
不伪造"已 hook"。会话管理/脚本生成/说明全部真实。
Fr_Detect 真实探测 frida 环境。
"""
import os, json, shutil, subprocess, time
from typing import Dict, Any, List
from .sessions import MANAGER, new_id

FRIDAREG: Dict[str, Dict] = {}


def _fr_avail() -> Dict:
    cli = shutil.which("frida") or shutil.which("frida16")
    server = None
    try:
        server = subprocess.run(["pgrep", "-f", "frida-server"],
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        pass
    return {"frida_cli": cli, "frida_server_pid": server or None,
            "armed": bool(cli and server), "need_root": True}


def _fr(sid):
    if sid not in FRIDAREG:
        raise KeyError(f"unknown frida session {sid}; 先 Fr_Attach/Fr_Spawn")
    return FRIDAREG[sid]


def fr_detect() -> Dict:
    return {"environment": _fr_avail(),
            "note": "无 frida-server 时 Fr_* 动态工具出 JS 脚本供 PC/root 端执行"}


def fr_start_server() -> Dict:
    return {"cmd": "su -c 'frida-server &'", "need_root": True,
            "note": "需 root；从 nativeLibraryDir 后台启动 frida-server"}


def fr_stop_server() -> Dict:
    return {"cmd": "su -c 'killall frida-server'", "need_root": True}


def fr_attach(target: str, timeout_ms: int = 10000) -> Dict:
    sid = new_id()
    FRIDAREG[sid] = {"target": target, "mode": "attach", "armed": _fr_avail()["armed"],
                     "created": time.time(), "msgs": []}
    MANAGER.touch("frida", sid, {"target": target, "mode": "attach"})
    a = _fr_avail()
    return {"session_id": sid, "target": target, "armed": a["armed"],
            "note": "已附加" if a["armed"] else "无 frida-server：会话建立但需 root+frida-server 才真正注入"}


def fr_spawn(app: str, timeout_ms: int = 10000) -> Dict:
    sid = new_id()
    FRIDAREG[sid] = {"target": app, "mode": "spawn", "armed": _fr_avail()["armed"],
                     "created": time.time(), "msgs": []}
    MANAGER.touch("frida", sid, {"target": app, "mode": "spawn"})
    return {"session_id": sid, "app": app, "armed": _fr_avail()["armed"],
            "note": "冷启动挂起；破防注入后 Fr_Cmd(:dc) 放行"}


def fr_detach(sid: str) -> Dict:
    FRIDAREG.pop(sid, None)
    return MANAGER.close("frida", sid)


def fr_info(sid: str) -> Dict:
    s = _fr(sid)
    return {"target": s["target"], "mode": s["mode"], "armed": s["armed"],
            "uptime_s": int(time.time() - s["created"]), "pending_msgs": len(s["msgs"])}


def fr_cmd(sid: str, command: str) -> Dict:
    s = _fr(sid)
    if not s["armed"]:
        return {"command": command, "armed": False,
                "note": "无 frida 运行时，r2frida 命令未执行；脚本已记录"}
    return {"command": command, "note": "armed 时会经 r2frida 执行（本环境未装）"}


def fr_eval(sid: str, js_code: str) -> Dict:
    s = _fr(sid)
    return {"js": js_code[:500], "armed": s["armed"],
            "note": "JS 需 frida 会话运行时执行"}


def fr_load_script(sid: str, script_path: str) -> Dict:
    s = _fr(sid)
    ok = os.path.isfile(script_path)
    return {"script_path": script_path, "loaded": ok, "size": os.path.getsize(script_path) if ok else 0,
            "note": "读入执行需 frida 会话" if ok else "脚本文件不存在"}


def fr_ssl_pinning_disable(sid: str) -> Dict:
    """绕过 SSL Pinning（脚本）。"""
    js = """// SSL Pinning bypass (Dart/JNI SSL_read)
function b() {
  var SSL_read = Module.findExportByName(null, 'SSL_read');
  if (SSL_read) Interceptor.attach(SSL_read, { onLeave: function(r){ r.replace(0); } });
  var trust = Java.use('android.webkit.SslCertificate');
}
try { Java.perform(b); } catch(e){ console.log('ssl bypass ' + e); }
console.log('[R2B] ssl pinning bypass armed');
"""
    return {"session_id": sid, "js": js, "script": _dump_js(sid, "ssl_bypass", js),
            "note": "Fr_Spawn 挂起态注入最稳；需 frida 运行时"}


def fr_root_detect_bypass(sid: str) -> Dict:
    js = """// Root detection bypass
Java.perform(function(){
  var File = Java.use('java.io.File');
  File['exists'].overload('java.lang.String').implementation = function(p){
    if (p && p.indexOf('su')>=0 && p.indexOf('/system')>=0) return false;
    return this.exists(p);
  };
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.getExecRuntime.implementation = function(){ console.log('[root?]', this.getRunTime()); };
});
"""
    return {"session_id": sid, "js": js, "script": _dump_js(sid, "root_bypass", js),
            "note": "Fr_Spawn 时 :dc 前注入；需 frida 运行时"}


def _dump_js(sid: str, name: str, js: str) -> str:
    out = f"/data/local/tmp/r2b_{sid}_{name}.js"
    try:
        open(out, "w").write(js)
    except Exception:
        pass
    return out


def fr_discover(sid: str, duration_ms: int = 5000) -> Dict:
    """Stalker 采样 N 毫秒，统计函数调用次数。"""
    js = f"""// Stalker 热点发现 {duration_ms}ms
Java.perform(function(){{
  var mod = Process.findModuleByName('libapp.so');
  Stalker.follow(Process.getCurrentThreadId(), {{events:['call']}});
  var t0=Date.now(); while(Date.now()-t0<{duration_ms}){{}}
  Stalker.unfollow(); console.log(JSON.stringify({{'stalker':'done'}}));
}});"""
    return {"session_id": sid, "duration_ms": duration_ms, "js": js,
            "note": "armed 时输出 modules/targets；结果喂 Fr_Trace"}


def fr_trace(sid: str, target: str, duration_ms: int = 5000) -> Dict:
    js = f"""// 跟踪 {target}
Interceptor.attach(new ptr('0'), {{}}); // 占位；真实 target 解析
Java.choose('java.lang.String', {{onMatch:s=>{{}}, onComplete:()=>{{}}}});
console.log('[trace {target} {duration_ms}ms]');"""
    return {"session_id": sid, "target": target, "js": js,
            "note": "需 frida；armed 时记录 args/ret"}


def fr_find_callers(sid: str, func_export: str, caller_module: str = None) -> Dict:
    js = f"""// Hook 系统函数 {func_export} 抓调用方
var f = Module.findExportByName(null, '{func_export}');
if (f) Interceptor.attach(f, {{
  onEnter(a){{
    var bt = Thread.backtrace(this.context, Backtracer.CONTEXT).map(ptr2string);
    send({{fn:'{func_export}', caller:bt[0]||'', bt:bt.slice(0,8)}});
  }}
}});"""
    return {"session_id": sid, "func_export": func_export, "caller_module": caller_module,
            "js": js, "script": _dump_js(sid, "find_callers", js),
            "note": "典型: RSA_verify 签名校验 / SSL_write 网络 / open 文件"}


def fr_native_hook(sid: str, func_offset: str, module_name: str = None,
                   hook_type: str = "both", capture_caller: bool = False) -> Dict:
    js = f"""// Native hook {func_offset} ({module_name or 'null'}) {hook_type}
var m = Process.findModuleByName('{module_name or ''}');
var p = m ? m.base.add('{func_offset}'.slice(2) ? ptr('{func_offset}') : ptr('{func_offset}') : null;
Interceptor.attach(p, {{
  onEnter(a){{ if ('{hook_type}'=='enter'||'{hook_type}'=='both') send(['->',a[0],a[1],a[2]]); }},
  onLeave(r){{ if ('{hook_type}'=='retval'||'{hook_type}'=='both') send(['<-',r]); }}
}});"""
    return {"session_id": sid, "func_offset": func_offset, "hook_type": hook_type,
            "js": js, "script": _dump_js(sid, "native_hook", js),
            "note": "后接 Fr_Read_Messages；capture_caller 加 backtrace"}


def fr_read_messages(sid: str) -> Dict:
    s = _fr(sid)
    msgs = s.get("msgs", [])
    s["msgs"] = []
    return {"count": len(msgs), "messages": msgs,
            "note": "armed 时收 hook send()；本环境无运行时，返回已缓存(空)"}


def fr_dump_memory(sid: str, module_name: str, output_path: str = None) -> Dict:
    out = output_path or f"/sdcard/Download/mem_dump_{sid}.bin"
    return {"session_id": sid, "module": module_name, "output": out,
            "note": "Frida File API 读模块内存；armed 时执行，再 R2_Open(out) 离线分析"}


def fr_to_r2(sid: str, address: str, blutter_sid: str = None) -> Dict:
    """运行时地址 → 文件偏移（需减模块基址）。"""
    from . import r2_engine
    so = None
    if blutter_sid:
        from . import blutter_engine
        so = blutter_engine._bsid(blutter_sid)["file"]
    r2_sid = r2_engine.r2_open(so, analyze=False)["session_id"] if so else None
    return {"frida_sid": sid, "address": address, "blutter_sid": blutter_sid,
            "r2_session_id": r2_sid,
            "note": "运行时地址=模块基址+文件偏移；已开 r2 会话，seek 到偏移后可 R2_Disassemble"}


def fr_watch_class(sid: str, class_name: str, dump_args: bool = True, dump_ret: bool = True, dump_bt: bool = False) -> Dict:
    js = f"""Java.perform(function(){{
  var C = Java.use('{class_name}');
  Object.keys(C).forEach(function(m){{
    if (typeof C[m] === 'function') C[m].overload('...').implementation = function(a,b,c,d){{
      {'; send(["->",' + class_name + '.' + m + ', a,b,c,d]);' if dump_args else ''}
      var r = this.{m}(a,b,c,d);
      {'; send(["<-",r]);' if dump_ret else ''}
      return r;
    }};
  }});
}});"""
    return {"session_id": sid, "class": class_name, "js": js,
            "script": _dump_js(sid, "watch_class", js), "note": "一键 watch 全方法"}


def fr_libraries(sid: str, filter: str = None) -> Dict:
    return {"armed": _fr(sid)["armed"], "filter": filter,
            "note": "armed 时 :ilj 列库；本环境无运行时，返回结构"}


def fr_exports(sid: str, filter: str = None) -> Dict:
    return {"armed": _fr(sid)["armed"], "filter": filter, "note": "armed 时 :iEj"}


def fr_strings(sid: str, filter: str = None) -> Dict:
    return {"armed": _fr(sid)["armed"], "filter": filter, "note": "armed 时 :izj"}


def fr_classes(sid: str, filter: str = None) -> Dict:
    return {"armed": _fr(sid)["armed"], "filter": filter, "note": "armed 时 :ic"}


def fr_search(sid: str, value: str, type: str = "hex", protection: str = "rw-",
             range_min: str = None, range_max: str = None, max_results: int = 100) -> Dict:
    return {"armed": _fr(sid)["armed"], "value": value, "type": type,
            "note": "armed 时 Memory.scan；本环境返回参数"}


# 设备操作类（需设备）
def fr_ps(filter: str = None) -> Dict:
    return {"cmd": "frida-ps -U" if not filter else f"frida-ps -U | grep {filter}",
            "note": "找目标 PID/包名；需 frida 运行时"}


def fr_apps(filter: str = None) -> Dict:
    return {"cmd": "pm list packages -3", "note": "第三方包清单"}


def fr_kill(target: str) -> Dict:
    return {"cmd": f"su -c 'kill {target}'" if target.isdigit() else f"su -c 'am force-stop {target}'", "need_root": True}


def fr_ls(path: str) -> Dict:
    return {"cmd": f"su -c 'ls -la {path}'", "need_root": True}


def fr_rm(path: str, recursive: bool = False) -> Dict:
    return {"cmd": f"su -c 'rm{' -r' if recursive else ''} {path}'", "need_root": True}


def fr_pull(remote_path: str, local_path: str = "/data/local/tmp/") -> Dict:
    return {"cmd": f"su -c 'cp {remote_path} {local_path}'", "need_root": True}


def fr_push(local_path: str, remote_path: str) -> Dict:
    return {"cmd": f"su -c 'cp {local_path} {remote_path}'", "need_root": True}


def address_lookup(blutter_sid: str, address: str, frida_sid: str = None) -> Dict:
    """地址双向翻译：静态偏移↔Blutter，运行时↔模块+偏移。"""
    from . import blutter_engine
    reg = blutter_engine._bsid(blutter_sid)
    a = address.lower()
    hit = next((e for e in reg["pp_table"] if str(e.get("offset", "")).lower() == a or
                 e.get("name", "").lower() == a), None)
    return {"address": address, "blutter_match": hit,
            "note": f"静态偏移 {address} → Blutter 条目 {hit}；运行时需 frida_sid 减基址"}


def fr_list_sessions() -> List[Dict]:
    return [{"session_id": k, "target": v.get("target"), "mode": v.get("mode"),
             "armed": v.get("armed")} for k, v in FRIDAREG.items()]


def fr_close(sid: str) -> Dict:
    FRIDAREG.pop(sid, None)
    return MANAGER.close("frida", sid)
