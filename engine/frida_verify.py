"""
engine/frida_verify.py — 动态验证（Frida hook / 抓包对比）

frida-server 未装在本环境：产出可直接运行的 Frida hook JS 模板，
并检测 frida CLI；若可用则给出 spawn 命令。不伪造"已验证"。
"""
import os, shutil
from typing import Dict, Any, List


def _frida_cli() -> str:
    return shutil.which("frida") or shutil.which("frida16") or ""


def make_verify_script(so: str, func_names: List[str], out: str = None) -> Dict[str, Any]:
    """生成 Frida JS：hook 目标 native 函数，打印入参/返回值。"""
    out = out or so + ".verify.js"
    fname = os.path.basename(so)
    lines = [
        "// R2B Frida 动态验证脚本（自动生成）",
        f"// 目标 so: {fname}   目标函数: {', '.join(func_names[:8])}",
        "function h(name, mod) {",
        "  try {",
        "    var f = mod ? Module.findExportByName(mod, name) : Module.findExportByName(null, name);",
        "    if (!f) { console.log('[*] not found: ' + name); return; }",
        "    Interceptor.attach(f, {",
        "      onEnter: function (a) { console.log('[->] ' + name + ' a0=' + a[0]); },",
        "      onLeave: function (r) { console.log('[<-] ' + name + ' = ' + r); }",
        "    });",
        "  } catch (e) { console.log('[!] ' + name + ' ' + e); }",
        "}",
        "var so = null; try { so = Process.getModuleByName('%s'); } catch(e) {}",
        "Module.enumerateSymbols(so || null, /%s/).forEach(function (s) { h(s.name, so); });",
        "console.log('[R2B] verify script armed');",
    ]
    js = "\n".join(lines) % (fname, func_names[0] if func_names else ".*")
    open(out, "w").write(js)
    return {"script": out, "funcs": func_names[:8],
            "frida_cli": _frida_cli() or None,
            "run_hint": (f"frida -U -f <package> -l {out}" if _frida_cli()
                          else "未装 frida：拷到设备 frida-server 侧执行"),
            "verified": False}


def verify(so: str, func_names: List[str]) -> Dict[str, Any]:
    return make_verify_script(so, func_names)
