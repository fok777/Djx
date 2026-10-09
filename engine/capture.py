"""
engine/capture.py — 动态验证：抓包对比（mitmproxy / Frida 网络 hook）

生成可运行的抓包脚本：
  mitmproxy_addon.py  — 记录指定域名的请求/响应，抓 vip/member 判断接口
  frida_net_hook.js   — hook SSL_read/SSL_write/libc，抓 native 流量（对抗证书校验）
真实跑需 mitmproxy / frida-server（未装则输出脚本 + 说明，不伪造"已抓包"）。
"""
import os, shutil, json
from typing import Dict, Any, List


def mitmproxy_addon(domain: str, out: str = None) -> Dict[str, Any]:
    out = out or "r2b_mitm_addon.py"
    body = f'''# R2B mitmproxy addon · 目标域名 {domain}
# 用法: mitmproxy -s r2b_mitm_addon.py   (或 mitmweb 看 UI)
from mitmproxy import http

KEYS = ["vip","member","loadad","premium","isvip","subscribe","pay","auth","token"]

def request(flow: http.HTTPFlow):
    h = str(flow.request.headers).lower()
    if any(k in h for k in KEYS):
        print("[REQ]", flow.request.method, flow.request.pretty_host + flow.request.path)

def response(flow: http.HTTPFlow):
    body = flow.response.get_text()[:2000] if flow.response else ""
    if any(k in body.lower() for k in KEYS):
        print("[RESP]", flow.response.status_code, flow.request.path, "->", body[:200])
    print(">>", flow.request.pretty_host + flow.request.path,
          flow.response.status_code if flow.response else "?")
'''
    open(out, "w").write(body)
    return {"ok": True, "addon": out, "domain": domain,
            "frida_cli": bool(shutil.which("mitmproxy")),
            "note": "有 mitmproxy 直接跑；没有 pip install mitmproxy"}


def frida_net_hook(so: str = "", out: str = None) -> Dict[str, Any]:
    out = out or "r2b_frida_net.js"
    fname = os.path.basename(so) if so else "libssl.so"
    body = ("""// R2B Frida 网络 hook（对抗证书校验抓 native 流量）
// 用法: frida -U -f <pkg> -l r2b_frida_net.js
function h(mod, name, onEnter, onLeave){
  try{
    var f = Module.findExportByName(mod || null, name);
    if(!f){ console.log('[*] 无 ' + name); return; }
    Interceptor.attach(f, {
      onEnter: function(a){ this.args=a; console.log('[->] '+name); },
      onLeave: function(r){ if(onLeave) onLeave(r, this.args); }
    });
  }catch(e){ console.log('[!] '+name+' '+e); }
}
var libssl = Process.getModuleByName("libssl.so");
if (libssl) {
  ["SSL_read","SSL_write"].forEach(function(n){
    h("libssl.so", n,
      function(a){ if(n=="SSL_write" && a[1]) console.log('  [out] '+Memory.readByteArray(a[1], Math.min(512, a[2]||0))); },
      function(r,a){ if(n=="SSL_read" && r>0 && a[1]) console.log('  [in] '+Memory.readByteArray(a[1], Math.min(512, r))); });
  });
} else { console.log('[!] libssl.so 未加载'); }
console.log('[R2B] 网络 hook armed');
""")
    open(out, "w").write(body)
    return {"ok": True, "script": out, "frida_cli": bool(shutil.which("frida") or shutil.which("frida16")),
            "note": "有 frida-server 即可 hook 抓包；无则仅生成脚本"}


def capture_verify(target: Dict[str, Any] = None, out_dir: str = None) -> Dict[str, Any]:
    """第⑤步：按目标出 mitmproxy + frida 两套抓包脚本。"""
    out_dir = out_dir or "r2b_capture"
    os.makedirs(out_dir, exist_ok=True)
    domain = (target or {}).get("domain", "example.com")
    so = (target or {}).get("so", "")
    m = mitmproxy_addon(domain, os.path.join(out_dir, "r2b_mitm_addon.py"))
    f = frida_net_hook(so, os.path.join(out_dir, "r2b_frida_net.js"))
    return {"mitmproxy": m, "frida_net": f, "out_dir": out_dir,
            "verified": False,
            "note": "生成两套抓包脚本；对比请求/响应找 vip/member 判断接口，Frida 对抗证书校验"}


# ============ 服务端验证绕过（改本地不够时，直接 mock 掉服务端判断）============
VERIFY_API_KW = ["vip", "member", "verify", "license", "auth", "premium",
                 "subscribe", "pay", "activate", "check", "entitlement", "entitled"]


def locate_verify_api(so: str, extract_dir: str = "") -> Dict[str, Any]:
    """从 so/字符串里找疑似"验证/授权" API 端点（URL + 域名）。"""
    import re, glob, os
    urls = set()
    blobs = []
    if so and os.path.isfile(so):
        blobs.append(so)
    if extract_dir:
        blobs += glob.glob(os.path.join(extract_dir, "**", "lib*.so"), recursive=True)
    for f in blobs:
        try:
            data = open(f, "rb").read()
        except Exception:
            continue
        for m in re.finditer(rb"https?://[A-Za-z0-9./_\-?=&%]+", data):
            urls.add(m.group(0).decode(errors="ignore"))
    hit = [u for u in urls if any(k in u.lower() for k in VERIFY_API_KW)]
    domains = set()
    for u in urls:
        m = re.search(r"https?://([^/]+)", u)
        if m:
            domains.add(m.group(1))
    return {"verify_api_candidates": hit[:50], "all_urls_sample": sorted(urls)[:80],
            "domains": sorted(domains)[:40],
            "note": "把这些域名/端点喂给 hook_response_rewrite，拦截并改写 VIP/授权响应"}


def hook_response_rewrite(domain: str, rewrites: Dict[str, Any] = None,
                          path_kw: str = "vip", out: str = None) -> Dict[str, Any]:
    """生成 Frida 脚本：hook SSL_read（服务端响应），解析 JSON 按 rewrites 改写字段
    （默认 vip/member/isVip/premium/entitled → true），写回内存绕过服务端验证。"""
    out = out or "r2b_vip_resp_hook.js"
    rw = rewrites or {"vip": True, "isVip": True, "member": True, "premium": True,
                      "entitled": True, "activated": True, "expiresAt": "9999-12-31"}
    rw_json = json.dumps(rw, ensure_ascii=False)
    body = f"""// R2B 服务端验证绕过 · 目标域名 {domain} · 改写字段 {rw_json}
// 用法: frida -U -f <pkg> -l r2b_vip_resp_hook.js
// 原理: hook OpenSSL SSL_read，拦截 {domain} 的响应 JSON，把授权字段改成成功值 → 绕过服务端 VIP 校验
Java.perform(function () {{
  // 1) native 层: hook SSL_read 捕获响应
  var SSL_read = Module.findExportByName('libssl.so', 'SSL_read');
  Interceptor.attach(SSL_read, {{
    onLeave: function (r) {{
      if (r > 0) {{
        try {{
          var buf = arguments[1];
          var s = String.readUTF8(buf, Math.min(r, 8192));
          if (s.indexOf('"vip"') >= 0 || s.indexOf('"member"') >= 0 || s.indexOf('"{path_kw}"') >= 0) {{
            rewrite(s, buf, r);
            console.log('[VIP-BYPASS] 已改写 ' + s.slice(0, 120));
          }}
        }} catch (e) {{}}
      }}
    }}
  }});
}});
function rewrite(jsonStr, buf, len) {{
  var o = JSON.parse(jsonStr);
  var RW = {rw_json};
  for (var k in RW) {{ setDeep(o, k, RW[k]); }}
  var out = JSON.stringify(o);
  // 长度够就原地写回(前缀截断到 len), 否则日志提示
  if (out.length <= len) {{
    Memory.writeUtf8String(buf, out);
  }} else {{ console.log('[VIP-BYPASS] 改写体较长, 原样输出: ' + out.slice(0,200)); }}
}}
function setDeep(o, key, val) {{
  if (key in o) {{ o[key] = val; return; }}
  for (var k in o) {{ if (o[k] && typeof o[k] === 'object') setDeep(o[k], key, val); }}
}}
"""
    open(out, "w").write(body)
    return {"ok": True, "script": out, "domain": domain, "rewrites": rw,
            "frida_cli": bool(shutil.which("frida") or shutil.which("frida16")),
            "verified": False,
            "note": "需 frida-server 真跑；把服务端 VIP 响应改写成成功，绕过服务端验证"}
