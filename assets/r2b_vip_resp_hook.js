// R2B 服务端验证绕过 · 目标域名 api.example.com · 改写字段 {"vip": true, "isVip": true, "member": true, "premium": true, "entitled": true, "activated": true, "expiresAt": "9999-12-31"}
// 用法: frida -U -f <pkg> -l r2b_vip_resp_hook.js
// 原理: hook OpenSSL SSL_read，拦截 api.example.com 的响应 JSON，把授权字段改成成功值 → 绕过服务端 VIP 校验
Java.perform(function () {
  // 1) native 层: hook SSL_read 捕获响应
  var SSL_read = Module.findExportByName('libssl.so', 'SSL_read');
  Interceptor.attach(SSL_read, {
    onLeave: function (r) {
      if (r > 0) {
        try {
          var buf = arguments[1];
          var s = String.readUTF8(buf, Math.min(r, 8192));
          if (s.indexOf('"vip"') >= 0 || s.indexOf('"member"') >= 0 || s.indexOf('"None"') >= 0) {
            rewrite(s, buf, r);
            console.log('[VIP-BYPASS] 已改写 ' + s.slice(0, 120));
          }
        } catch (e) {}
      }
    }
  });
});
function rewrite(jsonStr, buf, len) {
  var o = JSON.parse(jsonStr);
  var RW = {"vip": true, "isVip": true, "member": true, "premium": true, "entitled": true, "activated": true, "expiresAt": "9999-12-31"};
  for (var k in RW) { setDeep(o, k, RW[k]); }
  var out = JSON.stringify(o);
  // 长度够就原地写回(前缀截断到 len), 否则日志提示
  if (out.length <= len) {
    Memory.writeUtf8String(buf, out);
  } else { console.log('[VIP-BYPASS] 改写体较长, 原样输出: ' + out.slice(0,200)); }
}
function setDeep(o, key, val) {
  if (key in o) { o[key] = val; return; }
  for (var k in o) { if (o[k] && typeof o[k] === 'object') setDeep(o[k], key, val); }
}
