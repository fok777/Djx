"""
webui.py — R2B 内置 Web 控制台（单页，无外部依赖）

为什么用它：后端是 Python，Termux 里跑起来就有完整能力。
再给它套一个网页界面，手机浏览器打开就能点、能跑、看得到结果，
不必再去写一套 Java UI 把工具重写一遍。

设计：
  - 纯标准库渲染，无模板引擎、无 CDN（Termux 上离线可用）
  - 移动端优先：大按钮、卡片、底部图标条
  - 点分类图标 -> 弹出该分类工具列表 -> 点工具直接真执行
"""
from typing import Any, Dict, List

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#1a73e8">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>R2B 逆向控制台</title>
<style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC","Noto Sans CJK SC","Microsoft YaHei",sans-serif;
background:#f5f7fa;color:#202124;padding-bottom:calc(84px + env(safe-area-inset-bottom))}
.hd{background:#fff;padding:14px 16px calc(12px);display:flex;align-items:center;gap:12px;
border-bottom:1px solid #e8eaed;position:sticky;top:0;z-index:20}
.logo{width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#1a73e8,#4285f4);
display:flex;align-items:center;justify-content:center;font-size:21px;flex:0 0 auto}
.tt{flex:1;min-width:0}
.tt h1{margin:0;font-size:16px;font-weight:600}
.tt p{margin:1px 0 0;font-size:11.5px;color:#5f6368}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:1px}
.on{background:#188038}.off{background:#9aa0a6}
.wrap{padding:14px}
.apk{background:#fff;border-radius:12px;padding:11px 13px;margin-bottom:12px;display:flex;gap:9px;align-items:center}
.apk input{flex:1;border:0;outline:0;font-size:13px;background:transparent;min-width:0;color:#202124}
.apk input::placeholder{color:#9aa0a6}
.btn{border:0;border-radius:9px;padding:8px 13px;font-size:13px;font-weight:500;cursor:pointer;background:#1a73e8;color:#fff}
.btn.g{background:#eef1f5;color:#1a73e8}
.btn:active{opacity:.75}
.stats{display:flex;gap:8px;margin-bottom:12px}
.stat{flex:1;background:#fff;border-radius:11px;padding:10px 8px;text-align:center}
.stat b{display:block;font-size:19px;color:#1a73e8;line-height:1.2}
.stat span{font-size:10.5px;color:#5f6368}
.sec{font-size:12.5px;font-weight:600;color:#5f6368;margin:16px 2px 9px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(84px,1fr));gap:10px}
.cat{background:#fff;border-radius:13px;padding:12px 6px 10px;text-align:center;cursor:pointer;
transition:transform .1s;position:relative}
.cat:active{transform:scale(.95)}
.cat .ic{width:44px;height:44px;border-radius:12px;margin:0 auto 7px;display:flex;
align-items:center;justify-content:center;font-size:22px;color:#fff}
.cat .nm{font-size:12px;font-weight:600;line-height:1.25}
.cat .ct{font-size:10.5px;color:#80868b;margin-top:2px}
.cat .bad{position:absolute;top:5px;right:5px;width:7px;height:7px;border-radius:50%}
.bad.y{background:#188038}.bad.n{background:#f9ab00}

/* 底部图标条 */
.bar{position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:1px solid #e8eaed;
display:flex;overflow-x:auto;padding:8px 8px calc(8px + env(safe-area-inset-bottom));z-index:30;
scrollbar-width:none}
.bar::-webkit-scrollbar{display:none}
.tab{flex:0 0 auto;width:48px;height:48px;border-radius:12px;margin-right:8px;display:flex;
align-items:center;justify-content:center;font-size:22px;cursor:pointer;opacity:.45;transition:opacity .15s}
.tab.sel{opacity:1;box-shadow:0 0 0 2.5px #1a73e8}

/* 弹层 */
.mask{position:fixed;inset:0;background:rgba(0,0,0,.42);z-index:50;display:none;
align-items:flex-end;justify-content:center}
.mask.show{display:flex}
.sheet{background:#f5f7fa;width:100%;max-width:640px;height:88vh;border-radius:17px 17px 0 0;
display:flex;flex-direction:column;animation:up .2s ease}
@keyframes up{from{transform:translateY(30px);opacity:.5}to{transform:none;opacity:1}}
.sh{background:#fff;padding:13px 15px;border-radius:17px 17px 0 0;display:flex;align-items:center;gap:10px;
border-bottom:1px solid #e8eaed}
.sh h2{margin:0;font-size:15.5px;flex:1;min-width:0}
.x{width:30px;height:30px;border-radius:50%;background:#f1f3f4;border:0;font-size:17px;
cursor:pointer;color:#5f6368;line-height:1}
.sb{flex:1;overflow-y:auto;padding:12px;-webkit-overflow-scrolling:touch}
.src{width:100%;border:1px solid #dadce0;border-radius:10px;padding:9px 11px;font-size:14px;
outline:0;margin-bottom:11px;background:#fff}
.row{background:#fff;border-radius:11px;padding:11px 12px;margin-bottom:8px;cursor:pointer;
display:flex;gap:10px;align-items:flex-start}
.row:active{background:#f8f9fa}
.row .mi{width:29px;height:29px;border-radius:8px;flex:0 0 auto;display:flex;align-items:center;
justify-content:center;font-size:15px;color:#fff}
.row .bd{flex:1;min-width:0}
.row .n{font-size:13.5px;font-weight:600;word-break:break-all}
.row .d{font-size:11.5px;color:#80868b;margin-top:2px;line-height:1.45}
.fld{margin-bottom:10px}
.fld label{display:block;font-size:11.5px;color:#5f6368;margin-bottom:3px}
.fld input{width:100%;border:1px solid #dadce0;border-radius:8px;padding:8px 10px;font-size:14px;outline:0}
.run{width:100%;padding:12px;font-size:15px;border-radius:11px;background:#1a73e8;color:#fff;border:0;font-weight:500}
pre{background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:11px;overflow:auto;font:11.5px/1.55
ui-monospace,SFMono-Regular,Menlo,monospace;max-height:60vh;white-space:pre-wrap;word-break:break-all;margin:0}
.err{background:#fce8e6;color:#c5221f;padding:11px;border-radius:10px;font-size:13px}
.loading{text-align:center;padding:26px;color:#80868b;font-size:13px}
.empty{text-align:center;padding:36px 16px;color:#9aa0a6;font-size:13px}
.hint{font-size:11.5px;color:#80868b;padding:7px 11px;background:#fff;border-radius:9px;margin-bottom:10px;
border-left:3px solid #f9ab00}
</style>
</head>
<body>

<div class="hd">
  <div class="logo">&#128295;</div>
  <div class="tt">
    <h1>R2B 逆向控制台</h1>
    <p><span class="dot" id="dot"></span><span id="st">连接中…</span></p>
  </div>
</div>

<div class="wrap">
  <div class="apk">
    <input id="apk" placeholder="APK / so 文件路径（多数工具需要）">
    <button class="btn g" onclick="useSample()">填入</button>
  </div>

  <div class="stats">
    <div class="stat"><b id="s1">-</b><span>工具总数</span></div>
    <div class="stat"><b id="s2">-</b><span>分类</span></div>
    <div class="stat"><b id="s3">-</b><span>引擎就绪</span></div>
  </div>

  <div class="sec">工具分类 · 点击查看</div>
  <div class="grid" id="grid"><div class="loading">加载中…</div></div>
</div>

<!-- 分类工具列表 -->
<div class="mask" id="m1"><div class="sheet">
  <div class="sh"><h2 id="c1">分类</h2><button class="x" onclick="close(1)">&times;</button></div>
  <div class="sb">
    <input class="src" id="q" placeholder="搜索工具名 / 描述…" oninput="filter()">
    <div id="list"><div class="loading">加载中…</div></div>
  </div>
</div></div>

<!-- 执行 -->
<div class="mask" id="m2"><div class="sheet">
  <div class="sh"><h2 id="c2">工具</h2><button class="x" onclick="close(2)">&times;</button></div>
  <div class="sb">
    <div id="desc" style="font-size:12.5px;color:#5f6368;margin-bottom:11px"></div>
    <div id="form"></div>
    <button class="run" onclick="run()">执行</button>
    <div id="out" style="margin-top:13px"></div>
  </div>
</div></div>

<!-- 结果 -->
<div class="mask" id="m3"><div class="sheet">
  <div class="sh"><h2 id="c3">结果</h2><button class="x" onclick="close(3)">&times;</button></div>
  <div class="sb"><pre id="res"></pre></div>
</div></div>

<div class="bar" id="bar"></div>

<script>
var CATS=[], TOOLS={}, CUR=null, CURTOOL=null;

async function api(u){
  var r=await fetch(u); if(!r.ok) throw new Error('HTTP '+r.status);
  return await r.json();
}
async function rpc(method,params){
  var r=await fetch('/mcp',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:Date.now(),method:method,params:params||{}})});
  return await r.json();
}

async function boot(){
  try{
    var h=await api('/health');
    document.getElementById('dot').className='dot on';
    document.getElementById('st').textContent='服务运行中 · '+h.tools+' 个工具';
  }catch(e){
    document.getElementById('dot').className='dot off';
    document.getElementById('st').textContent='服务未连接';
  }
  try{
    var c=await api('/api/categories');
    CATS=c.categories;
    document.getElementById('s1').textContent=c.total;
    document.getElementById('s2').textContent=CATS.length;
    document.getElementById('s3').textContent=CATS.filter(function(x){return x.real}).length+'/'+CATS.length;
    render();
  }catch(e){
    document.getElementById('grid').innerHTML='<div class="empty">加载失败: '+e.message+'</div>';
  }
}

function render(){
  var g=document.getElementById('grid'), b=document.getElementById('bar'), h='', t='';
  CATS.forEach(function(c,i){
    h+='<div class="cat" onclick="openCat('+i+')">'
      +'<div class="ic" style="background:'+c.color+'">'+c.icon+'</div>'
      +'<div class="nm">'+c.title+'</div><div class="ct">'+c.count+' 个</div>'
      +'<div class="bad '+(c.real?'y':'n')+'"></div></div>';
    t+='<div class="tab" style="background:'+c.color+'" onclick="openCat('+i+')">'+c.icon+'</div>';
  });
  g.innerHTML=h; b.innerHTML=t;
}

async function openCat(i){
  CUR=CATS[i];
  document.getElementById('c1').textContent=CUR.title+' · '+CUR.count+' 个工具';
  document.getElementById('q').value='';
  show(1);
  document.getElementById('list').innerHTML='<div class="loading">加载中…</div>';
  try{
    if(!TOOLS[CUR.id]){
      TOOLS[CUR.id]=await api('/api/tools?cat='+encodeURIComponent(CUR.id));
    }
    draw(TOOLS[CUR.id]);
  }catch(e){
    document.getElementById('list').innerHTML='<div class="empty">加载失败: '+e.message+'</div>';
  }
}

function draw(list){
  var h='';
  if(!list.length){document.getElementById('list').innerHTML='<div class="empty">该分类没有工具</div>';return;}
  if(!CUR.real){
    h+='<div class="hint">'+CUR.note+'</div>';
  }
  list.forEach(function(t){
    h+='<div class="row" onclick=\'openTool('+JSON.stringify(t.name).replace(/'/g,"\\'")+')\'>'
      +'<div class="mi" style="background:'+CUR.color+'">'+CUR.icon+'</div>'
      +'<div class="bd"><div class="n">'+esc(t.name)+'</div>'
      +'<div class="d">'+esc(t.description||'')+'</div></div></div>';
  });
  document.getElementById('list').innerHTML=h;
}

function filter(){
  var q=document.getElementById('q').value.toLowerCase().trim();
  var all=TOOLS[CUR.id]||[];
  if(!q){draw(all);return;}
  draw(all.filter(function(t){
    return t.name.toLowerCase().indexOf(q)>=0 || (t.description||'').toLowerCase().indexOf(q)>=0;
  }));
}

function openTool(name){
  var list=TOOLS[CUR.id]||[], t=null;
  for(var i=0;i<list.length;i++){if(list[i].name===name){t=list[i];break;}}
  if(!t) return;
  CURTOOL=t;
  document.getElementById('c2').textContent=t.name;
  document.getElementById('desc').textContent=t.description||'';
  var props=(t.inputSchema&&t.inputSchema.properties)||{};
  var req=(t.inputSchema&&t.inputSchema.required)||[];
  var f='';
  for(var k in props){
    var p=props[k]||{};
    var need=req.indexOf(k)>=0;
    var apkv=getApk();
    var val=(/apk|path|file|so|target|dir/i.test(k)&&apkv)?apkv:'';
    f+='<div class="fld"><label>'+esc(k)+(p.description?' · '+esc(p.description):'')
      +(need?' <span style="color:#c5221f">*</span>':'')+'</label>'
      +'<input id="p_'+esc(k)+'" value="'+esc(val)+'" placeholder="'+(p.type||'string')+'"></div>';
  }
  if(!f) f='<div style="font-size:12.5px;color:#80868b;margin-bottom:11px">该工具无需参数</div>';
  document.getElementById('form').innerHTML=f;
  document.getElementById('out').innerHTML='';
  show(2);
}

async function run(){
  if(!CURTOOL) return;
  var props=(CURTOOL.inputSchema&&CURTOOL.inputSchema.properties)||{};
  var args={};
  for(var k in props){
    var el=document.getElementById('p_'+k);
    if(el&&el.value.trim()) args[k]=el.value.trim();
  }
  document.getElementById('out').innerHTML='<div class="loading">执行中…</div>';
  try{
    var r=await rpc('tools/call',{name:CURTOOL.name,arguments:args});
    if(r.error){
      document.getElementById('out').innerHTML='<div class="err">'+esc(r.error.message||JSON.stringify(r.error))+'</div>';
      return;
    }
    var c=(r.result&&r.result.content)||[];
    var txt=c.map(function(x){return x.text||''}).join('\n');
    var isErr=r.result&&r.result.isError;
    try{
      var o=JSON.parse(txt);
      txt=JSON.stringify(o,null,2);
    }catch(e){}
    document.getElementById('out').innerHTML=
      (isErr?'<div class="err">工具返回错误</div>':'')
      +'<pre>'+esc(txt)+'</pre>';
  }catch(e){
    document.getElementById('out').innerHTML='<div class="err">'+esc(e.message)+'</div>';
  }
}

function getApk(){return document.getElementById('apk').value.trim();}
function useSample(){
  var i=document.getElementById('apk');
  i.value='/sdcard/Download/app.apk';
}
function show(n){document.getElementById('m'+n).classList.add('show');}
function close(n){document.getElementById('m'+n).classList.remove('show');}
function esc(s){
  return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
document.querySelectorAll('.mask').forEach(function(m){
  m.addEventListener('click',function(e){if(e.target===m)m.classList.remove('show');});
});
boot();
</script>
</body>
</html>
"""


def _cat_meta() -> Dict[str, Dict[str, Any]]:
    """分类的图标与配色（UI 展示用，与 categories.py 的业务数据分开）。"""
    return {
        "R2":      {"icon": "\U0001F4BB", "color": "#00897B"},
        "Fr":      {"icon": "\U0001F40D", "color": "#F57C00"},
        "Blutter": {"icon": "\U0001F426", "color": "#1A73E8"},
        "Il2Cpp":  {"icon": "⚡", "color": "#8E24AA"},
        "Ub":      {"icon": "⏱", "color": "#00796B"},
        "Nav":     {"icon": "\U0001F9ED", "color": "#0288D1"},
        "Apk":     {"icon": "\U0001F4E6", "color": "#E8710A"},
        "Pentest": {"icon": "\U0001F6E1", "color": "#C62828"},
        "Misc":    {"icon": "\U0001F5C3", "color": "#5F6368"},
        "Engine":  {"icon": "\U0001F527", "color": "#37474F"},
    }


def categories_payload() -> Dict[str, Any]:
    """给 UI 用的分类汇总：业务数据 + 图标配色。"""
    from r2b_mcp.categories import summarize
    s = summarize()
    meta = _cat_meta()
    out = []
    for c in s.get("categories", []):
        m = meta.get(c["id"], {"icon": "⚙", "color": "#5F6368"})
        out.append({
            "id": c["id"],
            "title": c["title"],
            "count": c.get("count", 0),
            "real": bool(c.get("real")),
            "note": c.get("note", ""),
            "icon": m["icon"],
            "color": m["color"],
        })
    return {"total": s.get("total", 0), "categories": out}


def tools_payload(cat: str) -> List[Dict[str, Any]]:
    """某分类下的工具列表。"""
    from r2b_mcp.server import build_tools
    tools = build_tools()
    if not cat or cat.lower() in ("all", "全部"):
        return [{"name": t["name"], "description": t.get("description", ""),
                 "inputSchema": t.get("inputSchema", {})} for t in tools]
    out = []
    for t in tools:
        if t.get("category") == cat or t["name"].startswith(cat + "_"):
            out.append({"name": t["name"], "description": t.get("description", ""),
                        "inputSchema": t.get("inputSchema", {})})
    return out


def render_html() -> str:
    return HTML
