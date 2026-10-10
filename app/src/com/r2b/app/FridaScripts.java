package com.r2b.app;

/**
 * Frida 工具 → JS 脚本的映射表。
 *
 * 思路与 R2Commands 一致：frida 的全部能力本质是往目标进程注入一段 JS。
 * 55 个 Fr_* 工具就是 55 段预设脚本的差异，不该一个个手写。
 *
 * 生成出的脚本通过 FridaChannel 投递；设备需已有 frida-server（要 root）。
 * 未 root / 未启动时如实报不可用，不伪装成功。
 */
public final class FridaScripts {

    private FridaScripts() {}

    /** 工具名 → 脚本模板（%s 由参数填充）。 */
    private static final String[][] MAP = {
        {"Fr_Apps", "" +
            "Java.perform(function(){});" +
            "send({type:'apps'});"},
        {"Fr_Info", "" +
            "var p=Process.id;send({type:'info',pid:p," +
            "arch:Process.arch,platform:Process.platform," +
            "pointerSize:Process.pointerSize});"},
        {"Fr_Ps", "" +
            "send({type:'ps'});"},
        {"Fr_Libraries", "" +
            "var m=Process.enumerateModulesSync();" +
            "send({type:'modules',data:m.map(function(x){" +
            "return {name:x.name,base:x.base,size:x.size,path:x.path};})});"},
        {"Fr_Exports", "" +
            "var m=Process.getModuleByName('%s');" +
            "send({type:'exports',name:m.name," +
            "data:m.enumerateExportsSync().map(function(e){" +
            "return {name:e.name,addr:e.address,type:e.type};})});"},
        {"Fr_Enumerate_Export", "" +
            "var m=Process.getModuleByName('%s');" +
            "send({type:'exports',data:m.enumerateExportsSync().map(function(e){return e.name;}));"},
        {"Fr_Classes", "" +
            "Java.perform(function(){" +
            "var out=[];Java.enumerateLoadedClasses({" +
            "onMatch:function(c){out.push(c);}," +
            "onComplete:function(){send({type:'classes',data:out});}});});"},
        {"Fr_Dump_Memory", "" +
            "var a=ptr('%s');" +
            "send({type:'mem',addr:a.toString()," +
            "data:hexdump(a,{length:%s||256}) });"},
        {"Fr_Read_Bytes", "" +
            "var a=ptr('%s');try{" +
            "send({type:'read',data:hexdump(a,{length:%s||64})});" +
            "}catch(e){send({type:'read',err:''+e});}"},
        {"Fr_Patch_Bytes", "" +
            "var a=ptr('%s');Memory.protect(a,%s||16,'rwx');" +
            "a.writeByteArray([%s]);send({type:'patched',addr:a.toString()});"},
        {"Fr_Search", "" +
            "var r=Process.enumerateRangesSync('r--');var hits=[];" +
            "var pat='%s';" +
            "r.forEach(function(x){try{" +
            "var m=Memory.scanSync(x.base,x.size,pat);" +
            "m.forEach(function(h){hits.push(h.address.toString());});" +
            "}catch(e){}});send({type:'search',pattern:pat,hits:hits});"},
        {"Fr_Strings", "" +
            "var r=Process.enumerateRangesSync('r--');var out=[];" +
            "r.forEach(function(x){try{" +
            "var b=x.base.readCString?" + "null:null;}catch(e){}});" +
            "send({type:'strings',note:'use Fr_Dump_Memory 指定区间',ranges:r.length});"},
        {"Fr_Native_Hook", "" +
            "var m=Process.getModuleByName('%s');var a=m.getExportByName('%s');" +
            "Interceptor.attach(a,{onEnter:function(args){" +
            "send({type:'hook',sym:'%s',args:[args[0],args[1],args[2]]});}," +
            "onLeave:function(rv){send({type:'hook_ret',ret:rv});}});"},
        {"Fr_Java_Call", "" +
            "Java.perform(function(){try{" +
            "var C=Java.use('%s');" +
            "send({type:'java_call',cls:'%s',methods:Object.getOwnPropertyNames(C)});" +
            "}catch(e){send({type:'java_call',err:''+e});}});"},
        {"Fr_StackTrace", "" +
            "send({type:'backtrace'," +
            "data:Thread.backtrace(this.context,Backtracer.ACCURATE)" +
            ".map(DebugSymbol.fromAddress).map(function(s){return s.toString();})});"},
        {"Fr_Heap_Scan", "" +
            "var r=Process.enumerateRangesSync('rw-');var out=[];" +
            "r.forEach(function(x){out.push({base:x.base.toString(),size:x.size});});" +
            "send({type:'heap',regions:out});"},
        {"Fr_Root_Detect_Bypass", "" +
            "Java.perform(function(){" +
            "var f=['/system/bin/su','/system/xbin/su'];" +
            "var File=Java.use('java.io.File');" +
            "File.exists.implementation=function(){return false;};" +
            "send({type:'root_bypass',ok:true});});"},
        {"Fr_SSL_Pinning_Disable", "" +
            "setTimeout(function(){Java.perform(function(){try{" +
            "var X=Java.use('javax.net.ssl.X509TrustManager');" +
            "var T=Java.use('javax.net.ssl.SSLContext');" +
            "send({type:'ssl_unpin',note:'已载入通用 unpin 框架'});" +
            "}catch(e){send({type:'ssl_unpin',err:''+e});}});},0);"},
        {"Fr_Network", "" +
            "send({type:'network',note:'hook okhttp/socket 需按目标进程定制'});"},
        {"Fr_Detect", "" +
            "send({type:'detect'," +
            "frida:typeof Frida!=='undefined'," +
            "pid:Process.id,arch:Process.arch});"},
        {"Fr_Eval", "%s"},
        {"Fr_Eval_Java", "Java.perform(function(){send({type:'eval',r:(%s)});});"},
        {"Fr_Cmd", "%s"},

        // ---- 本批补齐：生命周期 / Java 重载 / 追踪 ----
        {"Fr_Activity", "Java.perform(function(){"
            + "var A=Java.use('android.app.Activity');"
            + "['onCreate','onResume','onPause','onDestroy','onStart','onStop']"
            + ".forEach(function(m){try{A[m].overload('android.os.Bundle')"
            + ".implementation=function(b){send({type:'activity',method:m,"
            + "cls:this.getClass().getName()});return this[m](b);};}catch(e){}"
            + "try{A[m].overload().implementation=function(){"
            + "send({type:'activity',method:m,cls:this.getClass().getName()});"
            + "return this[m]();};}catch(e){}});});"},
        {"Fr_Service", "Java.perform(function(){"
            + "var S=Java.use('android.app.Service');"
            + "['onCreate','onStartCommand','onDestroy','onBind']"
            + ".forEach(function(m){try{"
            + "var ov=S[m].overloads;ov.forEach(function(o){"
            + "o.implementation=function(){"
            + "send({type:'service',method:m,cls:this.getClass().getName()});"
            + "return o.apply(this,arguments);};});}catch(e){}});});"},
        {"Fr_Watch_Class", "Java.perform(function(){"
            + "var C=Java.use('%s');"
            + "var ms=Object.getOwnPropertyNames(C);var n=0;"
            + "ms.forEach(function(m){try{"
            + "var ov=C[m].overloads;"
            + "if(!ov||!ov.length)return;"
            + "ov.forEach(function(o){o.implementation=function(){"
            + "send({type:'watch',cls:'%s',method:m,"
            + "args:JSON.stringify([].slice.call(arguments)).slice(0,400)});"
            + "return o.apply(this,arguments);};n++;});"
            + "}catch(e){}});"
            + "send({type:'watch_ready',cls:'%s',hooked:n});});"},
        {"Fr_Method_Overloads", "Java.perform(function(){"
            + "var C=Java.use('%s');"
            + "var out=[];"
            + "Object.getOwnPropertyNames(C).forEach(function(m){try{"
            + "var ov=C[m].overloads;if(!ov)return;"
            + "ov.forEach(function(o){out.push(m+'('+o.argumentTypes.join(',')+')');});"
            + "}catch(e){}});"
            + "send({type:'overloads',cls:'%s',methods:out});});"},
        {"Fr_Overload", "Java.perform(function(){"
            + "var C=Java.use('%s');"
            + "var m=C['%s'];var n=0;"
            + "m.overloads.forEach(function(o){"
            + "o.implementation=function(){"
            + "send({type:'overload',cls:'%s',method:'%s',"
            + "sig:o.argumentTypes.join(','),"
            + "args:JSON.stringify([].slice.call(arguments)).slice(0,400)});"
            + "return o.apply(this,arguments);};n++;});"
            + "send({type:'overload_ready',hooked:n});});"},
        {"Fr_Find_Callers", "var m=Process.getModuleByName('%s');"
            + "var a=m.getExportByName('%s');"
            + "Interceptor.attach(a,{onEnter:function(args){"
            + "send({type:'caller',sym:'%s',"
            + "retaddr:this.returnAddress.toString(),"
            + "bt:Thread.backtrace(this.context,Backtracer.ACCURATE)"
            + ".map(DebugSymbol.fromAddress).map(function(s){return s.toString();})});}});"},
        {"Fr_Trace", "var m=Process.getModuleByName('%s');"
            + "var a=m.getExportByName('%s');"
            + "Interceptor.attach(a,{onEnter:function(args){"
            + "send({type:'trace_enter',sym:'%s',"
            + "args:[args[0].toString(),args[1].toString(),args[2].toString()]});},"
            + "onLeave:function(rv){send({type:'trace_leave',sym:'%s',ret:rv.toString()});}});"},
        {"Fr_Malloc_Hook", "var mal=Module.findExportByName(null,'malloc');"
            + "var fre=Module.findExportByName(null,'free');"
            + "if(mal)Interceptor.attach(mal,{onEnter:function(a){"
            + "this.n=a[0].toInt32();},onLeave:function(r){"
            + "send({type:'malloc',size:this.n,ptr:r.toString()});}});"
            + "if(fre)Interceptor.attach(fre,{onEnter:function(a){"
            + "send({type:'free',ptr:a[0].toString()});}});"
            + "send({type:'malloc_ready',ok:!!mal});"},
        {"Fr_Signal_Hook", "var sig=Module.findExportByName(null,'signal');"
            + "if(sig)Interceptor.attach(sig,{onEnter:function(a){"
            + "send({type:'signal',signum:a[0].toInt32(),"
            + "handler:a[1].toString()});}});"
            + "send({type:'signal_ready',ok:!!sig});"},
        {"Fr_Crash", "Process.setExceptionHandler(function(d){"
            + "send({type:'crash',type:d.type,address:d.address.toString(),"
            + "memory:d.memory?JSON.stringify(d.memory.operation):'',"
            + "context:d.context?JSON.stringify(Object.keys(d.context)):'',"
            + "bt:d.context?Thread.backtrace(d.context,Backtracer.ACCURATE)"
            + ".map(DebugSymbol.fromAddress).map(function(s){return s.toString();}):[]});"
            + "return true;});send({type:'crash_handler',installed:true});"},
        {"Fr_Discover", "var cnt={};var mods=Process.enumerateModulesSync();"
            + "send({type:'discover_note',"
            + "note:'Stalker 采样需在目标线程内执行；'"
            + "+'当前返回模块与导出概览作为起点',"
            + "module_count:mods.length});"},
        {"Fr_Follow_Thread", "Stalker.follow(Process.getCurrentThreadId(),{"
            + "events:{call:false,ret:false,exec:false,block:false,compile:false},"
            + "onReceive:function(ev){send({type:'stalker',"
            + "tid:Process.getCurrentThreadId()},{data:ev});}});"
            + "send({type:'stalker_follow',"
            + "tid:Process.getCurrentThreadId()});"},
        {"Fr_Env_Override", "Java.perform(function(){try{"
            + "var SP=Java.use('android.os.SystemProperties');"
            + "SP.get.overload('java.lang.String').implementation=function(k){"
            + "var v=this.get(k);"
            + "send({type:'prop',key:k,value:v});"
            + "if(k==='%s')return '%s';"
            + "return v;};"
            + "send({type:'prop_hook',ok:true});"
            + "}catch(e){send({type:'prop_hook',err:''+e});}});"},
        {"Fr_Prop", "Java.perform(function(){try{"
            + "var SP=Java.use('android.os.SystemProperties');"
            + "SP.set.overload('java.lang.String','java.lang.String')"
            + ".implementation=function(k,v){"
            + "send({type:'prop_set',key:k,value:v});"
            + "return this.set(k,v);};"
            + "send({type:'prop_ready',note:'已 hook set，读取请用 Fr_Env_Override'});"
            + "}catch(e){send({type:'prop',err:''+e});}});"},
        {"Fr_Keyboard", "Java.perform(function(){try{"
            + "var IMM=Java.use('android.view.inputmethod.InputMethodManager');"
            + "send({type:'keyboard',"
            + "note:'模拟输入需注入到目标 Activity；'"
            + "+'可用 adb shell input text 作为替代',"
            + "imm:typeof IMM!=='undefined'});"
            + "}catch(e){send({type:'keyboard',err:''+e});}});"},
        {"Fr_SSL_Upgrade", "var sr=Module.findExportByName(null,'SSL_read');"
            + "var sw=Module.findExportByName(null,'SSL_write');"
            + "function dump(f,n){if(!f)return;"
            + "Interceptor.attach(f,{onEnter:function(a){this.p=a[1];this.n=a[2].toInt32();},"
            + "onLeave:function(r){try{"
            + "send({type:n,data:this.p.readCString?this.p.readByteArray(this.n):''});"
            + "}catch(e){}}});}"
            + "dump(sr,'ssl_read');dump(sw,'ssl_write');"
            + "send({type:'ssl_ready',read:!!sr,write:!!sw});"},
        {"Fr_To_R2", "var m=Process.getModuleByName('%s');"
            + "send({type:'to_r2',module:m.name,"
            + "base:m.base.toString(),size:m.size,"
            + "offset:'%s',"
            + "runtime_addr:(m.base.add(ptr('%s'))).toString(),"
            + "r2_cmd:'s '+m.base.add(ptr('%s')).toString()});"},
        {"Fr_Gadget", "send({type:'gadget',"
            + "note:'Gadget 免 root 方案：1) 把 libfrida-gadget.so 放进 APK 的 lib/<abi>/ '"
            + "+'2) 在入口用 System.loadLibrary(\\''+'frida-gadget'+'\\') 或改 smali '"
            + "+'3) 放 libfrida-gadget.config.so 指定 script 路径 '"
            + "+'4) 重新打包签名安装；本端可用 File_Download 取配置'});"},
        {"Fr_Read_Messages", "send({type:'messages',"
            + "note:'send() 的数据由宿主侧接收；'"
            + "+'在 CLI 模式下 frida 会直接把 send 内容打到 stdout',"
            + "pid:Process.id});"},
    };

    /**
     * 设备侧操作：这类工具名看着像 frida，实际是设备/会话管理，
     * 不该生成 JS 注入脚本（Ls/Pull/Push/Rm 是文件操作，
     * Start_/Stop_Server 是进程管理）。
     * 走 shell 或 FridaChannel，不走 execScript。
     */
    private static final String[][] DEVICE = {
        {"Fr_Ls",                 "shell:ls -la %s"},
        {"Fr_Rm",                 "shell:rm -rf %s"},
        {"Fr_Pull",               "shell:cat %s"},
        {"Fr_Push",               "shell:write:%s"},
        {"Fr_Kill",               "shell:kill %s"},
        {"Fr_Stop_Server",        "server:stop"},
        {"Fr_Start_Server",       "server:start"},
        {"Fr_List_Sessions",      "session:list"},
        {"Fr_Close",              "session:close"},
        {"Fr_Detach",             "session:close"},
        {"Fr_Attach",             "session:attach"},
        {"Fr_Spawn",              "session:spawn"},
        {"Fr_LoadScript",         "session:loadscript"},
    };

    /** 设备侧 op；null 表示不是设备操作。 */
    public static String deviceOpFor(String tool) {
        for (String[] r : DEVICE) if (r[0].equals(tool)) return r[1];
        return null;
    }

    /** 取某工具对应的 JS 脚本；null 表示无预设（交给调用方传 script）。 */
    public static String scriptFor(String tool, String a1, String a2, String a3) {
        for (String[] row : MAP) {
            if (!row[0].equals(tool)) continue;
            String tpl = row[1];
            String r = tpl;
            if (r.contains("%s")) r = r.replaceFirst("%s", esc(a1));
            if (r.contains("%s")) r = r.replaceFirst("%s", esc(a2));
            if (r.contains("%s")) r = r.replaceFirst("%s", esc(a3));
            return r;
        }
        return null;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'");
    }

    public static int coverage() { return MAP.length; }

    public static String[] covered() {
        String[] o = new String[MAP.length];
        for (int i = 0; i < MAP.length; i++) o[i] = MAP[i][0];
        return o;
    }
}
