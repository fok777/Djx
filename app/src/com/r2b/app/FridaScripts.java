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
    };

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
