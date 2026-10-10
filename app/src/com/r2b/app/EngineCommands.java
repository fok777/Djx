package com.r2b.app;

/**
 * Blutter / Il2Cpp / Nav / Pentest 四类工具 → 具体操作（op）的映射表。
 *
 * 与 R2Commands、FridaScripts 同一思路：
 *   这类工具名看着多（66 / 42 / 23 / 12），但落到已解析出来的数据上，
 *   绝大多数只是"从同一份结果里取不同切片 / 按关键词过滤"。
 *   逐个手写分支既写不完也易漏，用表批量派生才对。
 *
 * op 语义交给 ToolExecutor 解释执行：
 *   blutter.*  —— 基于 libapp.so 解析结果（ELF 符号 + 字符串）
 *   il2cpp.*   —— 基于 libil2cpp.so 解析结果
 *   nav.*      —— 基于 radare2 的函数/引用数据
 *   pentest.*  —— 基于字符串关键词扫描
 */
public final class EngineCommands {

    private EngineCommands() {}

    // ---------------- Blutter (66) ----------------
    private static final String[][] BLUTTER = {
        {"Blutter_Analyze",        "blutter.overview"},
        {"Blutter_Info",           "blutter.overview"},
        {"Blutter_AOT",            "blutter.aot"},
        {"Blutter_Strings",        "blutter.strings"},
        {"Blutter_Functions",      "blutter.functions"},
        {"Blutter_Classes",        "blutter.classes"},
        {"Blutter_Class_Detail",   "blutter.class.detail"},
        {"Blutter_Class_Methods",  "blutter.class.methods"},
        {"Blutter_Methods",        "blutter.methods"},
        {"Blutter_Method_Detail",  "blutter.method.detail"},
        {"Blutter_Fields",         "blutter.fields"},
        {"Blutter_Symbols",        "blutter.symbols"},
        {"Blutter_Imports",        "blutter.imports"},
        {"Blutter_Disassemble",    "blutter.disasm"},
        {"Blutter_Inspect",        "blutter.overview"},
        {"Blutter_Const",          "blutter.strings"},
        {"Blutter_Enum",           "blutter.strings"},
        {"Blutter_Closure",        "blutter.functions"},
        {"Blutter_Heap",           "blutter.strings"},
        {"Blutter_Async",          "blutter.functions"},
        {"Blutter_Mixin",          "blutter.classes"},
        {"Blutter_Extension",      "blutter.classes"},
        {"Blutter_Implement",      "blutter.classes"},
        {"Blutter_Inherits",       "blutter.classes"},
        {"Blutter_Superclass",     "blutter.classes"},
        {"Blutter_TypeArgs",       "blutter.classes"},
        {"Blutter_Mirror",         "blutter.classes"},
        {"Blutter_Object_Layouts", "blutter.fields"},
        {"Blutter_PP_Table",       "blutter.pp"},
        {"Blutter_Isolate",        "blutter.isolate"},
        {"Blutter_GC",             "blutter.isolate"},
        {"Blutter_VM_Cmd",         "blutter.vm"},
        {"Blutter_Version_Adapt",  "blutter.version"},
        {"Blutter_Lib",            "blutter.lib"},
        {"Blutter_Package",        "blutter.package"},
        {"Blutter_Routes",         "blutter.routes"},
        {"Blutter_Route_Map",      "blutter.routes"},
        {"Blutter_Widgets",        "blutter.widgets"},
        {"Blutter_Widget_Tree",    "blutter.widgets"},
        {"Blutter_Localizations",  "blutter.strings"},
        {"Blutter_Resources",      "blutter.resources"},
        {"Blutter_Asset_Icons",    "blutter.resources"},
        {"Blutter_Network_Urls",   "blutter.urls"},
        {"Blutter_Search",         "blutter.search"},
        {"Blutter_Find_Instances", "blutter.search"},
        {"Blutter_Resolve",        "blutter.search"},
        {"Blutter_Exception_Sites","blutter.exceptions"},
        {"Blutter_StackTrace",     "blutter.exceptions"},
        {"Blutter_Snapshot",       "blutter.snapshot"},
        {"Blutter_Heap_Dump",      "blutter.snapshot"},
        {"Blutter_Logs",           "blutter.logs"},
        {"Blutter_Channel",        "blutter.strings"},
        {"Blutter_Frida",          "blutter.tofrida"},
        {"Blutter_To_Frida_Hook",  "blutter.tofrida"},
        {"Blutter_To_R2",          "blutter.tor2"},
        {"Blutter_Annotate_R2",    "blutter.tor2"},
        {"Blutter_Annotate",       "blutter.tor2"},
        {"Blutter_To_Unidbg_Call", "blutter.tounidbg"},
        {"Blutter_Patch",          "blutter.patch"},
        {"Blutter_Modify_String",  "blutter.patch"},
        {"Blutter_Plugin",         "blutter.plugin"},
        {"Blutter_Dart_Access",    "blutter.dart"},
        {"Blutter_Decode_Base64",  "blutter.decode64"},
        {"Blutter_Decode_UTF16",   "blutter.decode16"},
        {"Blutter_List_Sessions",  "blutter.sessions"},
        {"Blutter_Close",          "blutter.close"},
    };

    // ---------------- Il2Cpp (42) ----------------
    private static final String[][] IL2CPP = {
        {"Il2Cpp_Open",            "il2cpp.open"},
        {"Il2Cpp_Analyze",         "il2cpp.overview"},
        {"Il2Cpp_Dump",            "il2cpp.overview"},
        {"Il2Cpp_Read",            "il2cpp.overview"},
        {"Il2Cpp_Version",         "il2cpp.version"},
        {"Il2Cpp_Version_Detect",  "il2cpp.version"},
        {"Il2Cpp_Metadata_Info",   "il2cpp.metadata"},
        {"Il2Cpp_Metadata_Parse",  "il2cpp.metadata"},
        {"Il2Cpp_Classes",         "il2cpp.classes"},
        {"Il2Cpp_Class_Detail",    "il2cpp.class.detail"},
        {"Il2Cpp_Methods",         "il2cpp.methods"},
        {"Il2Cpp_Method_Detail",   "il2cpp.method.detail"},
        {"Il2Cpp_Fields",          "il2cpp.fields"},
        {"Il2Cpp_Field_Defs",      "il2cpp.fields"},
        {"Il2Cpp_Find_Method",     "il2cpp.find.method"},
        {"Il2Cpp_Find_Field",      "il2cpp.find.field"},
        {"Il2Cpp_Find_Type",       "il2cpp.find.type"},
        {"Il2Cpp_Types",           "il2cpp.types"},
        {"Il2Cpp_Type_Defs",       "il2cpp.types"},
        {"Il2Cpp_Enums",           "il2cpp.enums"},
        {"Il2Cpp_Interfaces",      "il2cpp.interfaces"},
        {"Il2Cpp_Properties",      "il2cpp.properties"},
        {"Il2Cpp_Namespaces",      "il2cpp.namespaces"},
        {"Il2Cpp_Assemblies",      "il2cpp.assemblies"},
        {"Il2Cpp_Strings",         "il2cpp.strings"},
        {"Il2Cpp_Struct",          "il2cpp.struct"},
        {"Il2Cpp_Symbol_Restore",  "il2cpp.symbols"},
        {"Il2Cpp_So_Scan",         "il2cpp.scan"},
        {"Il2Cpp_Script_Json",     "il2cpp.scriptjson"},
        {"Il2Cpp_Search",          "il2cpp.search"},
        {"Il2Cpp_Csharp_Source",   "il2cpp.csharp"},
        {"Il2Cpp_Dummy_DLL",       "il2cpp.dummydll"},
        {"Il2Cpp_Export",          "il2cpp.export"},
        {"Il2Cpp_Import_IDA",      "il2cpp.export.ida"},
        {"Il2Cpp_Import_R2",       "il2cpp.export.r2"},
        {"Il2Cpp_To_R2",           "il2cpp.export.r2"},
        {"Il2Cpp_RVA_Table",       "il2cpp.rva"},
        {"Il2Cpp_RVA_Patch",       "il2cpp.rva"},
        {"Il2Cpp_Gameplay_Scan",   "il2cpp.gameplay"},
        {"Il2Cpp_Cheatable_Scan",  "il2cpp.gameplay"},
        {"Il2Cpp_AntiCheat_Scan",  "il2cpp.anticheat"},
        {"Il2Cpp_List_Sessions",   "il2cpp.sessions"},
        {"Il2Cpp_Close",           "il2cpp.close"},
    };

    // ---------------- Nav (23)：落到 radare2 ----------------
    private static final String[][] NAV = {
        {"Nav_Load",              "r2:iI"},
        {"Nav_BuildGraph",        "r2:agf"},
        {"Nav_Build_Call_Graph",  "r2:agc"},
        {"Nav_CallChain",         "r2:agc"},
        {"Nav_Call_Chain",        "r2:agc"},
        {"Nav_ExportGraph",       "r2:agfd"},
        {"Nav_Export_Graph",      "r2:agfd"},
        {"Nav_Mermaid",           "r2:agfw"},
        {"Nav_Function",          "r2:pdf"},
        {"Nav_Function_Context",  "r2:afij"},
        {"Nav_Stats",             "r2:aflc"},
        {"Nav_Modules",           "r2:om"},
        {"Nav_Symbol_Jump",       "r2:is~%s"},
        {"Nav_Who_Calls",         "r2:axt"},
        {"Nav_What_Calls",        "r2:axf"},
        {"Nav_Reverse_Search",    "r2:axt"},
        {"Nav_Cycle",             "r2:agc"},
        {"Nav_DFS",               "r2:agc"},
        {"Nav_Dominators",        "r2:agd"},
        {"Nav_Patch_Candidates",  "r2:/x %s"},
        {"Nav_Deobfuscate_Guide", "guide:deobf"},
        {"Nav_List_Sessions",     "r2:o"},
        {"Nav_Close",             "r2:o-*"},
    };

    // ---------------- Pentest (12)：关键词扫描 ----------------
    private static final String[][] PENTEST = {
        {"Pentest_Key_Extract",     "scan:key"},
        {"Pentest_Cred_Hunt",       "scan:cred"},
        {"Pentest_Auth_Extract",    "scan:auth"},
        {"Pentest_Auth_Bypass",     "scan:auth"},
        {"Pentest_CertPin_Extract", "scan:pin"},
        {"Pentest_SSL_Bypass",      "scan:ssl"},
        {"Pentest_SSL_Upgrade",     "scan:ssl"},
        {"Pentest_Sign_Bypass",     "scan:sign"},
        {"Pentest_Endpoint_Extract","scan:url"},
        {"Pentest_C2_Trace",        "scan:c2"},
        {"Pentest_Server_Fingerprint","scan:server"},
        {"Pentest_Traffic_Replay",  "scan:replay"},
    };

    public static String opFor(String tool) {
        for (String[] r : BLUTTER) if (r[0].equals(tool)) return r[1];
        for (String[] r : IL2CPP)  if (r[0].equals(tool)) return r[1];
        for (String[] r : NAV)     if (r[0].equals(tool)) return r[1];
        for (String[] r : PENTEST) if (r[0].equals(tool)) return r[1];
        return null;
    }

    /** 类别判定，供 ToolExecutor 路由。 */
    public static String kindOf(String tool) {
        for (String[] r : BLUTTER) if (r[0].equals(tool)) return "blutter";
        for (String[] r : IL2CPP)  if (r[0].equals(tool)) return "il2cpp";
        for (String[] r : NAV)     if (r[0].equals(tool)) return "nav";
        for (String[] r : PENTEST) if (r[0].equals(tool)) return "pentest";
        return null;
    }

    public static int coverage() {
        return BLUTTER.length + IL2CPP.length + NAV.length + PENTEST.length;
    }
}
