"""
engine/legacy_tools.py — 【已归档，未接入】

旧版工具清单，现由 r2b_mcp/tools_registry.py 取代（仅存档参考）。
保留仅作参考，如确认无用可直接删除本文件。
"""
from typing import Dict, Any, List

GS = {"type": "object", "properties": {
    "so_path": {"type": "string"}, "session_id": {"type": "string"}, "address": {"type": "string"},
    "func": {"type": "string"}, "keyword": {"type": "string"}, "query": {"type": "string"},
    "cmd": {"type": "string"}, "count": {"type": "integer"}}, "required": []}


def F(op):  # Frida 动态
    return ("frida_ops", {"op": op})


def R2c(cmd):  # R2 通用命令
    return ("r2_xcmds", {"cmd": cmd})


def N(op):
    return ("nav", {"op": op})


def P(op):
    return ("project", {"op": op})


# (类, [ (name, desc, route, args) ... ])
GROUPS: List = [
    ("Frida", [
        ("Fr_Detect", "检测Frida环境/设备", *F("detect")),
        ("Fr_Attach", "attach目标", *F("attach")),
        ("Fr_Spawn", "spawn目标", *F("spawn")),
        ("Fr_Detach", "detach", *F("detach")),
        ("Fr_Kill", "杀进程(需root)", *F("kill")),
        ("Fr_Ps", "进程列表", *F("ps")),
        ("Fr_Apps", "列第三方App(需root)", *F("apps")),
        ("Fr_Cmd", "Frida命令", *F("cmd")),
        ("Fr_Eval", "执行JS表达式", *F("eval")),
        ("Fr_Discover", "发现符号", *F("discover")),
        ("Fr_Trace", "trace函数", *F("trace")),
        ("Fr_Native_Hook", "native hook", *F("native_hook")),
        ("Fr_Watch_Class", "watch类", *F("watch_class")),
        ("Fr_Find_Callers", "找调用者", *F("find_callers")),
        ("Fr_Dump_Memory", "dump内存", *F("dump_memory")),
        ("Fr_Read_Messages", "读IPC消息", *F("read_messages")),
        ("Fr_SSL_Pinning_Disable", "绕SSL Pinning", *F("ssl_pinning_disable")),
        ("Fr_Root_Detect_Bypass", "绕Root检测", *F("root_detect_bypass")),
        ("Fr_LoadScript", "载入本地脚本(需root)", *F("load_script")),
        ("Fr_Start_Server", "启frida-server(需root)", *F("start_server")),
        ("Fr_Stop_Server", "停frida-server(需root)", *F("stop_server")),
        ("Fr_Search", "搜", *F("search")),
        ("Fr_Strings", "字符串", *F("strings")),
        ("Fr_Classes", "类", *F("classes")),
        ("Fr_Exports", "导出符号", *F("exports")),
        ("Fr_Libraries", "so库列表", *F("libraries")),
        ("Fr_Info", "目标信息", *F("info")),
        ("Fr_Ls", "列文件", *F("ls")),
        ("Fr_Rm", "删文件", *F("rm")),
        ("Fr_Pull", "pull文件", *F("pull")),
        ("Fr_Push", "push文件", *F("push")),
        ("Fr_Patch_Bytes", "运行时改内存热补丁(免重打包)*", *F("patch_bytes")),
        ("Fr_Read_Bytes", "读内存验证热补丁*", *F("read_bytes")),
        ("Fr_To_R2", "Frida结果喂R2", "bridge", {"bridge": "fr_to_r2"}),
        ("Fr_Close", "关Fr会话", "session_info", {}),
        ("Fr_List_Sessions", "列Fr会话", "session_info", {}),
        ("Fr_Gadget", "io_frida gadget注入*", *F("gadget")),
        ("Fr_StackTrace", "堆栈回溯*", *F("stack")),
        ("Fr_Overload", "列重载方法*", *F("overload")),
        ("Fr_Heap_Scan", "堆扫描对象*", *F("heap_scan")),
        ("Fr_Eval_Java", "Java.perform求值*", *F("eval_java")),
        ("Fr_Enumerate_Export", "枚举导出*", *F("enum_export")),
    ]),
    ("Radare2", [
        ("R2_Open", "打开so建索引+后台导伪C", "r2_open", {}),
        ("R2_Close", "关R2会话释放缓存", "session_info", {}),
        ("R2_Cmd", "任意r2命令(最通用)", "r2_xcmds", {}),
        ("R2_Analyze", "自动分析(afaa)", *R2c("afaa")),
        ("R2_Disassemble", "反汇编", *R2c("pd")),
        ("R2_Get_PseudoC", "出伪C(内存毫秒级)", "r2_pseudo_c", {}),
        ("R2_Decompile_Function", "反编译函数", "r2_pseudo_c", {}),
        ("R2_Xrefs", "交叉引用", *R2c("axt")),
        ("R2_Manage_Xrefs", "xref管理", *R2c("axt")),
        ("R2_Hexdump", "hexdump", *R2c("px")),
        ("R2_Sections", "节表", *R2c("iS")),
        ("R2_Imports", "导入表", *R2c("iE")),
        ("R2_Exports", "导出表", *R2c("iE")),
        ("R2_Entries", "入口", *R2c("ie")),
        ("R2_Strings", "字符串", *R2c("is")),
        ("R2_Seek", "定位", *R2c("s")),
        ("R2_Search", "搜索", "r2_search", {}),
        ("R2_Search_String", "搜字符串", "r2_search", {}),
        ("R2_Search_Functions", "搜函数", *R2c("afl")),
        ("R2_Search_PseudoC", "搜伪C", *R2c("pd")),
        ("R2_Functions", "函数清单", *R2c("afl")),
        ("R2_Hash", "哈希", *R2c("ph")),
        ("R2_Patch", "写补丁", "r2_write_patch", {}),
        ("R2_Info", "so信息", "r2_open", {}),
        ("R2_Version", "R2版本", "status", {}),
        ("R2_Analyze_File", "分析文件", "r2_open", {}),
        ("R2_Analyze_Target", "分析目标", "r2_open", {}),
        ("R2_Export_PseudoC_To_File", "导出伪C到文件", "export_r2cmd", {}),
        ("R2_List_Sessions", "列R2会话", "session_info", {}),
        ("R2_Arch", "设目标架构(arm/arm64)*", *R2c("e arch=arm64")),
        ("R2_Blocks", "基础块*", *R2c("dfj")),
        ("R2_Types", "类型*", *R2c("tj")),
        ("R2_Globals", "全局变量*", *R2c("dgj")),
        ("R2_Symbols", "符号*", *R2c("syj")),
        ("R2_Map", "内存映射*", *R2c("om")),
    ]),
    ("Unidbg", [
        ("Ub_Open", "加载so到模拟器", "unidbg_call", {}),
        ("Ub_Close", "关闭模拟器", "session_info", {}),
        ("Ub_Call", "按导出符号名调用", "unidbg_call", {}),
        ("Ub_Call_Offset", "按模块偏移调用(无符号内部函数)*", "unidbg_call", {}),
        ("Ub_Dump", "读模拟器内存(dump输出)*", "unidbg_call", {}),
        ("Ub_Modules", "列已加载模块及基址", "unidbg_call", {}),
        ("Ub_List_Sessions", "列unidbg会话", "session_info", {}),
        ("Ub_Session", "会话信息*", "session_info", {}),
        ("Ub_Env", "设环境变量*", "unidbg_call", {}),
        ("Ub_Syscall", "系统调用跟踪*", "unidbg_call", {}),
        ("Ub_Register_JNI", "注册JNI方法*", "unidbg_call", {}),
        ("Ub_Stub", "stub系统调用*", "unidbg_call", {}),
        ("Ub_Malloc", "模拟内存分配*", "unidbg_call", {}),
        ("Ub_File_Read", "模拟文件读*", "unidbg_call", {}),
        ("Ub_File_Write", "模拟文件写*", "unidbg_call", {}),
        ("Ub_Dlopen", "加载依赖so*", "unidbg_call", {}),
        ("Ub_Java_Call", "调Java方法*", "unidbg_call", {}),
        ("Ub_Print_Stack", "打印调用栈*", "unidbg_call", {}),
        ("Ub_Backtrace", "回溯*", "unidbg_call", {}),
        ("Ub_Close_Session", "关指定会话*", "session_info", {}),
        ("Ub_Info", "模拟器信息*", "status", {}),
    ]),
    ("IL2CPP", [
        ("Il2Cpp_Dump", "解析IL2CPP出dump.cs", "il2cpp_dump", {}),
        ("Il2Cpp_Search", "统一搜类/方法/字符串", "il2cpp_strings", {}),
        ("Il2Cpp_Read", "按行读dump.cs", "il2cpp_strings", {}),
        ("Il2Cpp_Classes", "搜类型(类名/程序集/父类/字段数)", "il2cpp_strings", {}),
        ("Il2Cpp_Strings", "搜硬编码字符串", "il2cpp_strings", {}),
        ("Il2Cpp_Methods", "搜方法*", "il2cpp_strings", {}),
        ("Il2Cpp_Fields", "搜字段*", "il2cpp_strings", {}),
        ("Il2Cpp_To_R2", "进native分析", "bridge", {"bridge": "il2cpp_to_r2"}),
        ("Il2Cpp_Gameplay_Scan", "按玩法分类捕捉目标*", "il2cpp_strings", {}),
        ("Il2Cpp_Struct", "结构体*", "il2cpp_strings", {}),
        ("Il2Cpp_Script_Json", "出script.json*", "il2cpp_dump", {}),
        ("Il2Cpp_Version", "Unity版本*", "il2cpp_dump", {}),
        ("Il2Cpp_Enums", "枚举*", "il2cpp_strings", {}),
        ("Il2Cpp_Interfaces", "接口*", "il2cpp_strings", {}),
        ("Il2Cpp_Properties", "属性*", "il2cpp_strings", {}),
    ]),
    ("Nav导航", [
        ("Nav_BuildGraph", "建函数调用图(Blutter/r2/IL2CPP)", *N("build")),
        ("Nav_ExportGraph", "导出调用图JSON", *N("export")),
        ("Nav_Modules", "模块划分(包名+类名聚类)", *N("modules")),
        ("Nav_Function", "函数360度视图", *N("function")),
        ("Nav_CallChain", "查调用路径", *N("callchain")),
        ("Nav_Stats", "导航图统计", *N("stats")),
        ("Nav_Mermaid", "导出Mermaid*", *N("mermaid")),
        ("Nav_Cycle", "找循环调用*", *N("cycle")),
        ("Nav_DFS", "深度搜索*", *N("dfs")),
        ("Nav_Patch_Candidates", "补丁点候选*", *N("patch_candidates")),
        ("Nav_Load", "载入已存图*", *N("load")),
        ("Nav_Close", "关导航图*", *N("close")),
    ]),
    ("APK会话", [
        ("Apk_Open", "打开识别类型(第1步)", "apk_open", {}),
        ("Apk_Close", "关APK会话+清临时so", "session_info", {}),
        ("Apk_Install", "root静默安装(任意本地路径)", "apk_install", {}),
        ("Apk_Diff", "两APK差异(native毫秒级)", "apk_diff", {}),
        ("Apk_Pack", "改so替换回APK重打包签名", "pack_output", {}),
    ]),
    ("Project", [
        ("Project_Save", "保存当前分析状态为项目", *P("save")),
        ("Project_Load", "加载已存项目", *P("load")),
        ("Project_List", "列出所有项目", *P("list")),
        ("Project_Delete", "删指定项目", *P("delete")),
        ("Project_Export", "导出Markdown/HTML分析报告", *P("export")),
    ]),
    ("Blutter", [
        ("Blutter_Analyze", "秒级全量解析Dart符号", "blutter_analyze", {}),
        ("Blutter_Strings", "Dart字符串全索引", "blutter_strings", {}),
        ("Blutter_Functions", "Dart函数全签名", "blutter_functions", {}),
        ("Blutter_Classes", "Dart类清单", "dex_classes", {}),
        ("Blutter_Class_Detail", "类细节(字段/方法)", "dex_classes", {}),
        ("Blutter_Methods", "方法清单*", "dex_classes", {}),
        ("Blutter_Method_Detail", "方法细节*", "dex_classes", {}),
        ("Blutter_Fields", "字段*", "dex_classes", {}),
        ("Blutter_Disassemble", "反汇编Dart函数", *R2c("pd")),
        ("Blutter_Dart_Access", "读写Dart对象内存", "frida_dynamic", {"op": "dart_access"}),
        ("Blutter_Find_Instances", "找Dart对象实例", "frida_dynamic", {"op": "find_instances"}),
        ("Blutter_Object_Layouts", "对象布局", "frida_dynamic", {"op": "object_layouts"}),
        ("Blutter_PP_Table", "页表快照", "frida_dynamic", {"op": "pp_table"}),
        ("Blutter_Modify_String", "改Dart字符串", "frida_dynamic", {"op": "modify_string"}),
        ("Blutter_Patch", "写补丁到so", "r2_write_patch", {}),
        ("Blutter_To_R2", "跳Radare2看伪C", "blutter_to_r2", {}),
        ("Blutter_To_Frida_Hook", "生成Frida hook", "frida_ops", {"op": "attach"}),
        ("Blutter_To_Unidbg_Call", "unidbg模拟调用", "unidbg_call", {}),
        ("Blutter_Annotate_R2", "符号导入Radare2", "export_r2cmd", {}),
        ("Blutter_Info", "Blutter会话信息", "status", {}),
        ("Blutter_List_Sessions", "列Blutter会话", "session_info", {}),
        ("Blutter_Logs", "Blutter日志", "status", {}),
        ("Blutter_Close", "关Blutter会话", "session_info", {}),
        ("Blutter_Heap", "Dart堆信息*", "frida_dynamic", {"op": "heap"}),
        ("Blutter_GC", "GC对象*", "frida_dynamic", {"op": "gc"}),
        ("Blutter_Closure", "闭包/方法引用*", "frida_dynamic", {"op": "closure"}),
        ("Blutter_Inherits", "类继承关系*", "dex_classes", {}),
        ("Blutter_Imports", "Dart import*", "dex_classes", {}),
        ("Blutter_Async", "异步方法*", "dex_classes", {}),
        ("Blutter_Enum", "枚举*", "dex_classes", {}),
        ("Blutter_Const", "常量*", "dex_classes", {}),
        ("Blutter_Search", "Dart符号搜索*", "blutter_strings", {}),
        ("Blutter_Version_Adapt", "Dart版本自适应*", "blutter_version_adapt", {}),
        ("Blutter_Package", "包名清单*", "dex_classes", {}),
        ("Blutter_Widgets", "Flutter Widget树*", "dex_classes", {}),
        ("Blutter_Routes", "路由表*", "dex_classes", {}),
        ("Blutter_Localizations", "本地化串*", "blutter_strings", {}),
        ("Blutter_Isolate", "Isolate*", "frida_dynamic", {"op": "isolate"}),
        ("Blutter_Mirror", "dart:mirror*", "frida_dynamic", {"op": "mirror"}),
        ("Blutter_AOT", "AOT快照*", "blutter_analyze", {}),
        ("Blutter_Snapshot", "快照摘要*", "blutter_analyze", {}),
        ("Blutter_Lib", "lib清单*", "dex_classes", {}),
        ("Blutter_Plugin", "插件*", "dex_classes", {}),
        ("Blutter_Channel", "MethodChannel*", "dex_classes", {}),
        ("Blutter_Extension", "扩展方法*", "dex_classes", {}),
        ("Blutter_Mixin", "mixin*", "dex_classes", {}),
        ("Blutter_Superclass", "超类*", "dex_classes", {}),
        ("Blutter_Implement", "实现接口*", "dex_classes", {}),
        ("Blutter_TypeArgs", "类型参数*", "dex_classes", {}),
        ("Blutter_Annotate", "注解*", "dex_classes", {}),
        ("Blutter_StackTrace", "Dart堆栈*", "frida_dynamic", {"op": "stack"}),
        ("Blutter_Inspect", "对象inspect*", "frida_dynamic", {"op": "inspect"}),
        ("Blutter_Resolve", "符号解析*", *R2c("afl")),
        ("Blutter_Symbols", "全部符号*", "blutter_functions", {}),
    ]),
    ("搜索/终端", [
        ("Search_All", "全量关键词搜索*", "r2_search", {}),
        ("Search_String", "搜字符串*", "r2_search", {}),
        ("Search_Symbol", "搜符号*", *R2c("iS")),
        ("Search_Xref", "搜交叉引用*", *R2c("axt")),
        ("Search_Regex", "正则搜*", *R2c("s//")),
        ("Search_URL", "搜URL/域名*", "r2_search", {}),
        ("Search_Secret", "搜密钥/token*", "r2_search", {}),
        ("Term", "执行r2命令(终端)*", "r2_xcmds", {}),
        ("Log_Level", "设日志级别*", "status", {}),
        ("Log_Tail", "看日志*", "status", {}),
        ("Progress", "任务进度*", "status", {}),
        ("Overview", "总览(架构/符号/字符串统计)*", "status", {}),
        ("Help", "工具帮助*", "status", {}),
        ("History", "命令历史*", "status", {}),
        ("Version", "R2B版本*", "status", {}),
    ]),
]


def build_legacy_tools() -> List[Dict[str, Any]]:
    tools = []
    for eng, items in GROUPS:
        for it in items:
            name, desc = it[0], it[1]
            route, args = it[2], it[3]
            tools.append({"name": name, "desc": f"[{eng}] {desc}",
                          "schema": GS, "route": route, "args": args})
    return tools


LEGACY_COUNT = sum(len(g[1]) for g in GROUPS)
