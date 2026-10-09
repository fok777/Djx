"""
r2b_mcp/tools_registry.py — 工具总表

工具数量由 SPEC 决定，不要在注释里写死数字（历史注释曾出现多个互相矛盾的
数字，已由 r2b_mcp/audit.py 在启动时自动比对并告警）。

每个工具：name / description / inputSchema / route(引擎函数名) / category。
route 由工具名小写化推导（见 _route），R2_Locate_* 系列统一路由到
r2_locate_keyword 并带 keyword 参数。参数名到引擎形参的映射由 server._bind 完成。
"""
from typing import Dict, Any, List


def _schema(props: Dict[str, Any], req: List[str]) -> Dict:
    return {"type": "object", "properties": props, "required": req}


# 参数类型简写
S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
A_S = {"type": "array", "items": {"type": "string"}}
A_I = {"type": "array", "items": {"type": "integer"}}
O = {"type": "object"}
OPT = {**S, "description": "optional"}

# 工具定义：(name, description, properties, required)
SPEC: List[tuple] = [
    # ============ R2_* (Radare2 静态) ============
    ("R2_Version", "测试 r2 引擎是否可用并返回版本信息。首次使用前调用确认 r2 加载正常。", {}, []),
    ("R2_Open", "打开二进制(.so/.dex/.elf)建r2会话，自动建函数索引+后台全量伪C导出(≤5000内存/>5000 SQLite)。返回8位session_id。", {"so_path": S, "mode": OPT, "session_id": OPT}, ["so_path"]),
    ("R2_Close", "关闭r2会话并释放资源(含伪C缓存)。", {"session_id": S}, ["session_id"]),
    ("R2_Cmd", "执行任意r2命令。afl/af/pd/iz/axt/wao nop/CC/afn 等。", {"session_id": S, "command": S, "timeout": I}, ["session_id", "command"]),
    ("R2_Analyze", "对已打开二进制执行自动分析(aa快/aaa深)。", {"session_id": S, "mode": OPT}, ["session_id"]),
    ("R2_Disassemble", "反汇编指定地址机器码。", {"session_id": S, "address": OPT, "count": I}, ["session_id"]),
    ("R2_Seek", "移动光标到指定地址。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("R2_Info", "查看二进制元信息(架构/端序/入口/大小)。", {"session_id": S}, ["session_id"]),
    ("R2_Functions", "列出所有函数(从内存索引秒回)。", {"session_id": S, "keyword": OPT}, ["session_id"]),
    ("R2_Search_Functions", "按函数名模糊搜索定位，返回地址+大小+名字。", {"session_id": S, "query": S, "max_results": I}, ["session_id", "query"]),
    ("R2_Strings", "提取可打印字符串。iz快/izz全文件。", {"session_id": S, "mode": OPT, "timeout": I}, ["session_id"]),
    ("R2_Search_String", "按关键词搜可读字符串(多线程快，AI优先用此而非R2_Search)。", {"session_id": S, "query": S, "max_results": I}, ["session_id", "query"]),
    ("R2_Sections", "列出ELF段(Section)信息。", {"session_id": S}, ["session_id"]),
    ("R2_Imports", "列出导入的外部函数(动态链接符号)。", {"session_id": S}, ["session_id"]),
    ("R2_Hexdump", "十六进制+ASCII查看指定地址内存。", {"session_id": S, "address": OPT, "count": I}, ["session_id"]),
    ("R2_Calculate", "计算表达式/地址运算(支持十六进制)。", {"session_id": S, "expression": S}, ["session_id", "expression"]),
    ("R2_Xrefs", "查找谁调用指定地址的函数(需先R2_Analyze)。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("R2_List_Sessions", "列出所有活跃r2会话。", {}, []),
    ("R2_Hash", "计算文件哈希(md5/sha1/sha256)。", {"session_id": S, "type": OPT}, ["session_id"]),
    ("R2_Search", "搜十六进制字节模式(机器码/magic，非字符串)。", {"session_id": S, "pattern": S, "threads": I}, ["session_id", "pattern"]),
    ("R2_Entries", "列出入口点。", {"session_id": S}, ["session_id"]),
    ("R2_Exports", "列出导出符号(其他模块可调，.so即JNI导出)。", {"session_id": S}, ["session_id"]),
    ("R2_Decompile_Function", "实时反编译(r2ghidra pdg更准/缓存未命中备选)。", {"session_id": S, "address": S, "engine": OPT}, ["session_id", "address"]),
    ("R2_Get_PseudoC", "【首选】从预编译缓存取函数伪C，毫秒级。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("R2_Search_PseudoC", "在全量伪C中搜关键词/正则，返回地址+函数名+片段。", {"session_id": S, "query": S, "regex": B, "max_results": I}, ["session_id", "query"]),
    ("R2_PseudoC_Status", "查看后台全量伪C导出进度。", {"session_id": S}, ["session_id"]),
    ("R2_Export_PseudoC_To_File", "将全量伪C导出到文件。", {"session_id": S}, ["session_id"]),
    ("R2_Analyze_Target", "按策略局部递归分析(basic/blocks/calls/refs/pointers/full)。", {"session_id": S, "strategy": OPT, "address": OPT}, ["session_id"]),
    ("R2_Analyze_File", "快速通道:开文件→aa分析→列函数→关闭。", {"file_path": S, "session_id": OPT}, ["file_path"]),
    ("R2_Config_Manager", "读写r2运行期配置(e命令)。", {"session_id": S, "key": S, "value": OPT}, ["session_id", "key"]),
    ("R2_Analysis_Hints", "管理分析提示(ah系列)：覆盖架构/位数/跳转。", {"session_id": S, "action": OPT, "address": OPT, "arch": OPT, "bits": OPT, "target": OPT}, ["session_id"]),
    ("R2_Manage_Xrefs", "管理/查询/创建交叉引用(ax系列)。", {"session_id": S, "action": S, "target_address": S, "source_address": OPT}, ["session_id", "action", "target_address"]),
    ("Find_Jni_Methods", "搜索所有JNI导出函数(Java_xxx)。", {"session_id": S}, ["session_id"]),
    ("Apply_Hex_Patch", "对指定地址写十六进制字节补丁(NOP/改条件/注入)。", {"session_id": S, "address": S, "hex_bytes": S}, ["session_id", "address", "hex_bytes"]),
    ("Rename_Function", "重命名函数(afn)。", {"session_id": S, "address": S, "name": S}, ["session_id", "address", "name"]),
    ("Scan_Crypto_Signatures", "扫AES/DES/MD5/SHA常量特征定位加密。", {"session_id": S}, ["session_id"]),
    ("Shell_Command", "在Android设备执行Shell命令(use_root则以su执行)。", {"command": S, "use_root": B}, ["command"]),
    ("File_Download", "获取文件下载ID用于局域网下载。", {"apk_session_id": S}, ["apk_session_id"]),
    ("Sqlite_Query", "用原生SQLiteDatabase执行SQL(读SELECT/写DML)。", {"db_path": S, "query": S}, ["db_path", "query"]),

    # ============ Blutter_* (Flutter/Dart) ============
    ("Blutter_Analyze", "对Flutter的libapp.so做Dart快照分析(3-5秒)，缓存类/函数/字符串。", {"lib_app_path": S, "lib_flutter_path": OPT, "timeout_seconds": I}, ["lib_app_path"]),
    ("Blutter_Classes", "从内存缓存搜Dart类列表(毫秒级)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Class_Detail", "查看指定Dart类完整结构(继承/字段/方法)。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Blutter_Functions", "搜索所有Dart函数(毫秒级，内存缓存)。", {"session_id": S, "class_name": OPT, "filter": OPT}, ["session_id"]),
    ("Blutter_Disassemble", "查看Dart函数完整汇编(Butter Dart IR)。", {"session_id": S, "function_name": OPT, "open_r2": B}, ["session_id"]),
    ("Blutter_Strings", "搜Dart快照中的字符串常量(毫秒级)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_PP_Table", "读pp.txt池化对象表(类/函数/字符串在libapp.so的精确偏移)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Object_Layouts", "读objs.txt对象布局表(字段偏移/类型继承/大小)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Frida", "导出Frida Hook脚本(所有Dart函数Interceptor桩)。", {"session_id": S}, ["session_id"]),
    ("Blutter_To_R2", "【Blutter→r2桥】跳r2并seek到指定函数偏移。", {"session_id": S, "function_name": S}, ["session_id", "function_name"]),
    ("Blutter_Patch", "在native层修改Dart函数(ret/nop/custom)。", {"session_id": S, "function_name": S, "action": S, "bytes": OPT}, ["session_id", "function_name", "action"]),
    ("Blutter_Modify_String", "修改libapp.so中字符串常量(不能比原串长)。", {"session_id": S, "search_str": S, "replace_str": S}, ["session_id", "search_str", "replace_str"]),
    ("Blutter_To_Frida_Hook", "【Blutter→Frida桥】Blutter偏移→运行时地址→注入Hook。", {"blutter_session_id": S, "frida_session_id": S, "function_name": S, "hook_type": OPT, "replace_value": OPT, "module_hint": OPT}, ["blutter_session_id", "frida_session_id", "function_name"]),
    ("Blutter_Dart_Access", "【桥·运行时读写】objs.txt字段偏移→Frida读写字段。", {"blutter_session_id": S, "frida_session_id": S, "class_name": S, "action": S, "field_name": OPT, "instance_addr": OPT, "new_value": OPT}, ["blutter_session_id", "frida_session_id", "class_name", "action"]),
    ("Blutter_Find_Instances", "【桥·实例→字段】Hook类方法入口捕this指针。", {"blutter_session_id": S, "frida_session_id": S, "class_name": S, "method_name": OPT, "module_hint": OPT}, ["blutter_session_id", "frida_session_id", "class_name"]),
    ("Blutter_Info", "查看Blutter会话统计(Dart版本/类数/函数数/字符串数)。", {"session_id": S}, ["session_id"]),
    ("Blutter_Logs", "查看Blutter_Analyze执行日志。", {"session_id": S}, ["session_id"]),
    ("Blutter_Close", "关闭Blutter分析会话释放内存。", {"session_id": S}, ["session_id"]),
    ("Blutter_List_Sessions", "列出所有活跃Blutter会话。", {}, []),
    ("Blutter_Annotate_R2", "【Blutter→r2集成】IR字段偏移+pp字符串注入r2注释。", {"session_id": S, "function_filter": OPT, "annotate_pp": B, "pp_filter": OPT}, ["session_id"]),
    ("Blutter_To_Unidbg_Call", "【Blutter→Unidbg桥】取Dart函数偏移→unidbg调用。", {"session_id": S, "function_name": S, "args": OPT}, ["session_id", "function_name"]),

    # ============ Fr_* (Frida 动态) ============
    ("Fr_Detect", "【环境检查】检测设备frida可用性(先调此确认)。", {}, []),
    ("Fr_Start_Server", "启动frida-server(需root)。", {}, []),
    ("Fr_Stop_Server", "停止frida-server。", {}, []),
    ("Fr_Kill", "杀进程(PID或包名)。", {"target": S}, ["target"]),
    ("Fr_Apps", "列出第三方应用(包名+APK路径)。", {"filter": OPT}, []),
    ("Fr_LoadScript", "从本地文件加载JS脚本到Frida会话。", {"session_id": S, "script_path": S}, ["session_id", "script_path"]),
    ("Fr_SSL_Pinning_Disable", "【破防】绕过SSL Pinning校验。", {"session_id": S}, ["session_id"]),
    ("Fr_Root_Detect_Bypass", "【破防】绕过Root检测。", {"session_id": S}, ["session_id"]),
    ("Fr_Discover", "【热点发现】Stalker采样统计函数调用次数。", {"session_id": S, "duration_ms": I}, ["session_id"]),
    ("Fr_Trace", "【精确跟踪】跟踪指定函数每次调用记录参数/返回。", {"session_id": S, "target": S, "duration_ms": I}, ["session_id", "target"]),
    ("Fr_Ls", "列出目标设备文件/目录。", {"path": S}, ["path"]),
    ("Fr_Rm", "删除目标设备文件/目录。", {"path": S, "recursive": B}, ["path"]),
    ("Fr_Pull", "从设备远程路径复制到本地。", {"remote_path": S, "local_path": OPT}, ["remote_path"]),
    ("Fr_Push", "从本地推送到设备远程路径。", {"local_path": S, "remote_path": S}, ["local_path", "remote_path"]),
    ("Fr_Ps", "列出设备运行进程(类frida-ps)。", {"filter": OPT}, []),
    ("Fr_Attach", "【附加模式】附加到已运行进程建r2frida会话。", {"target": S, "timeout_ms": I}, ["target"]),
    ("Fr_Spawn", "【启动模式】冷启动App并在入口点前注入Frida。", {"app": S, "timeout_ms": I}, ["app"]),
    ("Fr_Detach", "断开Frida会话释放资源。", {"session_id": S}, ["session_id"]),
    ("Fr_Info", "查看Frida会话详情。", {"session_id": S}, ["session_id"]),
    ("Fr_Cmd", "在Frida会话执行r2frida命令(须:开头)。", {"session_id": S, "command": S}, ["session_id", "command"]),
    ("Fr_Eval", "【终极】在Frida会话执行任意JS。", {"session_id": S, "js_code": S}, ["session_id", "js_code"]),
    ("Fr_Native_Hook", "【探路·主力】Interceptor.attach拦native函数0行手写JS。", {"session_id": S, "func_offset": S, "module_name": OPT, "hook_type": OPT, "capture_caller": B, "caller_module": OPT}, ["session_id", "func_offset"]),
    ("Fr_Find_Callers", "【探路·反混淆】Hook系统函数抓调用方地址+调用栈。", {"session_id": S, "func_export": S, "caller_module": OPT, "module_hint": OPT}, ["session_id", "func_export"]),
    ("Fr_Read_Messages", "【收数据】收取Frida hook send()上报的异步数据。", {"session_id": S}, ["session_id"]),
    ("Fr_Dump_Memory", "【桥·内存→文件】目标进程模块内存dump到文件供R2离线分析。", {"session_id": S, "module_name": S, "output_path": OPT}, ["session_id", "module_name"]),
    ("Fr_To_R2", "【桥·Frida→R2】运行时地址→文件偏移→开R2并seek。", {"frida_session_id": S, "address": S, "blutter_session_id": OPT}, ["frida_session_id", "address"]),
    ("Fr_Watch_Class", "【便利】一键Hook Java类所有方法。", {"session_id": S, "class_name": S, "dump_args": B, "dump_ret": B, "dump_bt": B}, ["session_id", "class_name"]),
    ("Address_Lookup", "【查询】地址双向翻译：静态偏移↔Blutter，运行时↔模块+偏移。", {"blutter_session_id": S, "address": S, "frida_session_id": OPT}, ["blutter_session_id", "address"]),
    ("Fr_Libraries", "列出目标进程加载的动态库。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Fr_Exports", "列出某模块导出函数。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Fr_Strings", "搜目标进程内存中的字符串。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Fr_Classes", "列出目标进程加载的Java类。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Fr_Search", "在目标进程内存中搜十六进制模式。", {"session_id": S, "value": S, "type": OPT, "protection": OPT, "range_min": OPT, "range_max": OPT, "max_results": I}, ["session_id", "value"]),
    ("Fr_List_Sessions", "列出所有活跃Frida会话。", {}, []),
    ("Fr_Close", "关闭指定Frida会话。", {"session_id": S}, ["session_id"]),

    # ============ Ub_* (Unidbg 模拟) ============
    ("Ub_Open", "【Unidbg·第1步】加载so到模拟器并创建会话，执行JNI_OnLoad/init_array。", {"file": S, "call_jni": B}, ["file"]),
    ("Ub_Call", "按导出符号名调用函数(Java_自动补参数)。", {"session_id": S, "symbol": S, "args": OPT, "trace": B}, ["session_id", "symbol"]),
    ("Ub_Call_Offset", "按模块偏移调用函数(无符号内部函数)。", {"session_id": S, "offset": S, "args": OPT, "trace": B}, ["session_id", "offset"]),
    ("Ub_Dump", "读模拟器内存(输出缓冲区/解密结果/全局变量)。", {"session_id": S, "address": S, "size": I}, ["session_id", "address"]),
    ("Ub_Modules", "列出模拟器已加载模块及基址。", {"session_id": S}, ["session_id"]),
    ("Ub_List_Sessions", "列出所有活跃unidbg模拟会话。", {}, []),
    ("Ub_Close", "关闭模拟会话释放资源。", {"session_id": S}, ["session_id"]),
    ("Ub_Write", "写模拟器内存(hex)，写后回读校验。", {"session_id": S, "address": S, "hex_bytes": S}, ["session_id", "address", "hex_bytes"]),
    ("Ub_Regs", "读/写CPU寄存器(不传set返回x0-x28快照)。", {"session_id": S, "set": OPT}, ["session_id"]),
    ("Ub_Alloc", "模拟器内malloc内存返回指针。", {"session_id": S, "size": I, "init": OPT}, ["session_id", "size"]),
    ("Ub_Free", "释放Ub_Alloc分配的内存。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("Ub_Read_String", "读C字符串(遇\\0截断)。", {"session_id": S, "address": S, "max_len": I}, ["session_id", "address"]),
    ("Ub_Hook", "指定地址装执行hook，命中快照x0-x3/lr/sp。", {"session_id": S, "address": S, "max_hits": I}, ["session_id", "address"]),
    ("Ub_Hook_Hits", "读Ub_Hook命中记录，默认读后清空。", {"session_id": S, "keep": B}, ["session_id"]),
    ("Ub_Search", "内存中搜hex字节模式(机器码/常量)。", {"session_id": S, "pattern": S, "start": OPT, "size": I}, ["session_id", "pattern"]),
    ("Ub_Disasm", "capstone反汇编模拟器内存(运行时自解密后真实代码)。", {"session_id": S, "address": S, "count": I}, ["session_id", "address"]),
    ("Ub_Patch", "keystone汇编文本编译机器码写入内存(运行时patch)。", {"session_id": S, "address": S, "asm": S}, ["session_id", "address", "asm"]),
    ("Ub_Save_State", "保存CPU寄存器快照(反复调换参)。", {"session_id": S}, ["session_id"]),
    ("Ub_Restore_State", "恢复Ub_Save_State保存的寄存器快照。", {"session_id": S}, ["session_id"]),
    ("Ub_Dump_To_R2", "【Unidbg→R2桥】dump内存→r2反汇编ARM64。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("R2_To_Ub_Call", "【R2→Unidbg桥】从r2会话取函数偏移→unidbg调用。", {"session_id": S, "offset": S, "args": OPT}, ["session_id", "offset"]),
    ("Ub_Hook_To_R2_Xrefs", "【Unidbg→R2桥】对hook返回地址查交叉引用。", {"session_id": S, "address": S}, ["session_id", "address"]),

    # ============ Project_* ============
    ("Project_Save", "保存当前分析状态为项目。", {"session_id": OPT, "name": S, "file_path": OPT, "notes": OPT, "commands": OPT, "arch": OPT}, ["name"]),
    ("Project_Load", "加载之前保存的项目。", {"project_id": S}, ["project_id"]),
    ("Project_List", "列出所有已保存分析项目。", {}, []),
    ("Project_Delete", "删除指定已保存项目。", {"project_id": S}, ["project_id"]),
    ("Project_Export", "导出项目为分析报告(markdown/html)。", {"project_id": S, "format": OPT}, ["project_id"]),

    # ============ Apk_* ============
    ("Apk_Open", "【第1步】打开APK/SO，自动识别类型走不同流程。APK→解压+Flutter检测+Blutter；SO→直接r2。", {"file": S, "upload_id": OPT, "arch": OPT, "skip_blutter": B}, []),
    ("Apk_Close", "关闭APK会话:关Blutter+删临时解压文件。", {"session_id": S}, ["session_id"]),
    ("Apk_Install", "静默安装APK并启动，返回进程ID。", {"apk_session_id": S}, ["apk_session_id"]),
    ("Apk_Pack", "【打包】修改后的so替换回原APK并重新打包签名(带_成品后缀)。", {"apk_session_id": S, "do_sign": B}, ["apk_session_id"]),

    # ============ Os_* ============
    ("Os_List_Dir", "列出设备指定目录内容(ls -la)。", {"path": OPT}, []),
    ("Os_Read_File", "读设备文本文件内容(cat)。", {"path": S}, ["path"]),
    ("Read_Logcat", "读Android系统日志logcat，支持tag过滤。", {"lines": I, "tag": OPT}, []),

    # ==== 补齐工具（跨7类真实/降级，非凑数）====
    # R2 补（真调 radare2 命令域）
    ("R2_Bytes_Read", "读指定地址字节(十六进制+ASCII)。", {"session_id": S, "address": S, "size": I}, ["session_id", "address"]),
    ("R2_Bytes_Write", "写指定地址字节(wx 内存字节序)。", {"session_id": S, "address": S, "hex_bytes": S}, ["session_id", "address", "hex_bytes"]),
    ("R2_Yank", "yank/paste 内存块(y)。", {"session_id": S, "action": S, "address": S, "size": I}, ["session_id", "action"]),
    ("R2_Zignatures", "管理 zignatures(z，函数指纹)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("R2_Signatures", "C函数签名/类型(iS)。", {"session_id": S, "name": OPT}, ["session_id"]),
    ("R2_Structs", "结构体/类型解析(t)。", {"session_id": S, "name": OPT}, ["session_id"]),
    ("R2_Sdb_Query", "sdb-query(k，查类型/结构数据库)。", {"session_id": S, "query": S}, ["session_id", "query"]),
    ("R2_Text_Log", "Text log(T，注释/日志/同步)。", {"session_id": S, "action": OPT, "text": OPT}, ["session_id"]),
    ("R2_Debugger", "调试器命令(d，断点/单步/寄存器)。", {"session_id": S, "command": S}, ["session_id", "command"]),
    ("R2_Macros", "脚本宏管理(. / ())。", {"session_id": S, "name": OPT, "body": OPT}, ["session_id"]),
    ("R2_Format_Parse", "C结构体定义解析布局。", {"session_id": S, "c_struct": S}, ["session_id", "c_struct"]),
    ("R2_Shellcode", "g生成shellcode(r_egg)。", {"session_id": S, "egg": S}, ["session_id", "egg"]),
    # Blutter 补（Dart 逆向）
    ("Blutter_Decode_UTF16", "Dart字符串utf-16le全表解码。", {"session_id": S, "limit": I}, ["session_id"]),
    ("Blutter_Resources", "解析flutter_assets资源清单(AssetManifest/FontManifest)。", {"session_id": S}, ["session_id"]),
    ("Blutter_Widget_Tree", "识别Flutter Widget/State/Element类。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Class_Methods", "类完整方法签名+字段。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Blutter_Exception_Sites", "定位异常/错误/throw字符串。", {"session_id": S}, ["session_id"]),
    ("Blutter_Heap_Dump", "Dart对象布局dump(objs近似)。", {"session_id": S}, ["session_id"]),
    ("Blutter_VM_Cmd", "Dart VM命令透传(需真实Blutter引擎)。", {"session_id": S, "cmd": S}, ["session_id", "cmd"]),
    # Fr 补（Frida 场景）
    ("Fr_Crash", "捕获崩溃/信号+调用栈。", {"session_id": S}, ["session_id"]),
    ("Fr_Follow_Thread", "Stalker跟指定线程。", {"session_id": S, "thread_id": S}, ["session_id", "thread_id"]),
    ("Fr_Method_Overloads", "枚举Java方法全部重载。", {"session_id": S, "class_name": S, "method": S}, ["session_id", "class_name"]),
    ("Fr_Malloc_Hook", "hook malloc/free追踪内存分配。", {"session_id": S}, ["session_id"]),
    ("Fr_SSL_Upgrade", "hook SSL_read/write抓HTTPS明文。", {"session_id": S}, ["session_id"]),
    ("Fr_Env_Override", "覆盖SystemProperties/环境变量。", {"session_id": S, "key": S, "value": S}, ["session_id", "key", "value"]),
    ("Fr_Signal_Hook", "hook信号处理器。", {"session_id": S, "signal": S}, ["session_id", "signal"]),
    # Ub 补（Unidbg 高级）
    ("Ub_Call_Java", "模拟Java层方法调用(JNIEnv+jobject)。", {"session_id": S, "method": S, "args": OPT}, ["session_id", "method"]),
    ("Ub_Struct_Build", "构造C结构体作参数。", {"session_id": S, "spec": S}, ["session_id", "spec"]),
    ("Ub_Callback_Install", "安装native回调桩。", {"session_id": S, "offset": S, "js": OPT}, ["session_id", "offset"]),
    ("Ub_Sequence", "多函数顺序调用链(共享内存态)。", {"session_id": S, "calls": S}, ["session_id", "calls"]),
    ("Ub_Stdout_Capture", "捕获stdout/printf输出。", {"session_id": S}, ["session_id"]),
    # Apk / Os / 散列 补
    ("Apk_Strings", "APK层全字符串(扫解压目录)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Apk_Upload", "局域网/upload端点注册(upload_id供Apk_Open)。", {"file_path": S, "label": OPT}, ["file_path"]),
    ("Os_Write_File", "写设备文本文件。", {"path": S, "content": S}, ["path", "content"]),
    ("Os_Stat", "文件stat(大小/权限)。", {"path": S}, ["path"]),

    # ==== 扩到 200+：关键词定位(R2_Locate_*) + 更多面工具 ====
    # 28 个关键词定位（预置 keyword，真调 r2 搜串+伪C；PART4 第③步"关键词定位"）
    ("R2_Locate_Vip", "定位 vip 相关偏移(搜串+伪C命中)。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Member", "定位 member 相关偏移。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_LoadAd", "定位 loadAd 广告加载偏移。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_IsVip", "定位 isVip 判断函数。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_IsMember", "定位 isMember 判断。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Premium", "定位 premium 权益相关。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Buy", "定位 buy 购买逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Subscribe", "定位 subscribe 订阅逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Trial", "定位 trial 试用逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Expire", "定位 expire 过期/有效期。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Unlock", "定位 unlock 解锁逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Pay", "定位 pay 支付逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Purchase", "定位 purchase 购买。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_License", "定位 license 授权。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Activated", "定位 activated 激活态。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Serial", "定位 serial 序列号。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Token", "定位 token 令牌。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Secret", "定位 secret 密钥。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Auth", "定位 auth 鉴权。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Root", "定位 root 检测。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Debug", "定位 debug 调试开关。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Test", "定位 test 测试桩。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Prod", "定位 prod 生产环境开关。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Flag", "定位 feature flag。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_ShowAd", "定位 showAd 展示广告。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_HideAd", "定位 hideAd 隐藏广告。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Bypass", "定位 bypass 绕过点。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Verify", "定位 verify 校验点。", {"session_id": S}, ["session_id"]),
    # 游戏/可改数值定位（配合 Il2Cpp_Cheatable_Scan）
    ("R2_Locate_Ammo", "定位 ammo 弹药偏移。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Health", "定位 health 血量偏移。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Coin", "定位 coin 金币/货币偏移。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Damage", "定位 damage 伤害逻辑。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Gold", "定位 gold 金币。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Price", "定位 price 价格/支付。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Rate", "定位 rate 倍率/概率。", {"session_id": S}, ["session_id"]),
    ("R2_Locate_Experience", "定位 experience/xp 经验。", {"session_id": S}, ["session_id"]),
    # R2 更多面(6)
    ("R2_Leak", "内存泄漏分析(ae)。", {"session_id": S}, ["session_id"]),
    ("R2_Diff", "二进制 diff(r2diff 对比两 so)。", {"session_id": S, "other_path": S}, ["session_id", "other_path"]),
    ("R2_Alias", "定义别名/表达式(?)。", {"session_id": S, "name": S, "expr": S}, ["session_id", "name", "expr"]),
    ("R2_Goto", "seek 到标签/地址(s)。", {"session_id": S, "target": S}, ["session_id", "target"]),
    ("R2_Reload", "重载 so 重新分析(o -r)。", {"session_id": S}, ["session_id"]),
    ("R2_Panel_Hint", "radare2 面板/图形模式提示(需GUI)。", {"session_id": S}, ["session_id"]),
    # Fr 更多场景(6, 出JS)
    ("Fr_Java_Call", "调用指定Java方法并取返回。", {"session_id": S, "class_name": S, "method": S, "args": OPT}, ["session_id", "class_name", "method"]),
    ("Fr_Activity", "追踪Activity生命周期。", {"session_id": S, "name": S}, ["session_id", "name"]),
    ("Fr_Service", "追踪Service。", {"session_id": S, "name": S}, ["session_id", "name"]),
    ("Fr_Network", "过滤/追踪网络请求(host)。", {"session_id": S, "host": S}, ["session_id", "host"]),
    ("Fr_Prop", "设系统属性(SystemProperties)。", {"session_id": S, "key": S, "value": S}, ["session_id", "key", "value"]),
    ("Fr_Keyboard", "模拟键盘输入。", {"session_id": S, "text": S}, ["session_id", "text"]),
    # Blutter 更多面(4)
    ("Blutter_Decode_Base64", "解码Dart快照里的base64字符串。", {"session_id": S, "limit": I}, ["session_id"]),
    ("Blutter_Network_Urls", "提取所有http/https URL。", {"session_id": S}, ["session_id"]),
    ("Blutter_Asset_Icons", "列flutter_assets资源/图标。", {"session_id": S}, ["session_id"]),
    ("Blutter_Route_Map", "提取Flutter路由(Page/Screen/Route类)。", {"session_id": S}, ["session_id"]),
    # Ub 更多面(2)
    ("Ub_MultiCall", "多函数顺序调用链。", {"session_id": S, "calls": S}, ["session_id", "calls"]),
    ("Ub_Jni_Callback", "JNI回调桩。", {"session_id": S, "symbol": S, "js": OPT}, ["session_id", "symbol"]),
    # Apk 更多面(2)
    ("Apk_Version_Info", "APK会话概要(stack/so数/blutter)。", {"session_id": S}, ["session_id"]),
    ("Apk_Install_Start", "安装并启动APK(需设备,返回PID)。", {"apk_session_id": S, "package": S}, ["apk_session_id", "package"]),
    # Os 更多面(2)
    ("Os_Grep", "文件内grep正则。", {"path": S, "pattern": S}, ["path", "pattern"]),
    ("Os_Find", "按glob找文件。", {"base_dir": S, "pattern": S}, ["base_dir", "pattern"]),

    # ==== Il2Cpp_* (Unity C# 全还原，15) ====
    ("Il2Cpp_Open", "【第1步】打开Unity APK/global-metadata.dat建Il2Cpp会话(检测版本+提C#符号)。", {"extract_dir": OPT, "metadata": OPT, "il2cpp_so": OPT}, []),
    ("Il2Cpp_Types", "列C#类型清单(全局类型)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Methods", "列C#方法签名清单。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Strings", "提C#硬编码字符串。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Class_Detail", "指定C#类的完整方法/字段。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Il2Cpp_Method_Detail", "指定C#方法签名+RVA状态。", {"session_id": S, "method": S}, ["session_id", "method"]),
    ("Il2Cpp_Metadata_Info", "Il2Cpp会话统计(版本/类型/方法/字符串数)。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_Version_Detect", "从metadata头判Unity版本(v29=2021/v39=Unity6)。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_So_Scan", "扫libil2cpp.so native符号。", {"session_id": S, "pattern": OPT}, ["session_id"]),
    ("Il2Cpp_RVA_Patch", "C#方法/类→RVA定位+patch(需Il2CppDumper取精确RVA)。", {"session_id": S, "method_or_class": S, "new_return": OPT}, ["session_id", "method_or_class"]),
    ("Il2Cpp_Gameplay_Scan", "游戏逻辑关键词扫(伤害/血量/武器/命中/暴击/货币)。", {"session_id": S, "keywords": OPT}, ["session_id"]),
    ("Il2Cpp_Export", "导出三件套(script.json/DummyTypes/string.json)。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Close", "关闭Il2Cpp会话。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_List_Sessions", "列出所有Il2Cpp会话。", {}, []),
    # Il2Cpp 深度扩展（16）
    ("Il2Cpp_Metadata_Parse", "global-metadata.dat完整结构(magic/blob偏移/各表数量)。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_Type_Defs", "全量类型定义+继承启发(基类/泛型)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Field_Defs", "字段名提取(近似,精确偏移需Il2CppDumper)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Assemblies", "程序集/模块前缀统计。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_Namespaces", "命名空间统计。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_Symbol_Restore", "全量C#方法→可读符号清单(导入r2/IDA)。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_RVA_Table", "方法→RVA表(精确需Il2CppDumper)。", {"session_id": S}, ["session_id"]),
    ("Il2Cpp_Dummy_DLL", "生成还原C#类型/方法骨架(dummy dll)。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Csharp_Source", "生成C#源码骨架(类+方法签名)。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Import_IDA", "生成IDA import脚本(af到RVA)。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Import_R2", "生成r2导入脚本(ff函数+重命名)。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Find_Type", "搜类型(按名)。", {"session_id": S, "name": S}, ["session_id", "name"]),
    ("Il2Cpp_Find_Method", "搜方法(按名)。", {"session_id": S, "name": S}, ["session_id", "name"]),
    ("Il2Cpp_Find_Field", "搜字段(按名)。", {"session_id": S, "name": S}, ["session_id", "name"]),
    ("Il2Cpp_Cheatable_Scan", "可改数值关键词(血量/弹药/金币/倍率/概率/经验)。", {"session_id": S, "keywords": OPT}, ["session_id"]),
    ("Il2Cpp_AntiCheat_Scan", "校验/反作弊/完整性点(verify/sign/license/root/debug)。", {"session_id": S, "keywords": OPT}, ["session_id"]),
    # ==== Nav_* (调用图/导航/反混淆，Mermaid输出，12) ====
    ("Nav_Build_Call_Graph", "建某函数调用图(axf递归)。", {"session_id": S, "func": S, "depth": I}, ["session_id", "func"]),
    ("Nav_Call_Chain", "A→B→C调用链(BFS寻径)。", {"session_id": S, "from_func": S, "to_func": S}, ["session_id", "from_func", "to_func"]),
    ("Nav_Mermaid", "生成调用图Mermaid(粘进渲染器)。", {"session_id": S, "func": S, "depth": I}, ["session_id", "func"]),
    ("Nav_Who_Calls", "谁调用了X(axt)。", {"session_id": S, "func": S}, ["session_id", "func"]),
    ("Nav_What_Calls", "X调用了谁(axf)。", {"session_id": S, "func": S}, ["session_id", "func"]),
    ("Nav_Reverse_Search", "从结果字符串反查引用地址。", {"session_id": S, "result_str": S}, ["session_id", "result_str"]),
    ("Nav_Symbol_Jump", "符号跳转+伪C上下文。", {"session_id": S, "symbol": S}, ["session_id", "symbol"]),
    ("Nav_Deobfuscate_Guide", "反混淆导航(识别OLLVM扁平化/BCF+还原思路)。", {"session_id": S, "func": S}, ["session_id", "func"]),
    ("Nav_Function_Context", "函数上下文(参数/变量/callee/caller/伪C)。", {"session_id": S, "func": S}, ["session_id", "func"]),
    ("Nav_Dominators", "枢纽函数(入度高,关键逻辑节点)。", {"session_id": S, "func": OPT, "depth": I}, ["session_id"]),
    ("Nav_Export_Graph", "导出调用图(json/mermaid文件)，path 非空时另存文件。", {"session_id": S, "func": S, "path": OPT, "fmt": OPT, "depth": I}, ["session_id", "func"]),
    ("Nav_List_Sessions", "列出可用Nav的r2会话。", {}, []),
    # ---- Pentest 域：过鉴权 + 打通服务器 + 横向 ----
    ("Pentest_Auth_Extract", "过鉴权① 提取so里鉴权相关字符串+判断函数。", {"session_id": S}, ["session_id"]),
    ("Pentest_Endpoint_Extract", "打通服务器① 提取服务端URL/域名/IP/接口路径。", {"session_id": S}, ["session_id"]),
    ("Pentest_Key_Extract", "提取硬编码密钥(32/64hex=AES/base64/PEM/算法名)。", {"session_id": S}, ["session_id"]),
    ("Pentest_CertPin_Extract", "提取证书pinning标记(bpg/fingerprint/pin)。", {"session_id": S}, ["session_id"]),
    ("Pentest_Cred_Hunt", "凭证猎捕:硬编码账号密码/JWT/设备ID。", {"session_id": S}, ["session_id"]),
    ("Pentest_C2_Trace", "C2/回传通道映射(信标端点)。", {"session_id": S}, ["session_id"]),
    ("Pentest_SSL_Bypass", "生成Frida SSL证书校验绕过脚本。", {"session_id": S, "out": OPT}, ["session_id"]),
    ("Pentest_Auth_Bypass", "鉴权绕过:定位判断点+arm64恒真patch字节+Frida hook。", {"session_id": S, "func": OPT}, ["session_id"]),
    ("Pentest_Sign_Bypass", "签名校验绕过:getPackageInfo/signatures hook方案。", {"session_id": S}, ["session_id"]),
    ("Pentest_Server_Fingerprint", "打通服务器:对域名/IP出nmap/TLS指纹/WAF/路径枚举命令。", {"target": S}, ["target"]),
    ("Pentest_Traffic_Replay", "流量重放/篡改:Frida hook SSL_write抓明文。", {"session_id": S}, ["session_id"]),
    ("Pentest_Lateral_Report", "横向汇总:攻击面报告(auth/端点/密钥/凭证/C2)。", {"session_id": S}, ["session_id"]),
    # ============ 补齐工具（legacy 登记但未实现，本次补齐 87 个）============
    ("Apk_Diff", "对比两个 APK 的差异(增删/变化/按类型分桶)。", {"a": S, "b": S, "show_unchanged": B}, ["a", "b"]),
    ("Blutter_AOT", "判断是否 AOT 编译快照(_kDart*/SnapshotInstructions 标志)。", {}, []),
    ("Blutter_Annotate", "批量生成 r2 注释脚本(afn/CC)，把 Dart 符号写回反汇编。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Async", "异步相关符号(Future/Stream/await/Isolate)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Channel", "Platform Channel 符号(MethodChannel/EventChannel)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Closure", "闭包相关符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Const", "常量符号(k 前缀 / _ 大写)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Enum", "枚举类型与全大写成员。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Extension", "Dart extension 扩展符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Fields", "类字段列表(Class.field 命名推断)。", {"session_id": S, "class_name": OPT, "filter": OPT}, ["session_id"]),
    ("Blutter_GC", "GC/堆相关符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Heap", "堆分配相关符号(同 GC 扫描)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Implement", "类实现了哪些方法(按 Class. 前缀聚合)。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Blutter_Imports", "import 依赖字符串(package:/dart:/flutter:)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Inherits", "类的继承链(父→祖父)。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Blutter_Inspect", "给一个名字自动判断是类/方法/字段/字符串并出详情。", {"session_id": S, "target": S}, ["session_id", "target"]),
    ("Blutter_Isolate", "Isolate 并发符号(spawn/SendPort/ReceivePort)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Lib", "native 库引用(.so 名)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Localizations", "本地化/多语言资源符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Method_Detail", "单方法详情(偏移/大小/所属类/可用 Frida 片段)。", {"session_id": S, "method": S}, ["session_id", "method"]),
    ("Blutter_Methods", "类方法列表(含偏移，可直接给 Fr_Native_Hook)。", {"session_id": S, "class_name": OPT, "filter": OPT}, ["session_id"]),
    ("Blutter_Mirror", "dart:mirrors 反射相关符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Mixin", "mixin 混入符号(Mixin 后缀)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Package", "依赖包聚合清单(package:/dart:)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Plugin", "Flutter 插件注册点(Plugin/registerWith)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Resolve", "地址→符号反查(pp_table + 最近函数)。", {"session_id": S, "address": S}, ["session_id", "address"]),
    ("Blutter_Routes", "路由表(/xxx 路径 + Navigator 调用点)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Search", "跨类/函数/字符串统一搜索。", {"session_id": S, "query": S, "kind": OPT, "max_results": I}, ["session_id", "query"]),
    ("Blutter_Snapshot", "AOT 快照元信息(版本/段大小/各类计数)。", {"session_id": S}, ["session_id"]),
    ("Blutter_StackTrace", "异常/堆栈相关符号(定位崩溃点与 try-catch)。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Blutter_Superclass", "类的直接父类。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Blutter_Symbols", "全部符号(类+函数+字符串)，可按 kind 过滤。", {"session_id": S, "filter": OPT, "kind": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_TypeArgs", "泛型参数符号(<T> 形式)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Blutter_Version_Adapt", "Dart 版本适配：报告版本并给出解析策略。", {"session_id": S}, ["session_id"]),
    ("Blutter_Widgets", "Widget/Page/View/Screen 组件符号。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Fr_Enumerate_Export", "枚举模块导出函数(含地址，可直接 hook)。", {"session_id": S, "module_name": OPT, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Fr_Eval_Java", "执行一段 Java 层 JS 代码(Java.perform 内)。", {"session_id": S, "code": S, "wrap_perform": B}, ["session_id", "code"]),
    ("Fr_Gadget", "Frida Gadget 免 root 方案(打进 APK 的操作步骤)。", {"session_id": OPT, "mode": OPT, "package": OPT}, []),
    ("Fr_Heap_Scan", "扫堆内存找字符串/字节模式。", {"session_id": S, "pattern": OPT, "max_results": I}, ["session_id"]),
    ("Fr_Overload", "枚举方法所有重载并逐个 hook(Java 重载必用)。", {"session_id": S, "class_name": S, "method": S, "dump_args": B}, ["session_id", "class_name", "method"]),
    ("Fr_Patch_Bytes", "改进程内存(运行时 patch，重启失效)。", {"session_id": S, "address": S, "hex_bytes": S, "restore": OPT}, ["session_id", "address", "hex_bytes"]),
    ("Fr_Read_Bytes", "读进程内存。", {"session_id": S, "address": S, "size": I}, ["session_id", "address"]),
    ("Fr_StackTrace", "抓调用栈(native Thread.backtrace / Java Exception 栈)。", {"session_id": S, "address": OPT, "depth": I}, ["session_id"]),
    ("Il2Cpp_Classes", "列出所有 C# 类(可按命名空间过滤)。", {"session_id": S, "filter": OPT, "namespace": OPT, "max_results": I}, ["session_id"]),
    ("Il2Cpp_Dump", "导出 Il2CppDumper 三件套到目录。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Enums", "枚举类型与成员。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Fields", "字段列表(字符串+getter/setter 推断，类型恒 unknown)。", {"session_id": S, "class_name": OPT, "filter": OPT, "max_results": I}, ["session_id"]),
    ("Il2Cpp_Interfaces", "接口列表(按 I 前缀命名约定识别)。", {"session_id": S, "class_name": OPT}, ["session_id"]),
    ("Il2Cpp_Properties", "属性列表(get_/set_ 成对识别)。", {"session_id": S, "class_name": OPT, "filter": OPT}, ["session_id"]),
    ("Il2Cpp_Read", "读 libil2cpp.so 指定地址。", {"session_id": S, "address": S, "size": I, "as_type": OPT}, ["session_id", "address"]),
    ("Il2Cpp_Script_Json", "产出 Il2CppDumper 风格 script.json。", {"session_id": S, "out_dir": OPT}, ["session_id"]),
    ("Il2Cpp_Search", "跨类型/方法/字符串搜索。", {"session_id": S, "query": S, "kind": OPT, "max_results": I}, ["session_id", "query"]),
    ("Il2Cpp_Struct", "结构体布局(按 8 字节对齐估算偏移)。", {"session_id": S, "class_name": S}, ["session_id", "class_name"]),
    ("Il2Cpp_To_R2", "导出 r2 脚本(afn/CC)把 C# 符号写回反汇编。", {"session_id": S, "out_dir": OPT, "class_name": OPT}, ["session_id"]),
    ("Il2Cpp_Version", "Unity 与 metadata 版本信息。", {"session_id": S}, ["session_id"]),
    ("Nav_BuildGraph", "显式建调用图并返回节点/边。", {"session_id": S, "func": OPT, "depth": I}, ["session_id"]),
    ("Nav_CallChain", "A→B 调用链寻径。", {"session_id": S, "from_func": S, "to_func": S}, ["session_id", "from_func", "to_func"]),
    ("Nav_Close", "释放会话缓存的调用图。", {"session_id": S}, ["session_id"]),
    ("Nav_Cycle", "检测调用环(递归/互相调用)。", {"session_id": S, "max_cycles": I}, ["session_id"]),
    ("Nav_DFS", "深度优先遍历(down 看它调谁 / up 看谁调它)。", {"session_id": S, "func": S, "depth": I, "direction": OPT}, ["session_id", "func"]),
    ("Nav_ExportGraph", "导出图到文件(json/dot/mermaid)，可 nav_load 载回。", {"session_id": S, "func": OPT, "path": OPT, "fmt": OPT, "depth": I}, ["session_id"]),
    ("Nav_Function", "单函数画像(调用者/被调用者/是否叶子)。", {"session_id": S, "func": S}, ["session_id", "func"]),
    ("Nav_Load", "从磁盘加载已导出的图，避免每次重建。", {"session_id": S, "path": OPT}, ["session_id"]),
    ("Nav_Modules", "列出会话涉及的段/模块信息。", {"session_id": S}, ["session_id"]),
    ("Nav_Patch_Candidates", "推荐值得 patch 的函数(校验/付费/反调试关键词+入度)。", {"session_id": S, "keywords": OPT, "max_results": I}, ["session_id"]),
    ("Nav_Stats", "图统计(节点/边/出入度 Top/孤立函数)。", {"session_id": S}, ["session_id"]),
    ("R2_Arch", "架构信息(arch/bits/endian/cpu/canary/nx)。", {"session_id": S}, ["session_id"]),
    ("R2_Blocks", "基本块列表(afbj)，看控制流。", {"session_id": S, "func": OPT}, ["session_id"]),
    ("R2_Globals", "全局变量(数据符号)。", {"session_id": S, "filter": OPT, "max_results": I}, ["session_id"]),
    ("R2_Map", "内存映射(om)。", {"session_id": S}, ["session_id"]),
    ("R2_Patch", "打补丁：写 hex / 写汇编 / 填 NOP(三选一)。", {"session_id": S, "address": S, "hex_bytes": OPT, "asm": OPT, "nop": I}, ["session_id", "address"]),
    ("R2_Symbols", "符号总表(可按类型过滤)。", {"session_id": S, "filter": OPT, "kind": OPT, "max_results": I}, ["session_id"]),
    ("R2_Types", "类型与结构体定义。", {"session_id": S, "filter": OPT}, ["session_id"]),
    ("Ub_Backtrace", "回溯当前调用栈(出 Java 源码)。", {"session_id": S, "max_frames": I}, ["session_id"]),
    ("Ub_Close_Session", "关闭 Unidbg 会话并释放分配/桩。", {"session_id": S}, ["session_id"]),
    ("Ub_Dlopen", "加载额外 so 到模拟器。", {"session_id": S, "path": S}, ["session_id", "path"]),
    ("Ub_Env", "报告 Unidbg 运行环境是否就绪(java+jar)。", {"session_id": OPT}, []),
    ("Ub_File_Read", "读模拟器文件系统(无 jar 时降级读宿主机)。", {"session_id": S, "path": S, "max_bytes": I}, ["session_id", "path"]),
    ("Ub_File_Write", "写文件到模拟器文件系统。", {"session_id": S, "path": S, "content": OPT, "hex_bytes": OPT}, ["session_id", "path"]),
    ("Ub_Info", "会话或全局 Unidbg 环境信息。", {"session_id": OPT}, []),
    ("Ub_Java_Call", "在模拟器里调用 Java 层方法。", {"session_id": S, "class_name": S, "method": S, "args": O, "signature": OPT}, ["session_id", "class_name", "method"]),
    ("Ub_Malloc", "在模拟器堆上分配内存。", {"session_id": S, "size": I, "init": OPT}, ["session_id"]),
    ("Ub_Print_Stack", "打印栈内存(hexdump)。", {"session_id": S, "size": I, "address": OPT}, ["session_id"]),
    ("Ub_Register_JNI", "注册 JNI 方法，使 RegisterNatives 能找到实现。", {"session_id": S, "class_name": S, "method": S, "signature": OPT}, ["session_id", "class_name", "method"]),
    ("Ub_Session", "建立/复用 Unidbg 模拟会话。", {"file": OPT, "call_jni": B, "session_id": OPT}, []),
    ("Ub_Stub", "给函数打桩直接返回指定值(绕过校验)。", {"session_id": S, "symbol": OPT, "address": OPT, "ret_value": I}, ["session_id"]),
    ("Ub_Syscall", "触发系统调用。", {"session_id": S, "number": I, "args": O}, ["session_id", "number"]),
    # ============ Engine_* 外部引擎管理（放 so 后自检/配置）============
    ("Engine_Status", "各引擎接入状态：资产是否存在/是否配调用方式/是否可调用。", {}, []),
    ("Engine_Probe", "探测引擎资产：列出 so 导出符号、猜测入口函数、试 dlopen。", {"name": OPT, "path": OPT}, []),
    ("Engine_Config", "查看当前 engines.json 调用配置。", {}, []),
    ("Engine_Set", "写入某引擎的调用配置(mode/entry/cmd/argtypes)。", {"name": S, "mode": OPT, "entry": OPT, "cmd": OPT, "argtypes": OPT, "restype": OPT, "args": OPT, "path": OPT}, ["name"]),
    ("Engine_Guide", "引擎该放哪个目录、命名规则、接入步骤。", {}, []),
    ("Engine_List_Assets", "列出已放入 engine_root 的所有资产文件与大小。", {}, []),

    ("Engine_R2_Status", "radare2 接入状态：可执行文件 / ctypes 直调 libr_core.so。", {}, []),
    ("Engine_R2_Lib", "手动加载 libr_core.so(ctypes 模式)并返回可用状态。", {"dir_hint": OPT}, []),
    ("Engine_R2_Cmd", "直接跑一条 r2 命令验证接入(自动选后端)。", {"so": S, "cmds": OPT, "timeout": I}, ["so"]),

    ("Engine_R2_Deps", "检查 radare2 的 libr_*.so 是否齐全(bridge 依赖 libr_core.so)。", {"dir_hint": OPT}, []),

    ("Engine_Inventory", "清点引擎资产：有什么/缺什么/去哪补完整版。", {}, []),
    ("Engine_Fetch_Plan", "某引擎的补货步骤(只出命令，不下网)。", {"engine": OPT}, []),

]


def _route(name: str) -> str:
    """工具名 → 引擎函数名（小写化，PseudoC→pseudoc 等）。"""
    return name.lower()


def build_tools() -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    for name, desc, props, req in SPEC:
        cat = name.split("_")[0]
        if name.startswith("R2_Locate_"):
            kw = name[len("R2_Locate_"):]
            kw = kw[0].lower() + kw[1:]
            route, route_args = "r2_locate_keyword", {"keyword": kw}
        else:
            route = {"Fr_LoadScript": "fr_load_script"}.get(name, _route(name))
            route_args = None
        tools.append({
            "name": name,
            "description": desc,
            "inputSchema": _schema(props, req),
            "route": route,
            "route_args": route_args,
            "category": cat,
            "is_core": True,
        })
    return tools


def tool_count() -> int:
    return len(build_tools())
