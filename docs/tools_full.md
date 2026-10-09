# R2B 264 工具完整清单（按类）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | 核心真实执行 | | |
| ◆ | 预置参数（真实执行，参数写死） | | |
| △ | 需运行时降级（frida/unidbg 未装则出脚本/说明） | | |

## R2（87）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `R2_Alias` | session_id, name, expr | 定义别名/表达式(?)。 |
| ★ | `R2_Analysis_Hints` | session_id, action, address, arch, bits, target | 管理分析提示(ah系列)：覆盖架构/位数/跳转。 |
| ★ | `R2_Analyze` | session_id, mode | 对已打开二进制执行自动分析(aa快/aaa深)。 |
| ★ | `R2_Analyze_File` | file_path, session_id | 快速通道:开文件→aa分析→列函数→关闭。 |
| ★ | `R2_Analyze_Target` | session_id, strategy, address | 按策略局部递归分析(basic/blocks/calls/refs/pointers/full)。 |
| ★ | `R2_Bytes_Read` | session_id, address, size | 读指定地址字节(十六进制+ASCII)。 |
| ★ | `R2_Bytes_Write` | session_id, address, hex_bytes | 写指定地址字节(wx 内存字节序)。 |
| ★ | `R2_Calculate` | session_id, expression | 计算表达式/地址运算(支持十六进制)。 |
| ★ | `R2_Close` | session_id | 关闭r2会话并释放资源(含伪C缓存)。 |
| ★ | `R2_Cmd` | session_id, command, timeout | 执行任意r2命令。afl/af/pd/iz/axt/wao nop/CC/afn 等。 |
| ★ | `R2_Config_Manager` | session_id, key, value | 读写r2运行期配置(e命令)。 |
| ★ | `R2_Debugger` | session_id, command | 调试器命令(d，断点/单步/寄存器)。 |
| ★ | `R2_Decompile_Function` | session_id, address, engine | 实时反编译(r2ghidra pdg更准/缓存未命中备选)。 |
| ★ | `R2_Diff` | session_id, other_path | 二进制 diff(r2diff 对比两 so)。 |
| ★ | `R2_Disassemble` | session_id, address, count | 反汇编指定地址机器码。 |
| ★ | `R2_Entries` | session_id | 列出入口点。 |
| ★ | `R2_Export_PseudoC_To_File` | session_id | 将全量伪C导出到文件。 |
| ★ | `R2_Exports` | session_id | 列出导出符号(其他模块可调，.so即JNI导出)。 |
| ★ | `R2_Format_Parse` | session_id, c_struct | C结构体定义解析布局。 |
| ★ | `R2_Functions` | session_id, keyword | 列出所有函数(从内存索引秒回)。 |
| ★ | `R2_Get_PseudoC` | session_id, address | 【首选】从预编译缓存取函数伪C，毫秒级。 |
| ★ | `R2_Goto` | session_id, target | seek 到标签/地址(s)。 |
| ★ | `R2_Hash` | session_id, type | 计算文件哈希(md5/sha1/sha256)。 |
| ★ | `R2_Hexdump` | session_id, address, count | 十六进制+ASCII查看指定地址内存。 |
| ★ | `R2_Imports` | session_id | 列出导入的外部函数(动态链接符号)。 |
| ★ | `R2_Info` | session_id | 查看二进制元信息(架构/端序/入口/大小)。 |
| ★ | `R2_Leak` | session_id | 内存泄漏分析(ae)。 |
| ★ | `R2_List_Sessions` | — | 列出所有活跃r2会话。 |
| ◆ | `R2_Locate_Activated` | session_id | 定位 activated 激活态。 |
| ◆ | `R2_Locate_Ammo` | session_id | 定位 ammo 弹药偏移。 |
| ◆ | `R2_Locate_Auth` | session_id | 定位 auth 鉴权。 |
| ◆ | `R2_Locate_Buy` | session_id | 定位 buy 购买逻辑。 |
| ◆ | `R2_Locate_Bypass` | session_id | 定位 bypass 绕过点。 |
| ◆ | `R2_Locate_Coin` | session_id | 定位 coin 金币/货币偏移。 |
| ◆ | `R2_Locate_Damage` | session_id | 定位 damage 伤害逻辑。 |
| ◆ | `R2_Locate_Debug` | session_id | 定位 debug 调试开关。 |
| ◆ | `R2_Locate_Experience` | session_id | 定位 experience/xp 经验。 |
| ◆ | `R2_Locate_Expire` | session_id | 定位 expire 过期/有效期。 |
| ◆ | `R2_Locate_Flag` | session_id | 定位 feature flag。 |
| ◆ | `R2_Locate_Gold` | session_id | 定位 gold 金币。 |
| ◆ | `R2_Locate_Health` | session_id | 定位 health 血量偏移。 |
| ◆ | `R2_Locate_HideAd` | session_id | 定位 hideAd 隐藏广告。 |
| ◆ | `R2_Locate_IsMember` | session_id | 定位 isMember 判断。 |
| ◆ | `R2_Locate_IsVip` | session_id | 定位 isVip 判断函数。 |
| ◆ | `R2_Locate_License` | session_id | 定位 license 授权。 |
| ◆ | `R2_Locate_LoadAd` | session_id | 定位 loadAd 广告加载偏移。 |
| ◆ | `R2_Locate_Member` | session_id | 定位 member 相关偏移。 |
| ◆ | `R2_Locate_Pay` | session_id | 定位 pay 支付逻辑。 |
| ◆ | `R2_Locate_Premium` | session_id | 定位 premium 权益相关。 |
| ◆ | `R2_Locate_Price` | session_id | 定位 price 价格/支付。 |
| ◆ | `R2_Locate_Prod` | session_id | 定位 prod 生产环境开关。 |
| ◆ | `R2_Locate_Purchase` | session_id | 定位 purchase 购买。 |
| ◆ | `R2_Locate_Rate` | session_id | 定位 rate 倍率/概率。 |
| ◆ | `R2_Locate_Root` | session_id | 定位 root 检测。 |
| ◆ | `R2_Locate_Secret` | session_id | 定位 secret 密钥。 |
| ◆ | `R2_Locate_Serial` | session_id | 定位 serial 序列号。 |
| ◆ | `R2_Locate_ShowAd` | session_id | 定位 showAd 展示广告。 |
| ◆ | `R2_Locate_Subscribe` | session_id | 定位 subscribe 订阅逻辑。 |
| ◆ | `R2_Locate_Test` | session_id | 定位 test 测试桩。 |
| ◆ | `R2_Locate_Token` | session_id | 定位 token 令牌。 |
| ◆ | `R2_Locate_Trial` | session_id | 定位 trial 试用逻辑。 |
| ◆ | `R2_Locate_Unlock` | session_id | 定位 unlock 解锁逻辑。 |
| ◆ | `R2_Locate_Verify` | session_id | 定位 verify 校验点。 |
| ◆ | `R2_Locate_Vip` | session_id | 定位 vip 相关偏移(搜串+伪C命中)。 |
| ★ | `R2_Macros` | session_id, name, body | 脚本宏管理(. / ())。 |
| ★ | `R2_Manage_Xrefs` | session_id, action, target_address, source_address | 管理/查询/创建交叉引用(ax系列)。 |
| ★ | `R2_Open` | so_path, mode, session_id | 打开二进制(.so/.dex/.elf)建r2会话，自动建函数索引+后台全量伪C导出(≤5000内存/>5000 SQLite)。返回8位session_id。 |
| ★ | `R2_Panel_Hint` | session_id | radare2 面板/图形模式提示(需GUI)。 |
| ★ | `R2_PseudoC_Status` | session_id | 查看后台全量伪C导出进度。 |
| ★ | `R2_Reload` | session_id | 重载 so 重新分析(o -r)。 |
| ★ | `R2_Sdb_Query` | session_id, query | sdb-query(k，查类型/结构数据库)。 |
| ★ | `R2_Search` | session_id, pattern, threads | 搜十六进制字节模式(机器码/magic，非字符串)。 |
| ★ | `R2_Search_Functions` | session_id, query, max_results | 按函数名模糊搜索定位，返回地址+大小+名字。 |
| ★ | `R2_Search_PseudoC` | session_id, query, regex, max_results | 在全量伪C中搜关键词/正则，返回地址+函数名+片段。 |
| ★ | `R2_Search_String` | session_id, query, max_results | 按关键词搜可读字符串(多线程快，AI优先用此而非R2_Search)。 |
| ★ | `R2_Sections` | session_id | 列出ELF段(Section)信息。 |
| ★ | `R2_Seek` | session_id, address | 移动光标到指定地址。 |
| ★ | `R2_Shellcode` | session_id, egg | g生成shellcode(r_egg)。 |
| ★ | `R2_Signatures` | session_id, name | C函数签名/类型(iS)。 |
| ★ | `R2_Strings` | session_id, mode, timeout | 提取可打印字符串。iz快/izz全文件。 |
| ★ | `R2_Structs` | session_id, name | 结构体/类型解析(t)。 |
| ★ | `R2_Text_Log` | session_id, action, text | Text log(T，注释/日志/同步)。 |
| ★ | `R2_To_Ub_Call` | session_id, offset, args | 【R2→Unidbg桥】从r2会话取函数偏移→unidbg调用。 |
| ★ | `R2_Version` | — | 测试 r2 引擎是否可用并返回版本信息。首次使用前调用确认 r2 加载正常。 |
| ★ | `R2_Xrefs` | session_id, address | 查找谁调用指定地址的函数(需先R2_Analyze)。 |
| ★ | `R2_Yank` | session_id, action, address, size | yank/paste 内存块(y)。 |
| ★ | `R2_Zignatures` | session_id, filter | 管理 zignatures(z，函数指纹)。 |

## Blutter（32）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Blutter_Analyze` | lib_app_path, lib_flutter_path, timeout_seconds | 对Flutter的libapp.so做Dart快照分析(3-5秒)，缓存类/函数/字符串。 |
| ★ | `Blutter_Annotate_R2` | session_id, function_filter, annotate_pp, pp_filter | 【Blutter→r2集成】IR字段偏移+pp字符串注入r2注释。 |
| ★ | `Blutter_Asset_Icons` | session_id | 列flutter_assets资源/图标。 |
| ★ | `Blutter_Class_Detail` | session_id, class_name | 查看指定Dart类完整结构(继承/字段/方法)。 |
| ★ | `Blutter_Class_Methods` | session_id, class_name | 类完整方法签名+字段。 |
| ★ | `Blutter_Classes` | session_id, filter | 从内存缓存搜Dart类列表(毫秒级)。 |
| ★ | `Blutter_Close` | session_id | 关闭Blutter分析会话释放内存。 |
| ★ | `Blutter_Dart_Access` | blutter_session_id, frida_session_id, class_name, action, field_name, instance_addr, new_value | 【桥·运行时读写】objs.txt字段偏移→Frida读写字段。 |
| ★ | `Blutter_Decode_Base64` | session_id, limit | 解码Dart快照里的base64字符串。 |
| ★ | `Blutter_Decode_UTF16` | session_id, limit | Dart字符串utf-16le全表解码。 |
| ★ | `Blutter_Disassemble` | session_id, function_name, open_r2 | 查看Dart函数完整汇编(Butter Dart IR)。 |
| ★ | `Blutter_Exception_Sites` | session_id | 定位异常/错误/throw字符串。 |
| ★ | `Blutter_Find_Instances` | blutter_session_id, frida_session_id, class_name, method_name, module_hint | 【桥·实例→字段】Hook类方法入口捕this指针。 |
| ★ | `Blutter_Frida` | session_id | 导出Frida Hook脚本(所有Dart函数Interceptor桩)。 |
| ★ | `Blutter_Functions` | session_id, class_name, filter | 搜索所有Dart函数(毫秒级，内存缓存)。 |
| ★ | `Blutter_Heap_Dump` | session_id | Dart对象布局dump(objs近似)。 |
| ★ | `Blutter_Info` | session_id | 查看Blutter会话统计(Dart版本/类数/函数数/字符串数)。 |
| ★ | `Blutter_List_Sessions` | — | 列出所有活跃Blutter会话。 |
| ★ | `Blutter_Logs` | session_id | 查看Blutter_Analyze执行日志。 |
| ★ | `Blutter_Modify_String` | session_id, search_str, replace_str | 修改libapp.so中字符串常量(不能比原串长)。 |
| ★ | `Blutter_Network_Urls` | session_id | 提取所有http/https URL。 |
| ★ | `Blutter_Object_Layouts` | session_id, filter | 读objs.txt对象布局表(字段偏移/类型继承/大小)。 |
| ★ | `Blutter_PP_Table` | session_id, filter | 读pp.txt池化对象表(类/函数/字符串在libapp.so的精确偏移)。 |
| ★ | `Blutter_Patch` | session_id, function_name, action, bytes | 在native层修改Dart函数(ret/nop/custom)。 |
| ★ | `Blutter_Resources` | session_id | 解析flutter_assets资源清单(AssetManifest/FontManifest)。 |
| ★ | `Blutter_Route_Map` | session_id | 提取Flutter路由(Page/Screen/Route类)。 |
| ★ | `Blutter_Strings` | session_id, filter | 搜Dart快照中的字符串常量(毫秒级)。 |
| ★ | `Blutter_To_Frida_Hook` | blutter_session_id, frida_session_id, function_name, hook_type, replace_value, module_hint | 【Blutter→Frida桥】Blutter偏移→运行时地址→注入Hook。 |
| ★ | `Blutter_To_R2` | session_id, function_name | 【Blutter→r2桥】跳r2并seek到指定函数偏移。 |
| ★ | `Blutter_To_Unidbg_Call` | session_id, function_name, args | 【Blutter→Unidbg桥】取Dart函数偏移→unidbg调用。 |
| ★ | `Blutter_VM_Cmd` | session_id, cmd | Dart VM命令透传(需真实Blutter引擎)。 |
| ★ | `Blutter_Widget_Tree` | session_id, filter | 识别Flutter Widget/State/Element类。 |

## Fr（47）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| △ | `Fr_Activity` | session_id, name | 追踪Activity生命周期。 |
| △ | `Fr_Apps` | filter | 列出第三方应用(包名+APK路径)。 |
| △ | `Fr_Attach` | target, timeout_ms | 【附加模式】附加到已运行进程建r2frida会话。 |
| △ | `Fr_Classes` | session_id, filter | 列出目标进程加载的Java类。 |
| △ | `Fr_Close` | session_id | 关闭指定Frida会话。 |
| △ | `Fr_Cmd` | session_id, command | 在Frida会话执行r2frida命令(须:开头)。 |
| △ | `Fr_Crash` | session_id | 捕获崩溃/信号+调用栈。 |
| △ | `Fr_Detach` | session_id | 断开Frida会话释放资源。 |
| △ | `Fr_Detect` | — | 【环境检查】检测设备frida可用性(先调此确认)。 |
| △ | `Fr_Discover` | session_id, duration_ms | 【热点发现】Stalker采样统计函数调用次数。 |
| △ | `Fr_Dump_Memory` | session_id, module_name, output_path | 【桥·内存→文件】目标进程模块内存dump到文件供R2离线分析。 |
| △ | `Fr_Env_Override` | session_id, key, value | 覆盖SystemProperties/环境变量。 |
| △ | `Fr_Eval` | session_id, js_code | 【终极】在Frida会话执行任意JS。 |
| △ | `Fr_Exports` | session_id, filter | 列出某模块导出函数。 |
| △ | `Fr_Find_Callers` | session_id, func_export, caller_module, module_hint | 【探路·反混淆】Hook系统函数抓调用方地址+调用栈。 |
| △ | `Fr_Follow_Thread` | session_id, thread_id | Stalker跟指定线程。 |
| △ | `Fr_Info` | session_id | 查看Frida会话详情。 |
| △ | `Fr_Java_Call` | session_id, class_name, method, args | 调用指定Java方法并取返回。 |
| △ | `Fr_Keyboard` | session_id, text | 模拟键盘输入。 |
| △ | `Fr_Kill` | target | 杀进程(PID或包名)。 |
| △ | `Fr_Libraries` | session_id, filter | 列出目标进程加载的动态库。 |
| △ | `Fr_List_Sessions` | — | 列出所有活跃Frida会话。 |
| △ | `Fr_LoadScript` | session_id, script_path | 从本地文件加载JS脚本到Frida会话。 |
| △ | `Fr_Ls` | path | 列出目标设备文件/目录。 |
| △ | `Fr_Malloc_Hook` | session_id | hook malloc/free追踪内存分配。 |
| △ | `Fr_Method_Overloads` | session_id, class_name, method | 枚举Java方法全部重载。 |
| △ | `Fr_Native_Hook` | session_id, func_offset, module_name, hook_type, capture_caller, caller_module | 【探路·主力】Interceptor.attach拦native函数0行手写JS。 |
| △ | `Fr_Network` | session_id, host | 过滤/追踪网络请求(host)。 |
| △ | `Fr_Prop` | session_id, key, value | 设系统属性(SystemProperties)。 |
| △ | `Fr_Ps` | filter | 列出设备运行进程(类frida-ps)。 |
| △ | `Fr_Pull` | remote_path, local_path | 从设备远程路径复制到本地。 |
| △ | `Fr_Push` | local_path, remote_path | 从本地推送到设备远程路径。 |
| △ | `Fr_Read_Messages` | session_id | 【收数据】收取Frida hook send()上报的异步数据。 |
| △ | `Fr_Rm` | path, recursive | 删除目标设备文件/目录。 |
| △ | `Fr_Root_Detect_Bypass` | session_id | 【破防】绕过Root检测。 |
| △ | `Fr_SSL_Pinning_Disable` | session_id | 【破防】绕过SSL Pinning校验。 |
| △ | `Fr_SSL_Upgrade` | session_id | hook SSL_read/write抓HTTPS明文。 |
| △ | `Fr_Search` | session_id, value, type, protection, range_min, range_max, max_results | 在目标进程内存中搜十六进制模式。 |
| △ | `Fr_Service` | session_id, name | 追踪Service。 |
| △ | `Fr_Signal_Hook` | session_id, signal | hook信号处理器。 |
| △ | `Fr_Spawn` | app, timeout_ms | 【启动模式】冷启动App并在入口点前注入Frida。 |
| △ | `Fr_Start_Server` | — | 启动frida-server(需root)。 |
| △ | `Fr_Stop_Server` | — | 停止frida-server。 |
| △ | `Fr_Strings` | session_id, filter | 搜目标进程内存中的字符串。 |
| △ | `Fr_To_R2` | frida_session_id, address, blutter_session_id | 【桥·Frida→R2】运行时地址→文件偏移→开R2并seek。 |
| △ | `Fr_Trace` | session_id, target, duration_ms | 【精确跟踪】跟踪指定函数每次调用记录参数/返回。 |
| △ | `Fr_Watch_Class` | session_id, class_name, dump_args, dump_ret, dump_bt | 【便利】一键Hook Java类所有方法。 |

## Ub（28）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| △ | `Ub_Alloc` | session_id, size, init | 模拟器内malloc内存返回指针。 |
| △ | `Ub_Call` | session_id, symbol, args, trace | 按导出符号名调用函数(Java_自动补参数)。 |
| △ | `Ub_Call_Java` | session_id, method, args | 模拟Java层方法调用(JNIEnv+jobject)。 |
| △ | `Ub_Call_Offset` | session_id, offset, args, trace | 按模块偏移调用函数(无符号内部函数)。 |
| △ | `Ub_Callback_Install` | session_id, offset, js | 安装native回调桩。 |
| △ | `Ub_Close` | session_id | 关闭模拟会话释放资源。 |
| △ | `Ub_Disasm` | session_id, address, count | capstone反汇编模拟器内存(运行时自解密后真实代码)。 |
| △ | `Ub_Dump` | session_id, address, size | 读模拟器内存(输出缓冲区/解密结果/全局变量)。 |
| △ | `Ub_Dump_To_R2` | session_id, address | 【Unidbg→R2桥】dump内存→r2反汇编ARM64。 |
| △ | `Ub_Free` | session_id, address | 释放Ub_Alloc分配的内存。 |
| △ | `Ub_Hook` | session_id, address, max_hits | 指定地址装执行hook，命中快照x0-x3/lr/sp。 |
| △ | `Ub_Hook_Hits` | session_id, keep | 读Ub_Hook命中记录，默认读后清空。 |
| △ | `Ub_Hook_To_R2_Xrefs` | session_id, address | 【Unidbg→R2桥】对hook返回地址查交叉引用。 |
| △ | `Ub_Jni_Callback` | session_id, symbol, js | JNI回调桩。 |
| △ | `Ub_List_Sessions` | — | 列出所有活跃unidbg模拟会话。 |
| △ | `Ub_Modules` | session_id | 列出模拟器已加载模块及基址。 |
| △ | `Ub_MultiCall` | session_id, calls | 多函数顺序调用链。 |
| △ | `Ub_Open` | file, call_jni | 【Unidbg·第1步】加载so到模拟器并创建会话，执行JNI_OnLoad/init_array。 |
| △ | `Ub_Patch` | session_id, address, asm | keystone汇编文本编译机器码写入内存(运行时patch)。 |
| △ | `Ub_Read_String` | session_id, address, max_len | 读C字符串(遇\0截断)。 |
| △ | `Ub_Regs` | session_id, set | 读/写CPU寄存器(不传set返回x0-x28快照)。 |
| △ | `Ub_Restore_State` | session_id | 恢复Ub_Save_State保存的寄存器快照。 |
| △ | `Ub_Save_State` | session_id | 保存CPU寄存器快照(反复调换参)。 |
| △ | `Ub_Search` | session_id, pattern, start, size | 内存中搜hex字节模式(机器码/常量)。 |
| △ | `Ub_Sequence` | session_id, calls | 多函数顺序调用链(共享内存态)。 |
| △ | `Ub_Stdout_Capture` | session_id | 捕获stdout/printf输出。 |
| △ | `Ub_Struct_Build` | session_id, spec | 构造C结构体作参数。 |
| △ | `Ub_Write` | session_id, address, hex_bytes | 写模拟器内存(hex)，写后回读校验。 |

## Il2Cpp（30）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Il2Cpp_AntiCheat_Scan` | session_id, keywords | 校验/反作弊/完整性点(verify/sign/license/root/debug)。 |
| ★ | `Il2Cpp_Assemblies` | session_id | 程序集/模块前缀统计。 |
| ★ | `Il2Cpp_Cheatable_Scan` | session_id, keywords | 可改数值关键词(血量/弹药/金币/倍率/概率/经验)。 |
| ★ | `Il2Cpp_Class_Detail` | session_id, class_name | 指定C#类的完整方法/字段。 |
| ★ | `Il2Cpp_Close` | session_id | 关闭Il2Cpp会话。 |
| ★ | `Il2Cpp_Csharp_Source` | session_id, out_dir | 生成C#源码骨架(类+方法签名)。 |
| ★ | `Il2Cpp_Dummy_DLL` | session_id, out_dir | 生成还原C#类型/方法骨架(dummy dll)。 |
| ★ | `Il2Cpp_Export` | session_id, out_dir | 导出三件套(script.json/DummyTypes/string.json)。 |
| ★ | `Il2Cpp_Field_Defs` | session_id, filter | 字段名提取(近似,精确偏移需Il2CppDumper)。 |
| ★ | `Il2Cpp_Find_Field` | session_id, name | 搜字段(按名)。 |
| ★ | `Il2Cpp_Find_Method` | session_id, name | 搜方法(按名)。 |
| ★ | `Il2Cpp_Find_Type` | session_id, name | 搜类型(按名)。 |
| ★ | `Il2Cpp_Gameplay_Scan` | session_id, keywords | 游戏逻辑关键词扫(伤害/血量/武器/命中/暴击/货币)。 |
| ★ | `Il2Cpp_Import_IDA` | session_id, out_dir | 生成IDA import脚本(af到RVA)。 |
| ★ | `Il2Cpp_Import_R2` | session_id, out_dir | 生成r2导入脚本(ff函数+重命名)。 |
| ★ | `Il2Cpp_List_Sessions` | — | 列出所有Il2Cpp会话。 |
| ★ | `Il2Cpp_Metadata_Info` | session_id | Il2Cpp会话统计(版本/类型/方法/字符串数)。 |
| ★ | `Il2Cpp_Metadata_Parse` | session_id | global-metadata.dat完整结构(magic/blob偏移/各表数量)。 |
| ★ | `Il2Cpp_Method_Detail` | session_id, method | 指定C#方法签名+RVA状态。 |
| ★ | `Il2Cpp_Methods` | session_id, filter | 列C#方法签名清单。 |
| ★ | `Il2Cpp_Namespaces` | session_id | 命名空间统计。 |
| ★ | `Il2Cpp_Open` | extract_dir, metadata, il2cpp_so | 【第1步】打开Unity APK/global-metadata.dat建Il2Cpp会话(检测版本+提C#符号)。 |
| ★ | `Il2Cpp_RVA_Patch` | session_id, method_or_class, new_return | C#方法/类→RVA定位+patch(需Il2CppDumper取精确RVA)。 |
| ★ | `Il2Cpp_RVA_Table` | session_id | 方法→RVA表(精确需Il2CppDumper)。 |
| ★ | `Il2Cpp_So_Scan` | session_id, pattern | 扫libil2cpp.so native符号。 |
| ★ | `Il2Cpp_Strings` | session_id, filter | 提C#硬编码字符串。 |
| ★ | `Il2Cpp_Symbol_Restore` | session_id | 全量C#方法→可读符号清单(导入r2/IDA)。 |
| ★ | `Il2Cpp_Type_Defs` | session_id, filter | 全量类型定义+继承启发(基类/泛型)。 |
| ★ | `Il2Cpp_Types` | session_id, filter | 列C#类型清单(全局类型)。 |
| ★ | `Il2Cpp_Version_Detect` | session_id | 从metadata头判Unity版本(v29=2021/v39=Unity6)。 |

## Nav（12）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Nav_Build_Call_Graph` | session_id, func, depth | 建某函数调用图(axf递归)。 |
| ★ | `Nav_Call_Chain` | session_id, from_func, to_func | A→B→C调用链(BFS寻径)。 |
| ★ | `Nav_Deobfuscate_Guide` | session_id, func | 反混淆导航(识别OLLVM扁平化/BCF+还原思路)。 |
| ★ | `Nav_Dominators` | session_id, func, depth | 枢纽函数(入度高,关键逻辑节点)。 |
| ★ | `Nav_Export_Graph` | session_id, func, fmt, depth | 导出调用图(json/mermaid文件)。 |
| ★ | `Nav_Function_Context` | session_id, func | 函数上下文(参数/变量/callee/caller/伪C)。 |
| ★ | `Nav_List_Sessions` | — | 列出可用Nav的r2会话。 |
| ★ | `Nav_Mermaid` | session_id, func, depth | 生成调用图Mermaid(粘进渲染器)。 |
| ★ | `Nav_Reverse_Search` | session_id, result_str | 从结果字符串反查引用地址。 |
| ★ | `Nav_Symbol_Jump` | session_id, symbol | 符号跳转+伪C上下文。 |
| ★ | `Nav_What_Calls` | session_id, func | X调用了谁(axf)。 |
| ★ | `Nav_Who_Calls` | session_id, func | 谁调用了X(axt)。 |

## Apk（8）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Apk_Close` | session_id | 关闭APK会话:关Blutter+删临时解压文件。 |
| ★ | `Apk_Install` | apk_session_id | 静默安装APK并启动，返回进程ID。 |
| ★ | `Apk_Install_Start` | apk_session_id, package | 安装并启动APK(需设备,返回PID)。 |
| ★ | `Apk_Open` | file, upload_id, arch, skip_blutter | 【第1步】打开APK/SO，自动识别类型走不同流程。APK→解压+Flutter检测+Blutter；SO→直接r2。 |
| ★ | `Apk_Pack` | apk_session_id, do_sign | 【打包】修改后的so替换回原APK并重新打包签名(带_成品后缀)。 |
| ★ | `Apk_Strings` | session_id, filter | APK层全字符串(扫解压目录)。 |
| ★ | `Apk_Upload` | file_path, label | 局域网/upload端点注册(upload_id供Apk_Open)。 |
| ★ | `Apk_Version_Info` | session_id | APK会话概要(stack/so数/blutter)。 |

## Project（5）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Project_Delete` | project_id | 删除指定已保存项目。 |
| ★ | `Project_Export` | project_id, format | 导出项目为分析报告(markdown/html)。 |
| ★ | `Project_List` | — | 列出所有已保存分析项目。 |
| ★ | `Project_Load` | project_id | 加载之前保存的项目。 |
| ★ | `Project_Save` | session_id, name, file_path, notes, commands, arch | 保存当前分析状态为项目。 |

## Os（6）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Os_Find` | base_dir, pattern | 按glob找文件。 |
| ★ | `Os_Grep` | path, pattern | 文件内grep正则。 |
| ★ | `Os_List_Dir` | path | 列出设备指定目录内容(ls -la)。 |
| ★ | `Os_Read_File` | path | 读设备文本文件内容(cat)。 |
| ★ | `Os_Stat` | path | 文件stat(大小/权限)。 |
| ★ | `Os_Write_File` | path, content | 写设备文本文件。 |

## Find（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Find_Jni_Methods` | session_id | 搜索所有JNI导出函数(Java_xxx)。 |

## Apply（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Apply_Hex_Patch` | session_id, address, hex_bytes | 对指定地址写十六进制字节补丁(NOP/改条件/注入)。 |

## Rename（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Rename_Function` | session_id, address, name | 重命名函数(afn)。 |

## Scan（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Scan_Crypto_Signatures` | session_id | 扫AES/DES/MD5/SHA常量特征定位加密。 |

## Shell（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Shell_Command` | command, use_root | 在Android设备执行Shell命令(use_root则以su执行)。 |

## File（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `File_Download` | apk_session_id | 获取文件下载ID用于局域网下载。 |

## Sqlite（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Sqlite_Query` | db_path, query | 用原生SQLiteDatabase执行SQL(读SELECT/写DML)。 |

## Address（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Address_Lookup` | blutter_session_id, address, frida_session_id | 【查询】地址双向翻译：静态偏移↔Blutter，运行时↔模块+偏移。 |

## Read（1）

| 标记 | 工具 | 参数 | 说明 |
|---|---|---|---|
| ★ | `Read_Logcat` | lines, tag | 读Android系统日志logcat，支持tag过滤。 |
