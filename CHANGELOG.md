# 变更记录

对原始源码的整理与加固。功能未删减，工具从 276 增至 375。

## 结构

- 根目录 15 个平铺文件 → `tests/` `legacy/` `docs/` `tools/`
- 删 `legacy/fetch_bili_videos.py`（与项目无关）

## 新增模块

| 文件 | 作用 |
|---|---|
| `r2b_mcp/logging_setup.py` | 统一日志，支持 `R2B_LOG_LEVEL` / `R2B_LOG_FILE` |
| `r2b_mcp/config.py` | 配置集中，超时/路径可用环境变量覆盖 |
| `r2b_mcp/audit.py` | 启动自检：文档失真 / 悬空 route / 重名 / schema |
| `r2b_mcp/categories.py` | 分类单一事实来源，README 表格由程序生成 |
| `engine/external_engine.py` | 外部引擎定位与调用（subprocess / ctypes / module） |
| `engine/blutter_output.py` | 解析 blutter 产物 `asm/` + `pp.txt` + `objs.txt` |
| `engine/r2_ctypes.py` | 无 r2 可执行文件时，ctypes 直调 `libr_core.so` |
| `engine/engine_mgmt.py` | `Engine_*` 管理工具 |
| `engine/*_extra.py` × 7 | 补齐 87 个未实现工具 |
| `tools/install_engines.py` | 从压缩包安装引擎 |
| `tools/fetch_engines.py` | 从官方源补货引擎 |
| `requirements.txt` | 依赖声明（原本没有） |

## 修正的问题

1. **文档数字失真** —— 四处注释各写 124 / 164 / 205 / 264，实际 276。
   数字改为程序生成，`audit.py` 启动时校验。
2. **零日志** —— 5925 行代码 `logging` 用量为 0，36 处裸 `except` 静默吞异常。
3. **无依赖声明** —— 补 `requirements.txt`（pyelftools / capstone / mitmproxy）。
4. **`R2` 常量永远非空** —— `shutil.which("radare2") or "radare2"`，
   没装也当存在用，必抛 `FileNotFoundError`。改为三级查找 + ctypes 兜底。
5. **`locate_blutter()` 找错东西** —— 原找 `blutter/*.so`。真实 blutter 的
   Android 产物就是 `libblutter_<ver>.so`（名字叫 .so，实为带 `.interp` 的
   PIE 可执行文件），官方仓库版则是 `blutter.py` / `bin/blutter_dartvm{ver}`。
   现同时支持两种形态，且加 ELF magic 校验。
6. **每次调用重建 276 个 dict** —— `call_tool` 里调 `build_tools()`，改为缓存。

## 工具补齐

从 `legacy/legacy_tools.py`（189 个登记）比对出现行未实现的 87 个，逐个补上：

| 模块 | 数量 | 补什么 |
|---|---|---|
| `blutter_extra.py` | 34 | 字段/方法/继承/枚举/路由/Widget/包依赖 |
| `ub_extra.py` | 14 | 会话/内存/文件读写/堆栈/系统调用/JNI/打桩 |
| `il2cpp_extra.py` | 12 | 类/字段/属性/接口/枚举/结构体/内存读 |
| `nav_extra.py` | 11 | 图加载/DFS/环检测/统计/补丁候选 |
| `frida_extra.py` | 8 | 内存读写/堆扫描/堆栈/Java eval/gadget |
| `r2_extra.py` | 7 | 架构/映射/块/全局变量/类型/符号表 |
| `apk_extra.py` | 1 | Apk_Diff |

另补 12 个 `Engine_*` 引擎管理工具。

## 引擎接入

- radare2：官方 `android-aarch64` 包含全部 `libr_*.so`，或用 ctypes 直调。
  `libr2aibridge.so` 只是 JNI 桥，依赖 `libr_core.so`，不含本体。
- blutter：手上 23 个 `.so` 即编译好的成品，覆盖 Dart 2.14 ~ 3.12.1，
  官方 `blutter.py` 会复用 `bin/` 同版本文件跳过编译。
- unidbg：手上即官方 v0.9.8，已最新。
- frida：server 与 gadget 齐备。

## 保留未动

- `apk.py` / `apk_engine.py` 均有 `apk_open`，`r2_engine.py` /
  `r2_pseudoc.py` 均有 `r2_open`/`r2_cmd`/`r2_search_string`，
  存在相对导入互相调用，未删，避免破坏功能。
- `legacy/` 下 4 个孤儿模块（ida_mcp / unidbg / vip_break / legacy_tools）保留归档。

## 后续修复

### 函数遮蔽（静默 bug）

`HANDLER_MODULES` 里靠前的模块会遮蔽后面模块的同名函数，导致工具实际调到旧实现：

| 工具 | 遮蔽者 | 被遮蔽 | 后果 |
|---|---|---|---|
| `Ub_Env` | `tools_extra` | `ub_extra` | 只看环境变量 `R2B_UNIDBG_JAR`，永远 `available=false` |
| `Nav_Export_Graph` | `nav_engine` | `nav_extra` | 拿不到 `path` 参数，无法导出到文件 |

修复：两处均改为转发到完整实现；`Nav_Export_Graph` schema 补 `path`。
`audit.py` 新增 `_shadowed_symbols()` 检测此类遮蔽，防止复发
（允许显式转发实现，不误报）。

## 安卓端 UI（第十一轮）

### 应用图标

换成二次元风格：金发双马尾猫耳女孩、闭眼大笑、白领结红领结黑裙、
黑蝴蝶结，配小猫与星星，浅棕渐变背景。已生成 5 个密度（48~192px）
+ 圆角版 + 512px Play Store 图，Manifest 配 `icon` / `roundIcon`。

**悬浮窗图标**用同一人物的圆形透明版（`res/drawable/ic_float*.png`，48/64/96px）。

### 工具数据

新增 `tools/gen_tools_data.py`，从 `categories.py` + `tools_registry.py`
生成 `app/assets/tools_data.json`（375 个工具 / 10 个大类），不再手写。

### 界面修正

| 屏 | 改动 |
|---|---|
| 主页 | 工具数从写死 264 改为读 `tools_data.json` |
| 服务控制 | 加返回按钮；LAN IP 运行时探测（原写死 192.168.2.48）；Root 状态实际检测 |
| 工具列表 | 新增搜索框，实时过滤 + 自动展开命中项 |

同时新增 `.github/workflows/build-apk.yml`（push/tag 自动构建并发 Release）
与 `.gitignore`（排除 190MB 引擎资产）。

## 工具列表底部图标条（第十二轮）

工具列表弹窗**底部**加一排分类图标（可横向滑动），点图标只显示该分类，
再点一次恢复全部。图标按参考图绘制（`tools/` 无，直接出 PNG）：

| 图标 | 分类 | drawable |
|---|---|---|
| 蓝放大镜 | Blutter | `ic_cat_blutter` |
| 黑终端窗口 | Radare2 | `ic_cat_r2` |
| 黄尖括号 `<>` | Frida | `ic_cat_frida` |
| 绿芯片 | Unidbg | `ic_cat_unidbg` |
| 粉紫方块（十字+圆点） | Il2Cpp | `ic_cat_il2cpp` |
| 青蓝圆（地图/书本） | Nav | `ic_cat_nav` |
| 橙方块（向下箭头） | Apk | `ic_cat_apk` |
| 橙文件夹 | Os / 项目 | `ic_cat_misc` |
| 红盾牌（补充） | Pentest | `ic_cat_pentest` |
| 灰扳手（补充） | Engine | `ic_cat_engine` |

每个图标出 5 个密度（24~96px）放 `app/res/drawable-*/`，
`tools_data.json` 新增 `icon_res` 字段指向资源名。
搜索框输入时自动取消图标条的选中态，避免两种过滤打架。

## 稳定性改造：前台服务（第十三轮）

旧架构把 MCP 的 ServerSocket 开在 Activity 线程里，Activity 被系统回收
（切后台 / 内存紧张 / 熄屏）时线程立刻被杀，表现就是"挂着挂着闪退"。

### 1. 服务搬进前台 Service（根治闪退）

新增 `McpForegroundService`：

- `startForeground` + 通知栏常驻，进程优先级提升
- `START_STICKY`：进程被杀后系统尝试重建
- `WakeLock` + `WifiLock`：熄屏后 CPU / WiFi 不休眠，socket 不断连
- `onTaskRemoved` 不自杀；`stopWithTask=false`
- Activity 只做控制面板，`onDestroy` 只解绑日志回调，绝不杀服务

Manifest 补权限：`FOREGROUND_SERVICE` / `FOREGROUND_SERVICE_SPECIAL_USE` /
`WAKE_LOCK` / `POST_NOTIFICATIONS` / `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`。

### 2. 生命周期与保活

- `onResume` 通过端口探测同步真实状态（比记标志位可靠）
- 首次启动引导加入电池优化白名单，否则系统几分钟就杀后台
- Android 13+ 请求通知权限
- `bufferedLog()`：Activity 重建后补回历史日志

### 3. 后端工具调用超时

新增 `cfg.tool_timeout`（默认 120 秒，`R2B_TOOL_TIMEOUT` 可调）。
单个工具卡死不再拖垮整个 HTTP 服务，超时返回明确错误。
实测：设 3 秒后 3.0 秒抛 TimeoutError，正常调用不受影响。

### 4. 引擎资产补全

- 引擎二进制改为 `ZIP_STORED` 不压缩，释放更快
- radare2：工作流从官方 release 取 `android-aarch64` 包，23 个 `libr_*.so`
- frida-server：修了解压命名问题（`xz -dk` 只去掉 .xz，必须显式重定向）

APK 内容：raw 248.0 MB，55 个 .so
（blutter 23 / radare2 24 / unidbg 9 / frida 2）

### 修掉的构建 bug

- `bash build.sh | tee` 的退出码来自 tee，脚本失败也判成功 → 加 `set -o pipefail`
- 重复的 `@Override`（注释插在注解与方法之间）
- `MainActivity` 缺 `android.util.Log` 导入
