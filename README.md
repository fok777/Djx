# R2B MCP

安卓逆向 MCP 服务。把 APK 扔进去，自动完成：识别技术栈 → 提取符号 →
定位关键函数 → 打补丁 → 验证 → 重新签名打包。

## 快速开始

```bash
pip install -r requirements.txt

python3 run_stdio.py          # stdio 模式（给 MCP 客户端用）
python3 run_sse.py            # HTTP 模式

python3 -m r2b_mcp.audit      # 自检：工具数、引擎模块、悬空 route
python3 -m r2b_mcp.categories # 分类统计 + 引擎可用性
```

## 架构

```
r2b_mcp/           MCP 协议层：工具表、分发、自检、日志、配置
engine/            引擎实现：R2 / Frida / Blutter / Il2Cpp / Unidbg / Apk / Nav / Pentest
assets/engine/     外部引擎二进制（体积大，不入库，见下）
tools/             引擎安装与补货脚本
tests/ legacy/ docs/
```

工具按前缀分类，当前共 379 个工具：

| 类 | 数量 | 说明 |
|---|---|---|
| `R2_*` | 94 | radare2 静态分析 |
| `Blutter_*` | 66 | Flutter / Dart |
| `Fr_*` | 55 | Frida 动态 hook |
| `Il2Cpp_*` | 42 | Unity IL2CPP |
| `Ub_*` | 42 | Unidbg 离线模拟 |
| `Nav_*` | 23 | 控制流 / 反混淆导航 |
| `Misc_*` | 20 | 系统、文件、工程 |
| `Pentest_*` | 12 | 鉴权 / 密钥 / 流量 |
| `Apk_*` | 9 | APK 解包与打包 |
| `Engine_*` | 12 | 引擎管理与自检 |

数量由 `categories.py` 生成，不手写。

## 引擎

外部引擎不入库（体积大）。查看缺什么、怎么补：

```bash
python3 -m r2b_mcp.categories      # 看哪些引擎就绪
```

或调用 `Engine_Inventory` / `Engine_Fetch_Plan` 工具。

| 引擎 | 获取 |
|---|---|
| radare2 | `python3 tools/fetch_engines.py radare2`（官方 android-aarch64 包） |
| blutter | 手上已有 23 个编译好的 `libblutter_<ver>.so`，直接用，不用编译 |
| unidbg | `python3 tools/fetch_engines.py unidbg`（官方 v0.9.8） |
| frida | `python3 tools/fetch_engines.py frida --ver <版本>` |

从已有压缩包安装：

```bash
python3 tools/install_engines.py 0.txt blutter.txt
```

## 安卓端

```
app/
├── AndroidManifest.xml
├── build.sh                        # aapt2 + javac + d8 + 签名
├── keystore.jks
├── res/mipmap-*/ic_launcher.png     # 应用图标（各密度 + 圆角版）
├── assets/tools_data.json           # 由 tools/gen_tools_data.py 生成
└── src/com/r2b/app/MainActivity.java
```

工具数据不手写，改代码后重跑：

```bash
python3 tools/gen_tools_data.py
```

### 本地构建

```bash
cd app && bash build.sh      # 产物 app/R2B.app.apk
```

需要 `aapt2` / `d8` / `apksigner`（Android build-tools 35+）与 JDK 17。
路径可用环境变量覆盖：`AJ` `AAPT` `D8` `APKSIGN`。

### GitHub Actions

推送到 `main` 或打 `v*` tag 会自动构建，产物在 Actions 的 Artifacts；
打 tag 时会附带 APK 发 Release。

```bash
git add . && git commit -m "..." && git push
git tag v1.0.0 && git push --tags      # 触发 Release
```

## 已知边界

- **R2 / Nav 依赖 radare2**：缺失时这 117 个工具不可用
- **Fr 依赖 frida**：未运行时只产出可执行的 JS 脚本，标 `executed: false`
- **Blutter 类结构**：未接真实引擎时是启发式推断，返回体带 `heuristic: true`
- **Il2Cpp 字段类型**：metadata 不含类型签名，结构体偏移是 8 字节对齐估算
- **签名**：无 apksigner 时只有 V1
