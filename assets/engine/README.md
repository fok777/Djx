# 内置引擎资产

全部是开源项目，公开可获取。放进对应子目录后，`engine_runtime.locate_*()` 会自动定位并优先使用，缺失才回落系统 PATH。

| 目录 | 放什么 | 开源地址 |
|---|---|---|
| `blutter/` | 整个 blutter 仓库（git clone 即可） | github.com/worawit/blutter |
| `radare2/` | r2 / radare2 可执行 | github.com/radareorg/radare2 |
| `frida/` | frida-server（设备端）+ libfrida-gadget*.so | github.com/frida/frida |
| `unidbg/` | unidbg.jar（含依赖） | github.com/zhkl0228/unidbg |

## Blutter 注意事项

**不需要编译** —— `blutter/` 下那 23 个 `libblutter_<版本>.so` 就是编译好的成品。
名字虽叫 `.so`，实为带 `.interp` 的 PIE 可执行文件（`/system/bin/linker64`），直接跑：

```sh
./libblutter_3_12_1.so -i libapp.so -o outdir
```

覆盖 Dart 2.14 ~ 3.12.1，比官方 README 声明的 Android 支持上限（3.11.1）还新。

- 官方仓库（github.com/worawit/blutter）确实**没有 GitHub Release**，源码即分发
- 但官方 `blutter.py` 会先查 `bin/blutter_dartvm{ver}_{os}_{arch}`，
  **命中就跳过编译** —— 所以把现有 .so 按官方命名链进 bin/ 即可复用
  （`python3 tools/fetch_engines.py blutter` 会自动做这层映射）
- **只有目标 Dart 版本 > 3.12.1 时才需要真的编译**，那时要：
  g++ ≥ 13 或 clang ≥ 16 + cmake / ninja / libicu-dev / libcapstone-dev，
  首次会 checkout Dart 源码，5~30 分钟
- 仅支持 Android arm64（arm64 二进制在 x86 机器上跑不了）

## 接入步骤

1. 把仓库/二进制放进对应子目录
2. `Engine_List_Assets` 确认文件被识别
3. `Engine_Set` 配调用方式（blutter 用 `mode=subprocess`）
4. `Engine_Status` 确认 `callable=true`，之后 `Blutter_Analyze` 自动走真实引擎
