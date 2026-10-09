"""
engine/unidbg.py — Unidbg 模拟调用桥接

unidbg 可模拟运行 .so（无需真机/目标设备）：加载 libil2cpp.so/libapp.so，
按 R2 定位的函数偏移发起符号化调用。生成可直接跑的 unidbg 脚本。
真实跑需 JUnit-vm unidbg（JVM 侧）；未装则输出脚本 + 说明，不伪造结果。
"""
import os, shutil
from typing import Dict, Any


def unidbg_call(so: str, func: str, args_repr: str = "0", out: str = None) -> Dict[str, Any]:
    """生成 unidbg 调用脚本（加载 so，调 func(args)）。"""
    out = out or (so + ".unidbg.java")
    fname = os.path.basename(so)
    code = f'''// R2B 生成的 Unidbg 模拟调用骨架（无需目标设备）
// 依赖: unidbg + 目标 so 的依赖（libc/libm/libstdc++，参考 assets/unidbg/）
// 用法: 放进 unidbg JUnit 工程，JVM 跑；so 先经 R2 定位 {func} 的偏移/签名
public class R2bUnidbgCall {{
  public static void main(String[] args) throws Exception {{
    AndroidEmulator emu = new AndroidEmulator(new UnidbgAndroid("arm64"));
    MemFactory mem = emu.getMemory();
    // 依 so 的 NEEDED 逐个 loadLibrary 依赖
    AndroidLibrary so = mem.loadLibrary(new File("{fname}"), true);
    Number r = so.callFunction(emu, "{func}", {args_repr});   // func({args_repr})
    System.out.println("[unidbg] {func} = " + r);
    emu.close();
  }}
}}
// 说明: 需 unidbg(JVM) 环境才真跑；未装则本骨架供参考（诚实标注）
'''
    open(out, "w").write(code)
    return {"ok": True, "script": out, "so": so, "func": func, "args": args_repr,
            "runnable": bool(shutil.which("java") or os.path.isdir("/usr/lib/jvm")),
            "note": "需 unidbg(JVM) 才能真跑；R2 先定位 func 偏移/签名再填 args"}
