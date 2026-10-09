#!/usr/bin/env python3
"""
把引擎资产包（那几个 txt 实为 zip）装进 assets/engine/。

用法：
    python3 tools/install_engines.py 0.txt blutter.txt old_r2b.txt
    python3 tools/install_engines.py 0.txt --dest /path/to/assets/engine

会自动识别 zip 内目录结构并放到对应子目录：
    blutter/*.so          -> assets/engine/blutter/
    radare2/*.so          -> assets/engine/radare2/
    unidbg/*.jar|*.so     -> assets/engine/unidbg/
    frida/*               -> assets/engine/frida/
    old_r2b/*             -> 只作参考，不装进引擎目录
"""
import os
import sys
import zipfile
import shutil

MAP = {
    "blutter": "blutter",
    "radare2": "radare2",
    "unidbg": "unidbg",
    "frida": "frida",
}
SKIP_TOP = {"old_r2b"}          # 逆向产物，不是引擎


def install(zpath: str, dest: str) -> int:
    if not zipfile.is_zipfile(zpath):
        print(f"  跳过 {zpath}（不是 zip）")
        return 0
    n = 0
    with zipfile.ZipFile(zpath) as z:
        for i in z.infolist():
            if i.is_dir():
                continue
            top = i.filename.split("/")[0]
            if top in SKIP_TOP:
                continue
            sub = MAP.get(top)
            if not sub:
                continue
            rel = "/".join(i.filename.split("/")[1:]) or os.path.basename(i.filename)
            out = os.path.join(dest, sub, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with z.open(i) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            print(f"  ✓ {sub}/{rel}  ({i.file_size/1048576:.1f} MB)")
            n += 1
    return n


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dest = None
    for a in sys.argv[1:]:
        if a.startswith("--dest="):
            dest = a.split("=", 1)[1]
    if not dest:
        dest = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "assets", "engine")
    os.makedirs(dest, exist_ok=True)
    print(f"目标目录: {dest}\n")
    total = 0
    for z in args:
        if not os.path.isfile(z):
            print(f"  跳过 {z}（文件不存在）")
            continue
        total += install(z, dest)
    print(f"\n共安装 {total} 个文件")
    print("下一步：python3 -m r2b_mcp.audit  # 确认工具表")
    print("        Engine_R2_Status / Engine_Status  # 确认引擎就绪")


if __name__ == "__main__":
    main()
