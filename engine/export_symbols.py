"""
engine/export_symbols.py — 符号导出：把 script.json / Dart 符号导入 IDA / Radare2

产出 script.json，可导入 IDA / r2：
  export_r2cmd  → Radare2 命令脚本（af/fs/af 定义函数、fl 标 flag）
  export_ida    → IDA Python 脚本（define_func + auto analysis + 命名）
"""
import os, json
from typing import Dict, Any, List


def export_r2cmd(symbols: List[Dict[str, Any]], out_path: str = None,
                 so_name: str = "libapp.so") -> Dict[str, Any]:
    """symbols: [{name, value(hex), ...}]。value 有就 af，否则 fs（flag）。"""
    out_path = out_path or "r2b_import.r2cmd"
    lines = [f"# R2B 生成的 Radare2 导入脚本 · 目标 {so_name}",
             f"# 用法: r2 -a {so_name} 然后  -r r2b_import.r2cmd 或  r2 -c '..' ",
             "e asm.c = true", ""]
    for s in symbols:
        nm = s.get("name", "")
        val = s.get("value") or s.get("rva")
        if val:
            lines.append(f"af {val} {nm}")
        else:
            lines.append(f"fs symbols\nf {nm}")
    lines += ["", "# 分析", "aaa", "# 出伪 C: pdf @<fn>"]
    open(out_path, "w").write("\n".join(lines))
    return {"ok": True, "r2cmd": out_path, "symbols": len(symbols),
            "note": "r2 -c 'e asm.c=true; -r 脚本; aaa' 后 pdf@fn 出伪C"}


def export_ida(symbols: List[Dict[str, Any]], out_path: str = None,
               so_name: str = "libapp.so") -> Dict[str, Any]:
    out_path = out_path or "r2b_import_ida.py"
    jsyms = json.dumps(symbols, ensure_ascii=False, default=str)
    body = f'''# R2B 生成的 IDA 导入脚本 · 目标 {so_name}
import ida_auto, ida_name, json
# 用法: IDA 打开 {so_name} → File/Script → 运行本脚本
SYMS = {jsyms}
for s in SYMS:
    nm = s.get("name","")
    val = s.get("value") or s.get("rva")
    if val:
        try:
            addr = int(str(val), 16) if isinstance(val,str) else int(val)
            ida_name.set_name(addr, nm, 1)
        except Exception as e:
            print("skip", nm, e)
ida_auto.auto_wait()
print(f"[R2B] 导入 {{len(SYMS)}} 个符号 → {so_name}")
'''
    open(out_path, "w").write(body)
    return {"ok": True, "ida_script": out_path, "symbols": len(symbols)}


def build_symbol_list(extract_dir: str = None, il2cpp_out: str = None) -> List[Dict[str, Any]]:
    """从 IL2CPP 的 script.json 读符号。"""
    if il2cpp_out and os.path.isfile(il2cpp_out):
        return json.load(open(il2cpp_out)).get("methods", [])
    return []
