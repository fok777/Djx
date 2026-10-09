"""
engine/elf.py — ELF 符号 / 字符串解析（真实用 pyelftools + capstone）

针对 Flutter 的 libapp.so（Dart AOT）和 Unity 的 libil2cpp.so：
- 提取动态符号（.dynsym）、可执行节、导出函数
- 提取字符串（.rodata/.data/.dynstr，含 Dart 方法名、包名、硬编码）
- 识别架构，供后续 Radare2 伪 C / 补丁用
"""
import re, os, json
from typing import List, Dict, Any

# pyelftools 是可选依赖：缺失时不应导致整个 MCP 服务起不来，
# 相关函数改为返回明确错误，由调用方降级。
try:
    from elftools.elf.elffile import ELFFile
    _HAS_ELFTOOLS = True
except ImportError:
    ELFFile = None
    _HAS_ELFTOOLS = False

# 常见可打印字符串最小长度
MIN_STR = 4


def _machine_name(m: str) -> str:
    return {
        "EM_AARCH64": "arm64 (aarch64)",
        "EM_ARM": "armeabi (arm32)",
        "EM_X86_64": "x86_64",
        "EM_386": "x86",
    }.get(m, m)


def parse_elf(path: str, max_symbols: int = 20000, max_strings: int = 60000) -> Dict[str, Any]:
    """解析单个 ELF（.so / .dat 里的 so）。"""
    out: Dict[str, Any] = {"path": path, "arch": None, "machine": None,
                           "is_pie": None, "entry": None, "symbols": [],
                           "dyn_symbols": [], "strings": [], "error": None}
    if not os.path.isfile(path):
        out["error"] = "not found"
        return out
    try:
        with open(path, "rb") as f:
            if not _HAS_ELFTOOLS:
                raise RuntimeError("未装 pyelftools（pip install pyelftools），无法解析 ELF")
            elf = ELFFile(f)
            out["elfclass"] = elf.elfclass
            out["arch"] = elf.get_machine_arch()
            out["machine"] = _machine_name(elf.header["e_machine"])
            try:
                out["is_pie"] = elf.header["e_type"] in ("ET_DYN", "ET_REL")
            except Exception:
                out["is_pie"] = None
            try:
                out["entry"] = hex(elf.header["e_entry"])
            except Exception:
                pass
            flags = elf.header["e_flags"]
            out["flags"] = hex(flags)
            # 节概览（先做，独立）
            out["sections"] = [s.name for s in elf.iter_sections() if s.name][:64]
            # 动态符号（每个 sym 独立容错；st_info 可能是 int）
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym:
                for sym in dynsym.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    try:
                        info = sym.entry["st_info"]
                        tv = info["st_value"] if isinstance(info, dict) else (info & 0xF)
                        ot = info["st_other"] if isinstance(info, dict) else (info >> 4)
                    except Exception:
                        tv = ot = None
                    out["dyn_symbols"].append({
                        "name": name, "value": hex(sym["st_value"]),
                        "size": sym["st_size"], "type": tv, "bind": ot,
                    })
                    if len(out["dyn_symbols"]) >= max_symbols:
                        break
            # 字符串（独立容错）
            seen = set()
            str_sections = [".rodata", ".data", ".dynstr", ".strtab", ".data.rel.ro"]
            for sname in str_sections:
                sec = elf.get_section_by_name(sname)
                if sec is None:
                    continue
                data = sec.data()
                if not data:
                    continue
                for m in re.finditer(rb"[\x20-\x7E]{%d,}" % MIN_STR, data):
                    s = m.group(0).decode("ascii", "ignore")
                    if s not in seen and len(out["strings"]) < max_strings:
                        seen.add(s)
                        out["strings"].append(s)
                for m in re.finditer(rb"(?:[\x20-\x7E]\x00){%d,}" % MIN_STR, data):
                    s = m.group(0).decode("utf-16-le", "ignore").rstrip("\x00")
                    if s and s not in seen and len(out["strings"]) < max_strings:
                        seen.add(s)
                        out["strings"].append(s)
            out["string_count"] = len(out["strings"])
            out["dyn_symbol_count"] = len(out["dyn_symbols"])
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ---- Dart / Unity 特征筛选 ----
DART_PATTERNS = [
    (re.compile(r"^Go_"), "dart_aot_fn"),
    (re.compile(r"^dart:"), "dart_lib"),
    (re.compile(r"^_kDart"), "dart_runtime"),
    (re.compile(r"\.dart$"), "dart_source"),
    (re.compile(r"^\[\[\u2026|Instance_|@dart", re.UNICODE), "dart_vm"),
]
UNITS = ["flutter", "package:", "assets/", "dart:", "io.", "ui.", "material"]


def pick_dart_artifacts(elf: Dict[str, Any]) -> Dict[str, Any]:
    """从 ELF 结果里挑出 Dart 相关符号/字符串（秒级全符号的核心）。"""
    dart_syms, dart_strs, interesting = [], [], []
    for s in elf.get("dyn_symbols", []):
        n = s.get("name", "")
        if any(p.search(n) for p in [re.compile(r"^Go_"), re.compile(r"^dart"), re.compile(r"Function"), re.compile(r"^_\w{4,}")]):
            dart_syms.append(n)
    for s in elf.get("strings", []):
        for p, tag in DART_PATTERNS:
            if p.search(s):
                dart_strs.append(s)
                break
        else:
            if any(u in s for u in UNITS):
                interesting.append(s)
    return {
        "dart_symbol_count": len(set(dart_syms)),
        "dart_symbols_sample": list(dict.fromkeys(dart_syms))[:200],
        "dart_strings": list(dict.fromkeys(dart_strs))[:500],
        "interesting_strings": list(dict.fromkeys(interesting))[:800],
        "total_strings": elf.get("string_count"),
        "total_dyn_symbols": elf.get("dyn_symbol_count"),
    }


def scan_dir_elfs(base_dir: str, pattern: str = "lib*.so", max_each: int = 4) -> Dict[str, Any]:
    """扫描目录下所有匹配 ELF，逐个解析（用于全量扫描）。"""
    import glob
    files = sorted(glob.glob(os.path.join(base_dir, "**", pattern), recursive=True))[:max_each * 8]
    report = {"scanned": len(files), "targets": []}
    for f in files:
        r = parse_elf(f)
        r["rel"] = os.path.relpath(f, base_dir)
        r["dart"] = pick_dart_artifacts(r)
        report["targets"].append({
            "file": r["rel"], "arch": r["arch"], "machine": r["machine"],
            "error": r["error"],
            "string_count": r.get("string_count", 0),
            "dyn_symbol_count": r.get("dyn_symbol_count", 0),
            "dart_symbol_count": r["dart"]["dart_symbol_count"],
        })
    return report
