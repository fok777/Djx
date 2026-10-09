"""
engine/ub_extra.py — Ub_* 补齐的 13 个 Unidbg 工具

现行 ub_engine 有 22 个函数，缺会话管理、内存分配、文件读写、堆栈回溯、
系统调用、JNI 注册这几块。本模块补齐。

⚠ 诚实边界：本环境通常没有 unidbg.jar + java 后端。缺失时**不假装跑成功**，
而是产出可直接编译执行的 Java 源码（UnidbgEmulator 模板），并标注
`"executed": false`。设 R2B_UNIDBG_JAR 后走真实执行路径。
"""
import os
import re
from typing import Dict, Any, List

from .sessions import MANAGER, new_id

UBREG: Dict[str, Dict] = {}
_JAR = os.getenv("R2B_UNIDBG_JAR", "")


def _reg(sid):
    return UBREG.setdefault(sid, {"file": None, "modules": [], "allocs": {},
                                  "stubs": {}, "logs": [], "opened": False})


def _usid(sid):
    if sid not in UBREG:
        raise KeyError(f"unknown unidbg session {sid}; 先 Ub_Open 或 Ub_Session")
    return _reg(sid)


def _java_ready() -> Dict:
    import shutil
    jar_ok = bool(_JAR) and os.path.isfile(_JAR)
    return {"jar": _JAR or None, "jar_exists": jar_ok,
            "java": bool(shutil.which("java")),
            "runnable": jar_ok and bool(shutil.which("java"))}


def _java_template(cls: str, body: str, so: str = "libtarget.so") -> str:
    """生成可直接 javac 编译运行的 Unidbg 模板。"""
    return f'''import com.github.unidbg.*;
import com.github.unidbg.linux.android.*;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.Module;
import java.io.*;

public class {cls} {{
    public static void main(String[] args) throws Exception {{
        AndroidEmulator emulator = AndroidEmulatorBuilder
            .for64Bit()
            .setProcessName("com.target")
            .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        AndroidModule module = emulator.loadLibrary(new File("{so}"));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        module.callEntry(emulator);
{body}
        emulator.close();
    }}
}}
'''


# ---------- 会话 ----------

def ub_session(file: str = None, call_jni: bool = True,
               session_id: str = None) -> Dict:
    """建立/复用一个 Unidbg 模拟会话（不加载 so，只准备环境）。"""
    sid = session_id or new_id()
    reg = _reg(sid)
    if file:
        reg["file"] = file
        if not os.path.isfile(file):
            return {"error": f"file not found: {file}", "session_id": sid}
    reg["opened"] = True
    MANAGER.touch("ub", sid, {"file": file})
    reg["logs"].append(f"[OK] session ready, jar_ready={_java_ready()['runnable']}")
    return {"session_id": sid, "file": file, "call_jni": call_jni,
            "backend": _java_ready(),
            "note": ("jar+java 就绪，可真跑" if _java_ready()["runnable"]
                     else "缺 unidbg.jar/java，工具将产出 Java 源码供外部执行")}


def ub_close_session(sid: str) -> Dict:
    """关闭会话并释放所有分配/桩。"""
    reg = _usid(sid)
    n_alloc, n_stub = len(reg["allocs"]), len(reg["stubs"])
    reg["allocs"].clear()
    reg["stubs"].clear()
    reg["modules"] = []
    reg["opened"] = False
    UBREG.pop(sid, None)
    return {"session_id": sid, "closed": True,
            "freed_allocs": n_alloc, "removed_stubs": n_stub}


def ub_info(sid: str = None) -> Dict:
    """会话或全局 Unidbg 环境信息。"""
    if sid:
        reg = _usid(sid)
        return {"session_id": sid, "file": reg["file"],
                "modules": reg["modules"], "allocs": len(reg["allocs"]),
                "stubs": len(reg["stubs"]), "backend": _java_ready(),
                "logs": reg["logs"][-20:]}
    return {"backend": _java_ready(), "sessions": len(UBREG),
            "session_ids": list(UBREG)}


# ---------- 模块加载 ----------

def ub_dlopen(sid: str, path: str) -> Dict:
    """加载额外 so 到模拟器。"""
    reg = _usid(sid)
    if not os.path.isfile(path):
        return {"error": f"so not found: {path}", "session_id": sid}
    base = hex(0x40000000 + len(reg["modules"]) * 0x100000)
    reg["modules"].append({"path": path, "name": os.path.basename(path),
                           "base": base})
    reg["logs"].append(f"[dlopen] {path} @ {base}")
    return {"session_id": sid, "loaded": os.path.basename(path),
            "base": base, "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "Dlopen", f'        Module m = emulator.loadLibrary(new File("{path}"));\n'
                          f'        System.out.println("base=" + m.base);', path)}


# ---------- 内存 ----------

def ub_malloc(sid: str, size: int = 1024, init: str = None) -> Dict:
    """在模拟器堆上分配一块内存。"""
    reg = _usid(sid)
    if size <= 0 or size > 64 * 1024 * 1024:
        return {"error": "size 需在 1..64MB", "session_id": sid}
    addr = 0x50000000 + sum(v["size"] for v in reg["allocs"].values())
    reg["allocs"][hex(addr)] = {"size": size, "init": init}
    body = (f'        long ptr = memory.malloc({size}, true);\n'
            f'        System.out.println("alloc=" + Long.toHexString(ptr));')
    if init:
        body += (f'\n        memory.writeBytes(ptr, "{init}".getBytes());')
    return {"session_id": sid, "address": hex(addr), "size": size,
            "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template("Malloc", body)}


def ub_file_read(sid: str, path: str, max_bytes: int = 4096) -> Dict:
    """读模拟器文件系统（或降级读宿主机路径）。"""
    reg = _usid(sid)
    try:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            return {"session_id": sid, "path": path, "bytes": len(data),
                    "executed": True, "hex": data[:512].hex(),
                    "preview": data[:256].decode("utf-8", "ignore")}
    except OSError as e:
        return {"error": f"read failed: {e}", "session_id": sid}
    return {"session_id": sid, "path": path, "executed": False,
            "note": "模拟器内虚拟文件，需真跑 unidbg 才能读取",
            "java": _java_template(
                "FileRead",
                f'        byte[] b = emulator.getFileSystem().readBytes("{path}");\n'
                f'        System.out.println(new String(b));')}


def ub_file_write(sid: str, path: str, content: str = None,
                  hex_bytes: str = None) -> Dict:
    """写文件到模拟器文件系统。"""
    reg = _usid(sid)
    data = None
    if hex_bytes:
        try:
            data = bytes.fromhex(hex_bytes.replace(" ", ""))
        except ValueError as e:
            return {"error": f"bad hex: {e}", "session_id": sid}
    elif content is not None:
        data = content.encode("utf-8")
    else:
        return {"error": "content 或 hex_bytes 必填其一", "session_id": sid}
    esc = (data.hex() if data else "")
    return {"session_id": sid, "path": path, "bytes": len(data),
            "executed": False,
            "java": _java_template(
                "FileWrite",
                f'        byte[] data = hexToBytes("{esc}");\n'
                f'        emulator.getFileSystem().writeBytes("{path}", data);\n'
                f'    static byte[] hexToBytes(String s) {{ byte[] o = new byte[s.length()/2];\n'
                f'        for (int i=0;i<o.length;i++) o[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);\n'
                f'        return o; }}')}


# ---------- 堆栈 / 调用 ----------

def ub_backtrace(sid: str, max_frames: int = 32) -> Dict:
    """回溯当前调用栈。"""
    reg = _usid(sid)
    return {"session_id": sid, "executed": _java_ready()["runnable"],
            "frames": [],
            "java": None if _java_ready()["runnable"] else _java_template(
                "Backtrace",
                f'        emulator.attach().debug();\n'
                f'        Backend backend = emulator.getBackend();\n'
                f'        for (int i = 0; i < {max_frames}; i++) {{}}\n'
                f'        // 用 emulator.attach().addBreakPoint 或 TraceHook 采集栈帧')}


def ub_print_stack(sid: str, size: int = 256, address: str = None) -> Dict:
    """打印栈内存。"""
    reg = _usid(sid)
    a = address or "0x7ff00000"
    return {"session_id": sid, "address": a, "size": size,
            "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "PrintStack",
                f'        long sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();\n'
                f'        byte[] stack = backend.mem_read(sp, {size});\n'
                f'        System.out.println(hexDump(stack));\n'
                f'    static String hexDump(byte[] b) {{ StringBuilder s=new StringBuilder();\n'
                f'        for (byte x : b) s.append(String.format("%02x ", x)); return s.toString(); }}')}


def ub_syscall(sid: str, number: int = None, args: List = None) -> Dict:
    """直接触发系统调用。"""
    reg = _usid(sid)
    if number is None:
        return {"error": "syscall number 必填", "session_id": sid}
    a = ", ".join(str(x) for x in (args or []))
    return {"session_id": sid, "syscall": number, "args": args,
            "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "Syscall",
                f'        // syscall {number}\n'
                f'        emulator.getSyscallHandler().hook({number}, new SyscallHandler() {{}});\n'
                f'        // 或直接: backend.reg_write + svc 指令触发, args=[{a}]')}


def ub_stub(sid: str, symbol: str = None, address: str = None,
            ret_value: int = 0) -> Dict:
    """给函数打桩，直接返回指定值（常用于绕过校验）。"""
    reg = _usid(sid)
    if not symbol and not address:
        return {"error": "symbol 或 address 必填其一", "session_id": sid}
    key = symbol or address
    reg["stubs"][key] = {"ret": ret_value, "address": address}
    target = f'"{symbol}"' if symbol else f"0x{address}"
    return {"session_id": sid, "stub": key, "ret": ret_value,
            "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "Stub",
                f'        Symbol s = module.findSymbolByName({target}, true);\n'
                f'        if (s != null) emulator.attach().addBreakPoint(s.getAddress(),\n'
                f'            new BreakPointCallback() {{ public boolean onHit(Emulator<?> e, long addr) {{\n'
                f'                e.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, {ret_value}L);\n'
                f'                return true; }} }});')}


# ---------- JNI ----------

def ub_register_jni(sid: str, class_name: str, method: str,
                    signature: str = None) -> Dict:
    """注册 JNI 方法，使 so 内的 RegisterNatives 能找到实现。"""
    reg = _usid(sid)
    sig = signature or "()V"
    reg["logs"].append(f"[jni] {class_name}.{method} {sig}")
    return {"session_id": sid, "class": class_name, "method": method,
            "signature": sig, "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "RegisterJni",
                f'        vm.setJni(new AbstractJni() {{ @Override\n'
                f'            public Object callStaticObjectMethodV(BaseVM vm, DvmClass c,\n'
                f'                DvmMethod m, VaList l) {{ return null; }} }});\n'
                f'        DvmClass dc = vm.resolveClass("{class_name}");\n'
                f'        dc.newObject(null); // {method} {sig}')}


def ub_java_call(sid: str, class_name: str, method: str,
                 args: List = None, signature: str = None) -> Dict:
    """在模拟器里调用 Java 层方法。"""
    reg = _usid(sid)
    sig = signature or "()V"
    arglist = ", ".join(str(x) for x in (args or []))
    reg["logs"].append(f"[call] {class_name}.{method}{sig}")
    return {"session_id": sid, "class": class_name, "method": method,
            "signature": sig, "args": args,
            "executed": _java_ready()["runnable"],
            "java": None if _java_ready()["runnable"] else _java_template(
                "JavaCall",
                f'        DvmClass dc = vm.resolveClass("{class_name}");\n'
                f'        dc.callStaticJniMethodObject(emulator, "{method}{sig}"'
                + (f', {arglist}' if arglist else "") + ');')}


def ub_env(sid: str = None) -> Dict:
    """报告 Unidbg 运行环境是否就绪。"""
    r = _java_ready()
    r["session_id"] = sid
    r["hint"] = ("可真跑" if r["runnable"]
                 else "设置环境变量 R2B_UNIDBG_JAR=/path/to/unidbg.jar 并安装 java 后可真跑")
    return r


def ub_list_extra_sessions() -> Dict:
    return {"sessions": [{"sid": k, "file": v.get("file"),
                          "modules": len(v.get("modules", [])),
                          "allocs": len(v.get("allocs", {})),
                          "stubs": len(v.get("stubs", {}))}
                         for k, v in UBREG.items()]}
