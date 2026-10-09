"""
engine/engine_mgmt.py — 外部引擎管理（放 so 进去后自检用）

提供 5 个工具：
  Engine_Status   各引擎：资产是否存在 / 是否配了调用方式 / 是否可调用
  Engine_Probe    探测某个引擎：so 导出符号、猜测入口函数、dlopen 是否成功
  Engine_Config   查看当前 engines.json
  Engine_Set      写入/修改某个引擎的调用配置
  Engine_Guide    告诉你该放哪、命名规则、接入步骤
"""
import os
import json
from typing import Dict, Any, Optional

from . import external_engine as EE


def engine_status() -> Dict[str, Any]:
    """各引擎接入状态总览。"""
    return EE.status()


def engine_probe(name: str = "blutter", path: str = None) -> Dict[str, Any]:
    """探测引擎资产：导出符号 + 猜测入口 + dlopen 结果。"""
    return EE.probe(name, path)


def engine_config() -> Dict[str, Any]:
    """查看当前 engines.json。"""
    cfg = EE.load_config()
    return {"path": EE.config_path(), "config": cfg}


def engine_set(name: str, mode: str = None, entry: str = None,
               cmd: str = None, argtypes: str = None, restype: str = None,
               args: str = None, path: str = None) -> Dict[str, Any]:
    """写入某个引擎的调用配置。cmd/argtypes/args 传 JSON 数组字符串。"""
    if not mode and not any([entry, cmd, path]):
        return {"error": "至少要给 mode 或其它一项", "example": {
            "name": "blutter", "mode": "subprocess",
            "cmd": '["python3","{blutter_py}","{libapp}","{outdir}"]'}}
    cfg = EE.load_config()
    cfg.setdefault("engines", {})
    e = cfg["engines"].setdefault(name, {})
    if mode:
        if mode not in ("subprocess", "ctypes", "module"):
            return {"error": "mode 必须是 subprocess / ctypes / module"}
        e["mode"] = mode
    if entry:
        e["entry"] = entry
    if path:
        e["path"] = path
    if restype:
        e["restype"] = restype
    for key, val in (("cmd", cmd), ("argtypes", argtypes), ("args", args)):
        if val:
            try:
                e[key] = json.loads(val) if isinstance(val, str) else val
            except json.JSONDecodeError as ex:
                return {"error": f"{key} 不是合法 JSON 数组: {ex}"}
    r = EE.save_config(cfg)
    if r.get("error"):
        return r
    return {"ok": True, "written": r["written"], "engine": name,
            "config": e, "next": f"跑 Engine_Status 确认 {name}.callable=true"}


def engine_guide() -> Dict[str, Any]:
    """引擎放置位置、命名规则、接入步骤。"""
    return EE.install_guide()


def engine_list_assets() -> Dict[str, Any]:
    """列出 engine_root 下已放入的所有资产文件（含大小）。"""
    root = EE.engine_runtime.engine_root()
    if not root or not os.path.isdir(root):
        return {"engine_root": root, "error": "engine_root 不存在"}
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            fp = os.path.join(dirpath, f)
            rel = os.path.relpath(fp, root)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                sz = None
            out.append({"path": rel, "size": sz,
                        "size_mb": round(sz / 1048576, 1) if sz else None})
    return {"engine_root": root, "count": len(out),
            "files": sorted(out, key=lambda x: -x["size_mb"] if x["size_mb"] else 0)}


def engine_r2_status() -> Dict[str, Any]:
    """radare2 接入状态：可执行文件 → ctypes(libr_core.so) → JNI 桥。"""
    from . import r2_engine, r2_ctypes, engine_runtime as ER
    exe = r2_engine._r2_binary()
    out: Dict[str, Any] = {"executable": exe}
    if exe:
        out["backend"] = "subprocess"
        return out
    info = r2_ctypes.available()
    out["ctypes"] = info
    if info.get("ok"):
        out["backend"] = "ctypes"
        return out
    # 都没有 → 看有没有 JNI 桥（桥不含本体，需 libr_core.so 配套）
    bridge = ER.locate_r2_bridge()
    out["bridge"] = bridge
    out["backend"] = "none"
    if bridge:
        deps = r2_ctypes.check_deps(os.path.dirname(bridge))
        out["bridge_note"] = (
            "libr2aibridge.so 只是 JNI 桥（导出 Java_com_r2aibridge_R2Core_*），"
            "DT_NEEDED 依赖 libr_core.so —— 它不含 radare2 本体，"
            "必须把 libr_core.so / libr_anal.so / libr_arch.so / "
            "libr_bin.so / libr_io.so / libr_util.so / libr_cons.so / "
            "libr_asm.so / libr_flag.so / libr_reg.so / libr_syscall.so / "
            "libr_parse.so / libr_crypto.so / libr_hash.so / libr_magic.so / "
            "libr_socket.so / libr_fs.so / libcapstone.so 等放进同目录")
        out["bridge_deps"] = deps
    out["hint"] = ("把 libr_core.so 等放进 <engine_root>/radare2/ 或设 "
                   "R2B_R2_LIBDIR；或设 R2B_R2 指向 r2 可执行文件")
    return out


def engine_r2_lib(dir_hint: str = "") -> Dict[str, Any]:
    """手动加载 libr_core.so（ctypes 模式）并返回可用状态。"""
    from . import r2_ctypes
    r = r2_ctypes.load(dir_hint)
    if not r.get("ok"):
        return r
    av = r2_ctypes.available()
    return {**r, **av}


def engine_r2_cmd(so: str, cmds: str = "iIj", timeout: int = 90) -> Dict[str, Any]:
    """直接跑一条 r2 命令，用来验证接入是否成功（自动选后端）。"""
    from . import r2_engine
    return r2_engine._r2(so, cmds, timeout=timeout)


def engine_r2_deps(dir_hint: str = "") -> Dict[str, Any]:
    """检查 radare2 的 libr_*.so 是否齐全（libr2aibridge.so 依赖 libr_core.so）。"""
    from . import r2_ctypes
    return r2_ctypes.check_deps(dir_hint)


def engine_inventory() -> Dict[str, Any]:
    """清点引擎资产：各引擎有什么、缺什么、去哪补完整版。

    清点各引擎资产：有什么、缺什么、去哪补完整版。
    """
    import glob
    E = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "assets", "engine")

    def ls(sub, pat="*"):
        d = os.path.join(E, sub)
        return [os.path.basename(p) for p in glob.glob(os.path.join(d, pat))] \
            if os.path.isdir(d) else []

    r2 = ls("radare2")
    librs = [f for f in r2 if f.startswith("libr_")]
    core = [f for f in r2 if f.startswith("libr_core.so")]
    bl = ls("blutter", "*.so")
    ub = ls("unidbg", "*.jar")
    fr = ls("frida")

    items = {
        "radare2": {
            "have_files": len(r2), "libr_count": len(librs),
            "has_libr_core": bool(core),
            "complete": bool(core) and len(librs) >= 15,
            "gap": ("" if core else
                    "只有 JNI 桥 libr2aibridge.so，缺 radare2 本体"
                    "（libr_core/libr_anal/libr_arch/libr_bin/libr_io 等 22 个）"),
            "official": "github.com/radareorg/radare2 releases → "
                        "radare2-{ver}-android-aarch64.tar.gz（官方预编译，含全部 libr_*.so）",
            "fix": "python3 tools/fetch_engines.py radare2",
        },
        "blutter": {
            "have_files": len(bl),
            "versions": sorted(bl),
            "complete": len(bl) > 0,
            "need_compile": False,
            "gap": "" if bl else "无引擎",
            "note": "这 " + str(len(bl)) + " 个 .so 就是编译好的成品，直接执行即可，"
                    "不必自己编译；只有目标 Dart 版本比手上最高版本更新时才需要编",
            "usage": "<exe> -i libapp.so -o outdir",
            "official": "github.com/worawit/blutter（仓库确无 GitHub Release，"
                        "但 blutter.py 会复用 bin/ 里已有的同版本可执行文件、跳过编译）",
            "fix": "python3 tools/fetch_engines.py blutter",
        },
        "unidbg": {
            "have_jars": ub,
            "complete": bool([f for f in ub if "android" in f]),
            "latest_known": "0.9.8",
            "official": "github.com/zhkl0228/unidbg releases → unidbg-0.9.8.zip",
            "fix": "python3 tools/fetch_engines.py unidbg",
        },
        "frida": {
            "have_files": fr,
            "complete": "frida-server" in fr,
            "official": "github.com/frida/frida releases → "
                        "frida-server-{ver}-android-arm64.xz / frida-gadget-{ver}-android-arm64.so.xz",
            "fix": "python3 tools/fetch_engines.py frida --ver <版本>",
        },
    }
    return {"engine_root": E,
            "items": items,
            "incomplete": [k for k, v in items.items() if not v.get("complete")],
            "note": "完整版一律走官方源；tools/fetch_engines.py 负责下载，"
                    "blutter 只能 clone 后自编译"}


def engine_fetch_plan(engine: str = "") -> Dict[str, Any]:
    """给出某个引擎的补货步骤（不下网，只输出命令）。"""
    plans = {
        "radare2": {
            "can_download": True,
            "steps": ["python3 tools/fetch_engines.py radare2"],
            "manual": ["# 或手工：",
                       "curl -LO https://github.com/radareorg/radare2/releases/"
                       "download/6.2.2/radare2-6.2.2-android-aarch64.tar.gz",
                       "tar -xzf radare2-6.2.2-android-aarch64.tar.gz",
                       "cp radare2-6.2.2-android-aarch64/lib/libr_*.so assets/engine/radare2/"],
        },
        "blutter": {
            "can_download": False,
            "need_compile": False,
            "reason": "官方仓库无 Release，但**你手上已有 23 个编译好的成品**，直接用",
            "steps": ["# 直接用现有成品，无需编译：",
                      "assets/engine/blutter/libblutter_3_12_1.so -i libapp.so -o outdir",
                      "",
                      "# 或让脚本按版本挑：",
                      "python3 tools/fetch_engines.py blutter"],
            "compile_only_if": "目标 Dart 版本 > 3.12.1（手上最高版本）时才需要",
            "deps_if_compile": "g++>=13 或 clang>=16；python3-pyelftools "
                               "python3-requests git cmake ninja-build "
                               "build-essential pkg-config libicu-dev libcapstone-dev",
        },
        "unidbg": {"can_download": True,
                   "steps": ["python3 tools/fetch_engines.py unidbg"]},
        "frida": {"can_download": True,
                  "steps": ["python3 tools/fetch_engines.py frida --ver 17.5.1"]},
    }
    if engine:
        return plans.get(engine, {"error": f"未知引擎 {engine}",
                                  "available": list(plans)})
    return plans


def blob_read(blob_id: str = "", limit: int = 200_000, offset: int = 0):
    """
    取回被截断的大结果（配合 render_result 的 blob_id 使用）。

    反汇编、内存 dump、对象池这类输出常有几 MB，直接塞回模型会爆上下文，
    所以超预算时只回摘要 + blob_id，完整内容用本工具分页取回。
    """
    from r2b_mcp.server import _load_blob, _blob_dir
    if not blob_id:
        return {"error": "需要 blob_id"}
    txt = _load_blob(blob_id)
    if txt is None:
        return {"error": "blob 不存在或已清理: %s" % blob_id,
                "dir": _blob_dir()}
    total = len(txt)
    off = max(0, int(offset or 0))
    lim = max(1, int(limit or 200_000))
    chunk = txt[off:off + lim]
    return {
        "blob_id": blob_id,
        "total_chars": total,
        "offset": off,
        "returned_chars": len(chunk),
        "has_more": off + len(chunk) < total,
        "next_offset": off + len(chunk) if off + len(chunk) < total else None,
        "content": chunk,
    }


def frida_channel(action: str = "status", module: str = "", addr: str = "",
                  tag: str = "", script: str = "", **kw):
    """
    Frida 双通道状态。

    注意：本后端（Python 侧）不直接控制设备上的 frida，
    它只给出通道判断与脚本生成；真正执行在安卓端 ToolExecutor。
    """
    import os
    root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    server = _which("frida-server")
    gadget = ""
    for c in ("assets/engine/frida/io_frida.so",
              "assets/engine/frida/libfrida-gadget.so"):
        if os.path.exists(c):
            gadget = os.path.abspath(c)
            break
    if action in ("status", "capabilities"):
        mode = "server" if server else ("gadget" if gadget else "none")
        return {
            "rooted": root,
            "server_binary_found": bool(server),
            "server_path": server or "",
            "gadget_available": bool(gadget),
            "gadget_path": gadget,
            "mode": mode,
            "rpc_supported": False,
            "rpc_note": "frida-server 的 RPC 是私有二进制协议；"
                        "本后端仅做通道判断与脚本生成，不伪装为已支持",
            "android_note": "完整能力请以安卓端 Frida_Channel 为准",
        }
    if action == "script":
        m = module or "libapp.so"
        a = addr or "0x0"
        t = tag or "hook"
        return {"script": (
            "const MOD = '%s';\nconst OFF = %s;\n"
            "function attach() {\n"
            "  const base = Module.findBaseAddress(MOD);\n"
            "  if (!base) { setTimeout(attach, 300); return; }\n"
            "  const target = base.add(OFF);\n"
            "  Interceptor.attach(target, {\n"
            "    onEnter(args) { console.log('[%s] enter ' + target); },\n"
            "    onLeave(retval) { console.log('[%s] leave ' + retval); }\n"
            "  });\n}\nattach();\n" % (m, a, t, t))}
    return {"error": "未知 action: %s" % action,
            "available": ["status", "capabilities", "script"]}


def patch_session(action: str = "list", session: str = "", target: str = "",
                  note: str = "", **kw):
    """
    补丁编辑会话（Python 侧的轻量实现：快照目录 + 版本链 + 历史）。
    与安卓端 PatchSession 概念一致，便于两端行为对齐。
    """
    import os, shutil, time
    base = os.path.join(os.path.expanduser("~"), ".r2b", "sessions")
    os.makedirs(base, exist_ok=True)
    if action == "list":
        try:
            return {"sessions": sorted(os.listdir(base))}
        except Exception as e:
            return {"error": str(e)}
    if action == "open":
        if not target or not os.path.isfile(target):
            return {"error": "需要有效的 target"}
        sid = "s%d" % int(time.time())
        d = os.path.join(base, sid)
        os.makedirs(d, exist_ok=True)
        shutil.copy2(target, os.path.join(d, "base"))
        shutil.copy2(target, os.path.join(d, "v0"))
        with open(os.path.join(d, "history"), "w", encoding="utf-8") as f:
            f.write("open %s | %s\n" % (os.path.abspath(target), note or ""))
        return {"session_id": sid, "work_dir": d, "version": 0, "max_version": 0}
    if not session:
        return {"error": "需要 session"}
    d = os.path.join(base, session)
    if not os.path.isdir(d):
        return {"error": "会话不存在: %s" % session}
    if action in ("status", "audit"):
        hist = []
        hp = os.path.join(d, "history")
        if os.path.exists(hp):
            hist = [l.strip() for l in open(hp, encoding="utf-8") if l.strip()]
        vs = [int(f[1:]) for f in os.listdir(d)
              if f.startswith("v") and f[1:].isdigit()]
        return {"session_id": session, "work_dir": d,
                "max_version": max(vs) if vs else 0, "audit": hist}
    return {"error": "未知 action: %s" % action}
