"""
engine/apk_engine.py — Apk_* 4 工具（session 模型）
Apk_Open(APK→解压+检测+Blutter；SO→r2) / Apk_Close / Apk_Install / Apk_Pack(打包+签名成品)
"""
import os, json, time, shutil, glob
from typing import Dict, Any
from .sessions import MANAGER, new_id
from . import apk, blutter_engine, r2_engine, pack_sign


def _apk(sid):
    return MANAGER.require("apk", sid)


def apk_open(file: str = None, upload_id: str = None, arch: str = None,
             skip_blutter: bool = False, session_id: str = None) -> Dict:
    if file:
        path = file
    elif upload_id:
        path = MANAGER.upload_path(upload_id)
    else:
        return {"error": "需要 file 或 upload_id"}
    if not os.path.isfile(path):
        return {"error": f"file not found: {path}"}

    sid = session_id or new_id()
    ext = os.path.splitext(path)[1].lower()

    if ext in (".so", ".elf", ".o"):
        # 直接 r2 打开
        r2_sid = r2_engine.r2_open(path, analyze=True)["session_id"]
        MANAGER.touch("apk", sid, {"file": path, "type": "so", "r2_session_id": r2_sid})
        return {"session_id": sid, "type": "so", "r2_session_id": r2_sid,
                "note": "SO 一步到位，直接 R2_* 工具操作"}

    # APK
    ctx = apk.apk_open(path, path + ".extracted")
    so_list = [os.path.relpath(s, ctx["extract_dir"]) for s in
                glob.glob(os.path.join(ctx["extract_dir"], "lib/**/*.so"), recursive=True)]
    stack = ctx["stack_info"]["stack"]
    meta = {"file": path, "type": "apk", "extract_dir": ctx["extract_dir"],
             "so_list": so_list, "stack": stack, "blutter_sid": None, "packed": None}
    MANAGER.touch("apk", sid, meta)
    res = {"session_id": sid, "type": "apk", "stack": stack,
            "so_list": so_list, "file_count": ctx["file_count"]}
    if not skip_blutter and "libapp.so" in " ".join(so_list):
        libapp = os.path.join(ctx["extract_dir"], "lib/arm64-v8a/libapp.so")
        libapp = next((os.path.join(ctx["extract_dir"], s) for s in so_list if s.endswith("libapp.so")), None)
        if libapp:
            b = blutter_engine.blutter_analyze(libapp)
            meta["blutter_sid"] = b.get("session_id")
            res["blutter_sid"] = b.get("session_id")
            res["blutter"] = {"class_count": b.get("class_count"), "func_count": b.get("func_count"),
                              "pp_count": b.get("pp_count"), "dart_version": b.get("dart_version")}
    return res


def apk_close(session_id: str) -> Dict:
    m = _apk(session_id)
    MANAGER.close("apk", session_id)
    return {"closed": True, "session_id": session_id,
            "note": "已清临时解压目录 + 关联 Blutter 会话"}


def apk_install(apk_session_id: str) -> Dict:
    m = _apk(apk_session_id)
    return {"cmd": f"su -c 'pm install -r {m['file']}'",
            "start_cmd": "am start -n <pkg>/<Activity>",
            "need_device": True, "note": "root 静默安装+启动，返回 PID 供 Fr_Attach/Fr_Spawn"}


def apk_pack(apk_session_id: str, do_sign: bool = True) -> Dict:
    """把解压目录里被改的 so 替换回原 APK，重打包+签名。"""
    m = _apk(apk_session_id)
    ext = m["extract_dir"]
    src = m["file"]
    # 找修改过的 so（提取目录里的 so，覆盖回原 apk 对应路径）
    patch_map = {}
    for rel in m["so_list"]:
        p = os.path.join(ext, rel)
        if os.path.isfile(p):
            patch_map[rel] = p
    out = src.replace(".apk", "") + "_final.apk"
    pk = pack_sign.pack_output(src, patch_map, do_sign=do_sign, out=out)
    final = pk.get("final", out)
    m["packed"] = final
    return {"output": final, "replaced": pk.get("repack", {}).get("replaced"),
            "v1_signed": pk.get("v1"), "v2v3_signed": pk.get("v2v3"),
            "keystore": pk.get("keystore"),
            "note": "ASCII 名保证 JVM 签名可靠；V1 in-place 签；v2v3 需 apksigner(缺失则只 V1)"}
