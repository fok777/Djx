"""
engine/pack_sign.py — 打包输出（V1+V2+V3 签名成品）

把 patch 后的 .so 塞回 APK 重新打包，再签名：
  V1 = jarsigner（存在）
  V2/V3 = apksigner（动态探测 build-tools；缺则跳过并标注）
"""
import os, re, json, subprocess, zipfile, shutil, time
from typing import Dict, Any, List, Optional


def _which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _find_apksigner() -> Optional[str]:
    cand = ["/tmp/bt34/android-14/apksigner"]
    for root in ("/opt/android-sdk/build-tools", "/usr/lib/android-sdk/build-tools"):
        if os.path.isdir(root):
            for d in sorted(os.listdir(root), reverse=True):
                cand.append(os.path.join(root, d, "apksigner"))
    return _find_apksigner2(cand) or _which("apksigner")


def _find_apksigner2(cand: list) -> Optional[str]:
    return cand[0] if cand else None


def make_keystore(path: str = None, cn: str = "R2B", storepass: str = "android") -> Dict[str, Any]:
    path = path or "/var/minis/workspace/flutter_mcp/r2b/keystore.r2b.jks"
    keytool = _which("keytool") or "/usr/bin/keytool"
    if not os.path.exists(path):
        subprocess.run([keytool, "-genkeypair", "-v", "-keystore", path,
                        "-alias", "r2b", "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "3650", "-storepass", storepass,
                        "-keypass", storepass, "-dname", f"CN={cn},OU=R2B,O=R2B,L=NA,ST=NA,C=US"],
                       capture_output=True, text=True)
    return {"keystore": path, "alias": "r2b", "storepass": storepass, "created": not os.path.exists(path)}


def repack_apk(apk_path: str, patch_map: Dict[str, str], out_apk: str = None) -> Dict[str, Any]:
    """patch_map: {apk内相对路径: 本地替换文件路径}。重建 zip。"""
    out_apk = out_apk or (apk_path + ".repack" + time.strftime("%H%M%S") + ".apk")
    with zipfile.ZipFile(apk_path) as zin, zipfile.ZipFile(out_apk, "w", zipfile.ZIP_DEFLATED) as zout:
        names = zin.namelist()
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename in patch_map and os.path.isfile(patch_map[item.filename]):
                data = open(patch_map[item.filename], "rb").read()
            zout.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED)
    return {"ok": True, "out": out_apk, "replaced": list(patch_map.keys())}


def sign_v1(apk: str, ks: Dict, out: str = None) -> Dict[str, Any]:
    jarsigner = _which("jarsigner") or "/usr/bin/jarsigner"
    p = subprocess.run([jarsigner, "-keystore", ks["keystore"],
                        "-storepass", ks["storepass"], "-keypass", ks["storepass"],
                        apk, ks["alias"]],
                       capture_output=True, text=True)
    ok = p.returncode == 0 and os.path.exists(apk)
    return {"scheme": "v1", "ok": ok, "out": apk if ok else None,
            "err": (p.stderr or p.stdout)[-400:]}


def sign_v2_v3(apk: str, ks: Dict) -> Dict[str, Any]:
    apksigner = _find_apksigner()
    if not apksigner:
        return {"scheme": "v2/v3", "ok": False,
                "err": "apksigner not found; 装 build-tools 的 apksigner 后可签 V2/V3"}
    out = apk + ".v23.apk"
    p = subprocess.run([apksigner, "sign",
                        "--ks", ks["keystore"], "--ks-pass", f"pass:{ks['storepass']}",
                        "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                        "--v3-signing-enabled", "true", out],
                       capture_output=True, text=True)
    ok = p.returncode == 0 and os.path.exists(out)
    return {"scheme": "v2/v3", "ok": ok, "out": out if ok else None,
            "err": (p.stderr or p.stdout)[-400:]}


def pack_output(apk_path: str, patch_map: Dict[str, str],
                do_sign: bool = True, out: str = None) -> Dict[str, Any]:
    """打包 + 签名，产出成品 APK。"""
    out = out or (apk_path + ".modded" + time.strftime("%Y%m%d%H%M%S") + ".apk")
    rep = repack_apk(apk_path, patch_map, out)
    result = {"repack": rep, "signs": [], "final": out, "ok": rep["ok"]}
    if do_sign:
        ks = make_keystore()
        v1 = sign_v1(out, ks)   # in-place 签 out (V1)
        result["signs"].append(v1)
        result["v1"] = v1["ok"]
        result["final"] = out
        v23 = sign_v2_v3(out, ks)
        result["signs"].append(v23)
        result["v2v3"] = v23["ok"]
        if v23.get("out"):
            result["final"] = v23["out"]
        result["keystore"] = ks["keystore"]
    return result
