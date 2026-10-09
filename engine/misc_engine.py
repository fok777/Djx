"""
engine/misc_engine.py — Project_* + Os_* + 散列工具
Project 真实 JSON 存取；Sqlite 真跑；Os/logcat/shell 按 Linux 侧真实或给设备命令。
"""
import os, json, time, sqlite3, subprocess
from typing import Dict, Any
from .sessions import MANAGER, new_id


# ---------- Project_* ----------
def project_save(session_id: str = None, name: str = "", file_path: str = None,
                 notes: str = None, commands: str = None, arch: str = None) -> Dict:
    pid = new_id()
    MANAGER.projects[pid] = {
        "project_id": pid, "name": name, "session_id": session_id,
        "file_path": file_path, "notes": notes, "commands": (commands or "").splitlines(),
        "arch": arch, "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"project_id": pid, "name": name, "ok": True}


def project_load(project_id: str) -> Dict:
    p = MANAGER.projects.get(project_id)
    return p if p else {"error": f"project {project_id} not found"}


def project_list() -> list:
    return [{"project_id": p["project_id"], "name": p["name"], "arch": p.get("arch"),
             "saved_at": p.get("saved_at")} for p in MANAGER.projects.values()]


def project_delete(project_id: str) -> Dict:
    return {"deleted": MANAGER.projects.pop(project_id, None) is not None, "project_id": project_id}


def project_export(project_id: str, format: str = "markdown") -> Dict:
    p = MANAGER.projects.get(project_id)
    if not p:
        return {"error": "not found"}
    out_dir = "/var/minis/workspace/flutter_mcp/r2b/out_projects"
    os.makedirs(out_dir, exist_ok=True)
    if format == "html":
        body = ("<html><body><h1>%s</h1><p>file=%s arch=%s</p><pre>%s</pre></body></html>"
                % (p["name"], p.get("file_path"), p.get("arch"), "\n".join(p.get("commands", []))))
        path = f"{out_dir}/{p['name']}.html"
        open(path, "w").write(body)
    else:
        body = (f"# 项目 {p['name']}\n- session: {p.get('session_id')}\n- file: {p.get('file_path')}\n"
                f"- arch: {p.get('arch')}\n- 命令:\n```\n{chr(10).join(p.get('commands', []))}\n```\n"
                f"- 笔记: {p.get('notes')}\n")
        path = f"{out_dir}/{p['name']}.md"
        open(path, "w").write(body)
    return {"project_id": project_id, "format": format, "path": path}


# ---------- Os_* ----------
def os_list_dir(path: str = "/") -> Dict:
    try:
        items = [f"{f}{'/' if os.path.isdir(os.path.join(path, f)) else ''}" for f in os.listdir(path)]
        return {"path": path, "entries": items[:500]}
    except Exception as e:
        return {"path": path, "error": str(e)}


def os_read_file(path: str) -> Dict:
    if not os.path.isfile(path):
        return {"error": "not found"}
    try:
        return {"path": path, "content": open(path, "r", errors="ignore").read()[:20000]}
    except Exception as e:
        return {"error": str(e)}


# ---------- 散列工具 ----------
def read_logcat(lines: int = 50, tag: str = None) -> Dict:
    return {"cmd": f"logcat -d -t {lines}" + (f" {tag}:V *:S" if tag else ""),
            "need_device": True,
            "note": "普通模式读不到则自动 su 取全量；本 PRoot 侧无 logcat"}


def sqlite_query(db_path: str, query: str) -> Dict:
    q = query.strip()
    ro = q.lower().startswith(("select", "pragma", "with"))
    try:
        c = sqlite3.connect(f"file:{db_path}?mode={'ro' if ro else 'rw'}", uri=True)
        rows = c.execute(q).fetchall()
        c.close()
        return {"ok": True, "rows": rows[:500], "row_count": len(rows)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def shell_command(command: str, use_root: bool = False) -> Dict:
    """设备 shell（需 su）。此处只出命令，不实际执行设备命令。"""
    return {"command": command, "use_root": use_root,
            "actual_cmd": f"su -c '{command}'" if use_root else f"sh -c '{command}'",
            "executed": False, "note": "需 Android 设备执行；PRoot 侧仅出命令模板"}


def file_download(apk_session_id: str) -> Dict:
    apk = MANAGER.get("apk", apk_session_id)
    if not apk:
        return {"error": f"unknown apk session {apk_session_id}"}
    so_files = apk.get("so_list", [])
    dl = {}
    for so in so_files:
        p = os.path.join(apk.get("extract_dir", ""), so)
        if os.path.isfile(p):
            dl[so] = MANAGER.register_download(p)
    return {"apk_session_id": apk_session_id,
            "download_ids": dl,
            "usage": "curl -O http://<host>:5051/download/{id}"}
