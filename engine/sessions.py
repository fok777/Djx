"""
engine/sessions.py — 会话模型（核心）

所有工具都使用 session_id，调用方不需要处理文件路径。
五类会话：apk / r2 / blutter / frida / ub。
SessionManager 只负责 id 分配 + 生命周期；具体数据由各引擎自己按 sid 存。
"""
import os, uuid, time, json, threading
from typing import Dict, Any, Optional

_LOCK = threading.Lock()


def new_id() -> str:
    return uuid.uuid4().hex[:8]


class SessionManager:
    def __init__(self):
        # 每类会话：sid -> meta（引擎额外数据放在各引擎 registry）
        self.apk: Dict[str, Dict] = {}
        self.r2: Dict[str, Dict] = {}
        self.blutter: Dict[str, Dict] = {}
        self.frida: Dict[str, Dict] = {}
        self.ub: Dict[str, Dict] = {}
        self.uploads: Dict[str, Dict] = {}      # 局域网上传
        self.downloads: Dict[str, str] = {}      # download_id -> 路径
        self.projects: Dict[str, Dict] = {}      # 持久化 Project
        self._created = time.time()

    # ---- 通用 ----
    def touch(self, registry: str, sid: str, meta: Dict) -> Dict:
        getattr(self, registry)[sid] = meta
        return meta

    def get(self, registry: str, sid: str) -> Optional[Dict]:
        return getattr(self, registry, {}).get(sid)

    def require(self, registry: str, sid: str) -> Dict:
        m = getattr(self, registry, {}).get(sid)
        if m is None:
            raise KeyError(f"unknown {registry} session: {sid}")
        return m

    def close(self, registry: str, sid: str) -> Dict:
        d = getattr(self, registry, {})
        m = d.pop(sid, None)
        return {"closed": m is not None, "session_id": sid}

    def list_sessions(self, registry: str) -> list:
        return [{"session_id": k, **v} for k, v in getattr(self, registry, {}).items()]

    # ---- 上传/下载（局域网模式） ----
    def register_upload(self, meta: Dict) -> str:
        sid = new_id()
        self.uploads[sid] = meta
        return sid

    def upload_path(self, upload_id: str) -> str:
        return self.require("uploads", upload_id)["path"]

    def register_download(self, path: str) -> str:
        did = new_id()
        self.downloads[did] = path
        return did

    # ---- 统计 ----
    def summary(self) -> Dict:
        return {
            "uptime_s": int(time.time() - self._created),
            "apk": len(self.apk), "r2": len(self.r2),
            "blutter": len(self.blutter), "frida": len(self.frida),
            "ub": len(self.ub), "projects": len(self.projects),
            "uploads": len(self.uploads), "downloads": len(self.downloads),
        }


# 全局单例
MANAGER = SessionManager()
