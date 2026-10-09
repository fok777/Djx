"""
r2b_mcp/config.py — 集中配置

原工程配置散落各处（超时、路径、限制值硬编码在 10 个引擎模块里），
改一个超时要翻半天。这里统一收口，全部可用环境变量覆盖。

用法：
    from r2b_mcp.config import cfg
    subprocess.run(..., timeout=cfg.cmd_timeout)
"""
import os
from typing import Dict, Any


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Config:
    """运行期配置。所有字段只读约定，改请用环境变量。"""

    # ---- 子进程超时（秒）----
    cmd_timeout: int = _env_int("R2B_CMD_TIMEOUT", 60)
    analyze_timeout: int = _env_int("R2B_ANALYZE_TIMEOUT", 300)
    frida_timeout: int = _env_int("R2B_FRIDA_TIMEOUT", 30)

    # ---- 输出限制 ----
    max_output_chars: int = _env_int("R2B_MAX_OUTPUT", 200_000)
    max_search_results: int = _env_int("R2B_MAX_RESULTS", 200)
    pseudo_cache_threshold: int = _env_int("R2B_PSEUDO_CACHE_THRESHOLD", 5000)

    # ---- 目录 ----
    work_dir: str = os.getenv("R2B_WORK_DIR", os.path.join(os.path.expanduser("~"), ".r2b"))
    project_dir: str = os.getenv("R2B_PROJECT_DIR", "projects")
    output_dir: str = os.getenv("R2B_OUTPUT_DIR", "out_test")

    # ---- 行为开关 ----
    strict_mode: bool = _env_bool("R2B_STRICT", False)   # True 时缺失引擎直接报错而非降级
    auto_audit: bool = _env_bool("R2B_AUTO_AUDIT", True)  # 启动时跑一致性自检

    def ensure_dirs(self) -> None:
        for d in (self.work_dir, self.project_dir, self.output_dir):
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                pass

    def as_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in vars(self).items() if not k.startswith("_")}


cfg = Config()
