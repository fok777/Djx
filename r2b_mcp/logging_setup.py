"""
r2b_mcp/logging_setup.py — 统一日志

原工程 5925 行代码里 logging 用量为 0，36 处裸 except 静默吞异常，
出问题只能靠 print 到 stderr 猜。这里补上统一入口。

用法：
    from r2b_mcp.logging_setup import get_logger
    log = get_logger(__name__)
    log.info("..."); log.warning("..."); log.error("...", exc_info=True)

环境变量：
    R2B_LOG_LEVEL   DEBUG / INFO / WARNING / ERROR  默认 INFO
    R2B_LOG_FILE    日志文件路径，不设则只输出 stderr
"""
import os
import sys
import logging
from typing import Optional

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

_CONFIGURED = False
_DEFAULT_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"


def setup_logging(level: Optional[str] = None, log_file: Optional[str] = None) -> None:
    """初始化根 logger。重复调用安全。"""
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = (level or os.getenv("R2B_LOG_LEVEL") or "INFO").upper()
    log_file = log_file or os.getenv("R2B_LOG_FILE")

    root = logging.getLogger("r2b")
    root.setLevel(_LEVELS.get(level, logging.INFO))
    root.handlers.clear()

    fmt = logging.Formatter(_DEFAULT_FORMAT, datefmt="%H:%M:%S")

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if log_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as e:  # 日志写不了不能拖垮服务
            root.warning("无法写入日志文件 %s: %s", log_file, e)

    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """取 logger。name 会自动归到 r2b. 命名空间下，便于统一控制级别。"""
    if not _CONFIGURED:
        setup_logging()
    if not name.startswith("r2b"):
        name = f"r2b.{name}"
    return logging.getLogger(name)


def log_exception(log: logging.Logger, context: str, exc: BaseException) -> None:
    """统一的异常记录格式，避免各处 except 里写法不一。"""
    log.error("%s 失败: %s: %s", context, type(exc).__name__, exc, exc_info=True)
