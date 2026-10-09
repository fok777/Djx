#!/data/data/com.termux/files/usr/bin/bash
# R2B MCP 一键部署到 Termux
#
# 用法（在 Termux 里执行）：
#   bash install_termux.sh
#
# 装完后启动：
#   cd ~/r2b && python3 run_sse.py
#
# 这是让 375 个工具真正可用的方式——后端是 Python 写的，
# Termux 有 Python，直接跑就是完整能力。
set -e

PREFIX=/data/data/com.termux/files/usr
HOME_DIR=$HOME
R2B_DIR="$HOME_DIR/r2b"
ENGINE_DIR="$R2B_DIR/assets/engine"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$1"; }
ok() { printf '\033[1;32m[✓] %s\033[0m\n' "$1"; }

say "0/6 环境检查"
if [ ! -d "$PREFIX" ]; then
  echo "这不像 Termux 环境（找不到 $PREFIX）。"
  echo "请在 Termux App 里执行本脚本。"
  exit 1
fi
ok "Termux 环境确认"
echo "  架构: $(uname -m)"

say "1/6 安装系统包"
export DEBIAN_FRONTEND=noninteractive
pkg upgrade -y -o Dpkg::Options::=--force-confnew 2>&1 | tail -3 || true
pkg install -y python git wget curl unzip xz-utils 2>&1 | tail -5
ok "python / git / wget 已装"

# radare2：Termux 源里可能没有，装不上就从官方 release 取
say "2/6 radare2（影响 R2_* 94 个 + Nav_* 23 个工具）"
if pkg install -y radare2 2>&1 | tail -2; then
  if command -v r2 >/dev/null 2>&1; then
    ok "radare2 已装: $(r2 -v 2>/dev/null | head -1)"
  fi
fi
if ! command -v r2 >/dev/null 2>&1; then
  warn "Termux 源里没有 radare2，从官方 release 下载 android-aarch64 包"
  ARCH=$(uname -m)
  case "$ARCH" in
    aarch64) PKG=radare2-6.2.2-android-aarch64.tar.gz ;;
    armv7l|armv8l) PKG=radare2-6.2.2-android-arm.tar.gz ;;
    *) warn "未知架构 $ARCH，跳过 radare2"; PKG="" ;;
  esac
  if [ -n "$PKG" ]; then
    cd /tmp
    wget -q --show-progress -O r2.tar.gz \
      "https://github.com/radareorg/radare2/releases/download/6.2.2/$PKG" || \
      warn "下载失败，稍后可手动安装"
    if [ -f r2.tar.gz ]; then
      mkdir -p r2x && tar -xzf r2.tar.gz -C r2x --strip-components=1 2>/dev/null || true
      # 把可执行文件和库放进 Termux prefix
      find r2x -type f -name "r2" -o -type f -name "rabin2" -o -type f -name "radare2" \
        | head -3 | while read f; do cp "$f" "$PREFIX/bin/" 2>/dev/null && chmod 755 "$PREFIX/bin/$(basename $f)"; done
      find r2x -name "libr_*.so" -exec cp {} "$PREFIX/lib/" \; 2>/dev/null || true
      find r2x -name "libcapstone*.so" -o -name "libdemumble*.so" \
        -exec cp {} "$PREFIX/lib/" \; 2>/dev/null || true
      ldconfig 2>/dev/null || true
      if command -v r2 >/dev/null 2>&1; then ok "radare2 就绪"; else warn "radare2 未就绪，R2_* 工具会降级"; fi
    fi
  fi
fi

say "3/6 部署 R2B 源码"
mkdir -p "$R2B_DIR"
cd "$R2B_DIR"
# 如果当前目录下就是源码（比如从手机存储拷过来的），直接复制
if [ -f "$(dirname "$0")/../run_sse.py" ]; then
  cp -r "$(dirname "$0")/../." "$R2B_DIR/" 2>/dev/null || true
  ok "从本地目录复制源码"
else
  warn "未找到本地源码，尝试从 GitHub 拉取"
  if [ -d "$R2B_DIR/.git" ]; then
    git -C "$R2B_DIR" pull 2>&1 | tail -2 || true
  else
    git clone --depth 1 https://github.com/fok777/Djx.git "$R2B_DIR" 2>&1 | tail -3 || \
      warn "克隆失败，请手动把源码放到 $R2B_DIR"
  fi
fi
[ -f "$R2B_DIR/run_sse.py" ] && ok "源码就绪: $R2B_DIR" || warn "源码缺失，请手动放置"

say "4/6 安装 Python 依赖"
cd "$R2B_DIR"
python3 -m pip install --upgrade pip 2>&1 | tail -1 || true
# mitmproxy 在 Termux 上常编译失败，装不上不影响其它工具
python3 -m pip install pyelftools capstone 2>&1 | tail -3
ok "pyelftools / capstone 已装"

say "5/6 引擎资产"
mkdir -p "$ENGINE_DIR"/{blutter,frida,unidbg,radare2}
# 引擎 so/jar 体积大没进 git，优先从手机存储拷贝
for src in /sdcard/Download/r2b_engines /sdcard/r2b_engines "$HOME/r2b_engines"; do
  if [ -d "$src" ]; then
    cp -r "$src"/. "$ENGINE_DIR"/ 2>/dev/null && ok "已从 $src 复制引擎" && break
  fi
done
# frida-server（需 root 才用得上）
if command -v frida >/dev/null 2>&1; then
  ok "frida 已可用"
else
  python3 -m pip install frida-tools 2>&1 | tail -2 || warn "frida-tools 安装失败（需 root 才用得上）"
fi
echo "  引擎目录:"
for d in blutter frida unidbg radare2; do
  n=$(find "$ENGINE_DIR/$d" -type f 2>/dev/null | wc -l)
  printf '    %-10s %s 个文件\n' "$d" "$n"
done

say "6/6 自检"
cd "$R2B_DIR"
python3 -m r2b_mcp.audit 2>&1 | tail -15 || warn "自检未完全通过（不影响多数工具）"

cat <<EOF

$(printf '\033[1;32m')部署完成$(printf '\033[0m')

启动 MCP 服务：
  cd ~/r2b && python3 run_sse.py

然后 AI 客户端连接：
  http://$(ip route get 1.2.3.4 2>/dev/null | awk '{print $7; exit}' || echo 127.0.0.1):5051/mcp

常用：
  python3 -m r2b_mcp.categories   # 看 375 个工具的分类与引擎就绪状态
  python3 tools/fetch_engines.py status   # 看还缺哪些引擎
EOF
