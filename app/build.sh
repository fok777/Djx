#!/usr/bin/env bash
# R2B App 一键编译（aapt2 + javac17(UTF-8) + d8(bt34) + zip + jarsigner V1）
set -e
cd "$(dirname "$0")"
# 允许环境变量覆盖（GitHub Actions 用），否则用本地默认路径
export AJ="${AJ:-/opt/android-sdk/platforms/android-35/android.jar}"
export AAPT="${AAPT:-/opt/android-sdk/build-tools/35.0.2/aapt2}"
export APKSIGN="${APKSIGN:-}"
# 优先 d8：环境变量 D8 > $ANDROID_HOME 下的 build-tools > /tmp/bt34 的 d8
# 注意：不能写成 D8=""，那会把外部传入的值清掉。
export D8="${D8:-}"
if [ -z "$D8" ]; then
  for c in "${ANDROID_HOME:-/opt/android-sdk}"/build-tools/*/d8 \
           /opt/android-sdk/build-tools/*/d8 /tmp/bt34/android-14/d8; do
    [ -x "$c" ] && D8="$c" && break
  done
fi
[ -z "$D8" ] && { echo "缺 d8，设 D8=/path/d8"; exit 3; }
# javac：环境变量 JC > JAVA_HOME > PATH。
# 原写法 `ls /usr/lib/jvm/java-17*/bin/javac | head -1 || which javac` 在
# CI 上会拿到空值（|| 只兜住 head，head 永远成功），导致 ": command not found"。
export JC="${JC:-}"
if [ -z "$JC" ]; then
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    JC="$JAVA_HOME/bin/javac"
  else
    JC=$(command -v javac 2>/dev/null || true)
  fi
fi
[ -z "$JC" ] && { echo "缺 javac，设 JC=/path/to/javac 或正确设置 JAVA_HOME"; exit 3; }
echo "javac = $JC"
SP=r2bsecret
rm -rf build; mkdir -p build/classes
echo "[1/5] aapt2 compile + link（含 mipmap 图标）"
if [ -d res ]; then
  "$AAPT" compile --dir res -o build/res.zip
  "$AAPT" link --manifest AndroidManifest.xml -I "$AJ" \
    --min-sdk-version 24 --target-sdk-version 35 -o build/base.apk \
    --java build/java build/res.zip
else
  "$AAPT" link --manifest AndroidManifest.xml -I "$AJ" \
    --min-sdk-version 24 --target-sdk-version 35 -o build/base.apk --java build/java
fi
echo "[2/5] javac17 (UTF-8)"; "$JC" -source 1.8 -target 1.8 -encoding UTF-8 \
  -bootclasspath "$AJ" -cp "$AJ" -d build/classes \
  build/java/com/r2b/app/*.java src/com/r2b/app/*.java
echo "[3/5] d8 dex"; "$D8" --release --lib "$AJ" --min-api 24 --output build build/classes/com/r2b/app/*.class
echo "[4/5] 打包 classes.dex + assets + 引擎资产"
ENGINE_SRC="$(cd .. && pwd)/assets/engine"
python3 - "$ENGINE_SRC" <<'PYCODE'
import zipfile, os, sys
engine_src = sys.argv[1]
z = zipfile.ZipFile('build/base.apk')
zo = zipfile.ZipFile('build/r2b.apk', 'w', zipfile.ZIP_DEFLATED)
for i in z.infolist():
    zo.writestr(i, z.read(i.filename))
zo.write('build/classes.dex', 'classes.dex')

# 工具表
if os.path.exists('assets/tools_data.json'):
    zo.write('assets/tools_data.json', 'assets/tools_data.json')

# 引擎资产 -> assets/engine/<引擎>/<文件>
# 用 assets 而非 lib/：这些是"由代码显式加载"的可执行/库，
# 放 lib/ 会被系统当 JNI 库处理，且 <5MB 的会被压缩导致无法直接 exec。
n_so = n_all = 0
for eng in sorted(os.listdir(engine_src)):
    d = os.path.join(engine_src, eng)
    if not os.path.isdir(d):
        continue
    for root, _, files in os.walk(d):
        for fn in files:
            if fn.startswith('.'):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, engine_src).replace(os.sep, '/')
            # 引擎二进制用 STORED（不压缩）：释放时无需解压，190MB 明显更快
            zi = zipfile.ZipInfo('assets/engine/' + rel, date_time=(2024, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_STORED
            zi.external_attr = 0o644 << 16
            with open(full, 'rb') as fh:
                zo.writestr(zi, fh.read())
            n_all += 1
            if fn.endswith('.so'):
                n_so += 1
z.close(); zo.close()
print(f'引擎资产: {n_all} 个文件（其中 .so {n_so} 个）')
print('tools_data:', 'assets/tools_data.json' in zipfile.ZipFile('build/r2b.apk').namelist())
PYCODE
echo "--- APK 体积 ---"; ls -lh build/r2b.apk | awk '{print $5, $9}'
python3 - <<'PYCODE'
import zipfile, collections
z = zipfile.ZipFile('build/r2b.apk')
names = z.namelist()
c = collections.Counter()
for n in names:
    if n.startswith('assets/engine/'):
        p = n.split('/')
        if len(p) >= 4:
            c[p[2]] += 1
print('::notice::apk-entries=%d' % len(names))
for k, v in sorted(c.items()):
    print('::notice::apk-engine-%s=%d' % (k, v))
print('::notice::apk-so-total=%d' % sum(1 for n in names if n.endswith('.so')))
raw = sum(i.file_size for i in z.infolist())
comp = sum(i.compress_size for i in z.infolist())
print('::notice::apk-raw=%.1fMB compressed=%.1fMB' % (raw/1048576, comp/1048576))
PYCODE

echo "[5/5] 签名 V1"; [ -f keystore.jks ] || keytool -genkeypair -keystore keystore.jks -alias r2b \
  -keyalg RSA -keysize 2048 -validity 3650 -storepass $SP -keypass $SP -dname "CN=R2B,O=R2B,C=US" 2>/dev/null
jarsigner -keystore keystore.jks -storepass $SP build/r2b.apk r2b
[ -z "$APKSIGN" ] && APKSIGN=$(ls /tmp/bt34/android-14/apksigner /opt/android-sdk/build-tools/*/apksigner 2>/dev/null | head -1)
cp build/r2b.apk R2B.app.apk
if [ -n "$APKSIGN" ]; then
  "$APKSIGN" sign --ks keystore.jks --ks-pass pass:$SP \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
    --out build/r2b.v23.apk build/r2b.apk 2>&1 | head -2
  cp build/r2b.v23.apk R2B.app.apk
  echo "✅ V1+V2/V3 签名"
fi
("$APKSIGN" verify --print-certs R2B.app.apk 2>&1 | head -3) || jarsigner -verify R2B.app.apk 2>&1 | head -1
ls -lh R2B.app.apk
