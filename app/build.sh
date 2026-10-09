#!/usr/bin/env bash
# R2B App 一键编译（aapt2 + javac17(UTF-8) + d8(bt34) + zip + jarsigner V1）
set -e
cd "$(dirname "$0")"
# 允许环境变量覆盖（GitHub Actions 用），否则用本地默认路径
export AJ="${AJ:-/opt/android-sdk/platforms/android-35/android.jar}"
export AAPT="${AAPT:-/opt/android-sdk/build-tools/35.0.2/aapt2}"
export APKSIGN="${APKSIGN:-}"
# 优先 d8：完整 build-tools 的 d8 > /tmp/bt34 的 d8
D8=""
if [ -z "$D8" ]; then
  for c in /opt/android-sdk/build-tools/*/d8 /tmp/bt34/android-14/d8; do
    [ -x "$c" ] && D8="$c" && break
  done
fi
export D8
[ -z "$D8" ] && { echo "缺 d8，设 D8=/path/d8"; exit 3; }
JC=$(ls /usr/lib/jvm/java-17*/bin/javac 2>/dev/null | head -1 || which javac)
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
echo "[4/5] 打包 classes.dex + assets"; python3 -c "
import zipfile,os
z=zipfile.ZipFile('build/base.apk'); zo=zipfile.ZipFile('build/r2b.apk','w',zipfile.ZIP_DEFLATED)
for i in z.infolist(): zo.writestr(i,z.read(i.filename))
zo.write('build/classes.dex','classes.dex')
if os.path.exists('assets/tools_data.json'): zo.write('assets/tools_data.json','assets/tools_data.json')
z.close(); zo.close()
print('assets:', 'assets/tools_data.json' in zipfile.ZipFile('build/r2b.apk').namelist())
"
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
