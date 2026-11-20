#!/usr/bin/env bash
# Build and sign the Vault APK (Kotlin / Jetpack Compose). Ship at part ends only.
#
# The signing key is a secret: whoever holds it can ship an update that reads the vault.
#   keystore  ~/.android/vault.keystore          (outside the Syncthing workspace)
#   password  ~/.android/vault-keystore.pass     (0600) or VAULT_KEY_PASS in the environment
# The password is never hardcoded here and never passed on a command line (keytool and
# apksigner read it from the environment).
#
# NEVER uninstall the app to get past a signature mismatch: that deletes the vault.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

TEMURIN_HOME="${HOME}/jdk/temurin-21"
if [[ ! -x "${TEMURIN_HOME}/bin/javac" || ! -x "${TEMURIN_HOME}/bin/jlink" ]]; then
  echo "==> Downloading Eclipse Temurin 21"
  mkdir -p "${TEMURIN_HOME}"
  curl -fsSL -o /tmp/temurin21.tar.gz \
    "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk"
  tar -xzf /tmp/temurin21.tar.gz -C "${TEMURIN_HOME}" --strip-components=1
  rm -f /tmp/temurin21.tar.gz
fi
export JAVA_HOME="${TEMURIN_HOME}"
export PATH="${JAVA_HOME}/bin:${ANDROID_HOME}/platform-tools:${PATH}"

echo "sdk.dir=${ANDROID_HOME}" > "${ROOT}/local.properties"

KEYSTORE="${VAULT_KEYSTORE:-$HOME/.android/vault.keystore}"
KEY_ALIAS="${VAULT_KEY_ALIAS:-vault}"
PASS_FILE="${VAULT_KEY_PASS_FILE:-$HOME/.android/vault-keystore.pass}"
APK_SIGNED="${ROOT}/../vault.apk"
APK_ZIP="${HOME}/Downloads/vault.zip"

# Permissions the release APK may request. Anything else (INTERNET above all) fails the build.
# DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION is androidx.core's signature-level permission scoped to
# this package; it grants nothing outside the app. USE_BIOMETRIC (Part 3) lets the app show the
# system biometric prompt; it grants no data access.
ALLOWED_PERMISSIONS=(
  "com.nnikolovskii.vault.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
  "android.permission.USE_BIOMETRIC"
)

# Keystore and password must live outside the synced workspace.
WORKSPACE="$(cd "${ROOT}/../.." && pwd)"
for f in "${KEYSTORE}" "${PASS_FILE}"; do
  case "$(realpath -m "$f")" in
    "${WORKSPACE}"/*) echo "error: $f is inside the Syncthing workspace" >&2; exit 1 ;;
  esac
done

# --- signing password ------------------------------------------------------------------------
if [[ -z "${VAULT_KEY_PASS:-}" ]]; then
  if [[ ! -f "${PASS_FILE}" ]]; then
    echo "==> Creating ${PASS_FILE} (random, 0600)"
    mkdir -p "$(dirname "${PASS_FILE}")"
    (umask 077 && head -c 32 /dev/urandom | base64 | tr -d '\n/+=' > "${PASS_FILE}")
  fi
  mode="$(stat -c '%a' "${PASS_FILE}")"
  if [[ "${mode}" != "600" && "${mode}" != "400" ]]; then
    echo "error: ${PASS_FILE} must be mode 0600 (is ${mode})" >&2
    exit 1
  fi
  VAULT_KEY_PASS="$(tr -d '\r\n' < "${PASS_FILE}")"
fi
if [[ ${#VAULT_KEY_PASS} -lt 16 ]]; then
  echo "error: signing password is shorter than 16 characters" >&2
  exit 1
fi
export VAULT_KEY_PASS

# --- keystore --------------------------------------------------------------------------------
if [[ ! -f "${KEYSTORE}" ]]; then
  echo "==> Creating signing keystore at ${KEYSTORE}"
  (umask 077 && keytool -genkeypair \
    -keystore "${KEYSTORE}" \
    -storetype PKCS12 \
    -alias "${KEY_ALIAS}" \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -storepass:env VAULT_KEY_PASS \
    -keypass:env VAULT_KEY_PASS \
    -dname "CN=Vault, OU=personal, O=nnikolovskii, C=MK")
  echo "    Back this keystore up offline. Losing it means the next update cannot install."
fi
chmod 600 "${KEYSTORE}"

# --- build -----------------------------------------------------------------------------------
echo "==> Unit tests"
(cd "${ROOT}" && ./gradlew --no-daemon --max-workers=1 --console=plain test)
echo "==> Release APK"
(cd "${ROOT}" && ./gradlew --no-daemon --max-workers=1 --console=plain assembleRelease)

UNSIGNED="${ROOT}/app/build/outputs/apk/release/app-release-unsigned.apk"
[[ -f "${UNSIGNED}" ]] || { echo "error: unsigned APK missing" >&2; exit 1; }

BUILD_TOOLS_VER=""
if [[ -d "${ANDROID_HOME}/build-tools" ]]; then
  BUILD_TOOLS_VER="$(ls -1 "${ANDROID_HOME}/build-tools" | sort -V | tail -n 1)"
fi
BT="${ANDROID_HOME}/build-tools/${BUILD_TOOLS_VER}"
APKSIGNER="${BT}/apksigner"
AAPT2="${BT}/aapt2"
[[ -x "${APKSIGNER}" ]] || { echo "error: apksigner not found" >&2; exit 1; }
[[ -x "${AAPT2}" ]] || { echo "error: aapt2 not found" >&2; exit 1; }

# --- permission gate -------------------------------------------------------------------------
echo "==> Permission check"
PERMS="$("${AAPT2}" dump permissions "${UNSIGNED}" | sed -n "s/^uses-permission: name='\([^']*\)'.*/\1/p")"
bad=0
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  ok=0
  for allowed in "${ALLOWED_PERMISSIONS[@]}"; do [[ "$p" == "$allowed" ]] && ok=1; done
  if [[ $ok -eq 0 ]]; then
    echo "error: unexpected permission in APK: $p" >&2
    bad=1
  else
    echo "    ok: $p"
  fi
done <<< "${PERMS}"
if grep -q 'android.permission.INTERNET' <<< "${PERMS}"; then
  echo "error: APK requests INTERNET" >&2
  bad=1
fi
[[ $bad -eq 0 ]] || exit 1
echo "    no INTERNET, no unexpected permissions"

# --- sign ------------------------------------------------------------------------------------
echo "==> Signing"
"${APKSIGNER}" sign \
  --ks "${KEYSTORE}" \
  --ks-key-alias "${KEY_ALIAS}" \
  --ks-pass env:VAULT_KEY_PASS \
  --key-pass env:VAULT_KEY_PASS \
  --out "${APK_SIGNED}" \
  "${UNSIGNED}"
"${APKSIGNER}" verify --verbose "${APK_SIGNED}" | grep -E '^Verified using v[23]' || true
"${APKSIGNER}" verify "${APK_SIGNED}"
"${APKSIGNER}" verify --print-certs "${APK_SIGNED}" | grep -m1 'SHA-256 digest' | sed 's/^/    /'
rm -f "${APK_SIGNED}.idsig"

ZIP_PASS="${VAULT_ZIP_PASS:-change-me}"
mkdir -p "$(dirname "${APK_ZIP}")"
rm -f "${APK_ZIP}"
(cd "$(dirname "${APK_SIGNED}")" && zip -q -j -P "${ZIP_PASS}" "${APK_ZIP}" "$(basename "${APK_SIGNED}")")

# Drive upload is left to OptiBot.
echo "==> $(realpath "${APK_SIGNED}")"
echo "==> ${APK_ZIP}"
