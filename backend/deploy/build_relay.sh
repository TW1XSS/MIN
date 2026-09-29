#!/usr/bin/env bash
# Кросс-сборка min-relay под Raspberry Pi 2 B v1.1 (ARMv7) с macOS.
# Ставит на целевой хост один статический бинарь (musl) — БЕЗ зависимостей,
# поэтому один и тот же артефакт идёт на Pi, VPS и любую другую площадку.
#
# Использование:
#   backend/deploy/build_relay.sh                       # только собрать
#   backend/deploy/build_relay.sh --deploy 192.0.2.10     # собрать и залить
#   backend/deploy/build_relay.sh --deploy ops@1.2.3.4  # явный юзер
#
# Переменные:
#   MIN_SSH_KEY      приватный ключ (по умолчанию ~/.ssh/id_ed25519_pi)
#   MIN_SSH_USER     юзер по умолчанию при --deploy (root-only; не ops)
#   MIN_CROSS_PREFIX каталог bin кросс-тулчейна
set -euo pipefail

TARGET="armv7-unknown-linux-musleabihf"
BIN_NAME="min-relay"
PKG="min-relay"

BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BACKEND_DIR"

MIN_SSH_KEY="${MIN_SSH_KEY:-$HOME/.ssh/id_ed25519_pi}"
MIN_SSH_USER="${MIN_SSH_USER:-root}"
DEPLOY_TO=""

while [ $# -gt 0 ]; do
  case "$1" in
    --deploy)
      [ $# -ge 2 ] || { echo "build_relay.sh: --deploy требует [user@]host" >&2; exit 2; }
      DEPLOY_TO="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "build_relay.sh: неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

# --- 1. Кросс-тулчейн ---------------------------------------------------------
PREFIX="${MIN_CROSS_PREFIX:-/opt/homebrew/opt/${TARGET}/bin}"
CC_BIN="${PREFIX}/${TARGET}-gcc"
if [ ! -x "$CC_BIN" ]; then
  cat >&2 <<EOF
build_relay.sh: нет кросс-компилятора $CC_BIN

Установи тулчейн (готовый бинарник, macOS arm64/x86_64):
  brew tap messense/macos-cross-toolchains
  brew install messense/macos-cross-toolchains/${TARGET}

(альтернатива без brew: сборка нативно на Pi — tools, но 40-60 мин)
EOF
  exit 1
fi

echo "[1/4] target: $TARGET  (cc: $($CC_BIN -dumpversion))"
rustup target add "$TARGET" >/dev/null 2>&1 || true

# --- 2. Сборка ---------------------------------------------------------------
echo "[2/4] release-сборка $PKG (LTO, статический musl)"
CC="${TARGET}-gcc" \
CXX="${TARGET}-g++" \
AR="${TARGET}-ar" \
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="$CC_BIN" \
  cargo build --release -p "$PKG" --target "$TARGET"

ARTIFACT="target/${TARGET}/release/${BIN_NAME}"
[ -f "$ARTIFACT" ] || { echo "build_relay.sh: артефакт не найден: $ARTIFACT" >&2; exit 1; }

# --- 3. Проверка артефакта ---------------------------------------------------
FILE_OUT="$(file -b "$ARTIFACT")"
echo "[3/4] $FILE_OUT"
case "$FILE_OUT" in
  *ARM*) : ;;
  *) echo "build_relay.sh: артефакт НЕ ARM — сборка не для Pi" >&2; exit 1 ;;
esac
case "$FILE_OUT" in
  *"statically linked"*) : ;;
  *) echo "build_relay.sh: артефакт НЕ статический — на Pi будут сюрпризы" >&2; exit 1 ;;
esac

SIZE="$(du -h "$ARTIFACT" | cut -f1)"
SHA="$(shasum -a 256 "$ARTIFACT" | cut -d' ' -f1)"
echo "      размер: $SIZE"
echo "      sha256: $SHA"

# --- 4. Доставка (опционально) ----------------------------------------------
if [ -z "$DEPLOY_TO" ]; then
  echo "[4/4] доставка пропущена (нет --deploy)"
  exit 0
fi

case "$DEPLOY_TO" in
  *@*) HOST="$DEPLOY_TO" ;;
  *)   HOST="${MIN_SSH_USER}@${DEPLOY_TO}" ;;
esac

if [ ! -f "$MIN_SSH_KEY" ]; then
  echo "build_relay.sh: нет ключа $MIN_SSH_KEY (ssh-keygen -t ed25519 -C '' -f $MIN_SSH_KEY)" >&2
  exit 1
fi

SSH=(ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$MIN_SSH_KEY")

# sudo нужен только если ходим НЕ под root (DietPi без sudo-пакета — норма).
RUSER="${HOST%@*}"
if [ "$RUSER" = "$HOST" ]; then RUSER="$MIN_SSH_USER"; fi
if [ "$RUSER" = "root" ]; then SUDO=""; else SUDO="sudo "; fi

echo "[4/4] доставка на $HOST"
# Через ssh+stdin, а не scp: на узле может стоять Dropbear (нет sftp-server,
# современный scp не работает). Так работает везде.
"${SSH[@]}" "$HOST" "cat > /tmp/${BIN_NAME}.new" < "$ARTIFACT"
"${SSH[@]}" "$HOST" "${SUDO}install -m 0755 -o root -g root /tmp/${BIN_NAME}.new /usr/local/bin/${BIN_NAME} && rm -f /tmp/${BIN_NAME}.new"

REMOTE_SHA="$("${SSH[@]}" "$HOST" "${SUDO}sha256sum /usr/local/bin/${BIN_NAME} | cut -d' ' -f1")"
if [ "$REMOTE_SHA" != "$SHA" ]; then
  echo "build_relay.sh: sha256 не совпал (локально $SHA, на хосте $REMOTE_SHA)" >&2
  exit 1
fi

# Рестарт — если юнит уже установлен (первый деплой идёт до bootstrap_node.sh).
"${SSH[@]}" "$HOST" "/usr/local/bin/${BIN_NAME} --version"
if "${SSH[@]}" "$HOST" "systemctl cat ${BIN_NAME}.service >/dev/null 2>&1"; then
  "${SSH[@]}" "$HOST" "${SUDO}systemctl restart ${BIN_NAME} && sleep 2 && systemctl is-active ${BIN_NAME}"
  echo "OK: $BIN_NAME доставлен и перезапущен на $HOST"
else
  echo "OK: $BIN_NAME доставлен на $HOST (юнита ещё нет — запусти bootstrap_node.sh)"
fi