#!/usr/bin/env bash
# Локальная сборка iOS-клиента с адресом relay, НЕ сохраняя его в Git.
#
# Почему так: дефолтный relay лежит в MIN/Info.plist, чтобы обычная сборка
# работала «из коробки», но production-узел не должен быть привязан к
# публичному репозиторию (MIN-RED-015). Этот скрипт подставляет адрес в
# .app через INFOPLIST_KEY_MinRelayAddress и ничего не меняет в Git.
# scripts/export-public.sh заменяет дефолтный адрес плейсхолдером.
#
# Использование:
#   MIN_RELAY_ADDR='<relay>.onion:3001' scripts/build-local.sh
#   scripts/build-local.sh --udid <UDID>           # установить на устройство
#
# Файл адреса (в .gitignore, поэтому в публичный экспорт не попадает):
#   cp scripts/local-relay.env.example scripts/local-relay.env
#   # затем в scripts/local-relay.env строка  MIN_RELAY_ADDR=<relay>.onion:3001
# Либо передавайте адрес переменной окружения - тогда файл не нужен вовсе.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/scripts/local-relay.env"
DESTINATION="platform=iOS Simulator,name=iPhone 17"
INSTALL_UDID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --udid) INSTALL_UDID="${2:-}"; shift 2 ;;
    # Печатаем шапку до первой непустой некомментарной строки: жёсткий
    # диапазон sed протухал, когда в шапку добавили строку про пример файла.
    -h|--help) awk 'NR>1 && !/^#/ {exit} NR>1 {sub(/^# ?/,""); print}' "$0"; exit 0 ;;
    *) echo "build-local: неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

# 1. Адрес: переменная окружения приоритетнее файла.
ADDR="${MIN_RELAY_ADDR:-}"
if [ -z "$ADDR" ] && [ -f "$ENV_FILE" ]; then
  ADDR="$(sed -nE 's/^[[:space:]]*MIN_RELAY_ADDR[[:space:]]*=[[:space:]]*"?([^"]+)"?/\1/p' "$ENV_FILE" | head -1)"
fi
if [ -z "$ADDR" ]; then
  cat >&2 <<'EOF'
build-local: не задан адрес relay.

Скопируйте пример и подставьте свой адрес:
    cp scripts/local-relay.env.example scripts/local-relay.env
или передайте адрес переменной окружения:
    MIN_RELAY_ADDR='<relay>.onion:3001' scripts/build-local.sh

Без адреса приложение падает fail-closed с явной ошибкой — это намеренно.
EOF
  exit 2
fi
case "$ADDR" in
  *:*) : ;;
  *) echo "build-local: ожидается адрес host:port, получено '$ADDR'" >&2; exit 2 ;;
esac

cd "$ROOT"

echo "[1/2] сборка (адрес подставляется в Info.plist, в Git не попадает)"
xcodebuild \
  -workspace MIN.xcworkspace \
  -scheme MIN \
  -configuration Debug \
  -destination "$DESTINATION" \
  -derivedDataPath DerivedData \
  INFOPLIST_KEY_MinRelayAddress="$ADDR" \
  build

if [ -z "$INSTALL_UDID" ]; then
  echo "[2/2] сборка готова; установка пропущена (передай --udid <UDID>)"
  exit 0
fi

APP="$(find "$ROOT/DerivedData/Build/Products" -maxdepth 2 -name 'MIN.app' -print -quit)"
[ -n "$APP" ] || { echo "build-local: не найден MIN.app" >&2; exit 1; }
echo "[2/2] установка на $INSTALL_UDID"
xcrun simctl boot "$INSTALL_UDID" 2>/dev/null || true
xcrun simctl install "$INSTALL_UDID" "$APP"
xcrun simctl launch "$INSTALL_UDID" com.Pilgrim.MIN || true
echo "OK: приложение собрано и запущено"