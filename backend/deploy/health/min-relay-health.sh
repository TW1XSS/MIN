#!/bin/bash
# MIN relay health check (бета-страховка от «повис»/«умер молча»).
# Ставится как /usr/local/bin/min-relay-health.sh, дёргается timer'ом
# min-relay-health.timer (операционный таймер).
#
# Проверка: TCP-connect на frame-порт с повторами. Не рестартуем, если юнит
# в activating (идёт старт) — иначе сломаем поднимающийся процесс.
set -u

PORT="${1:-3001}"
HOST="${2:-127.0.0.1}"
UNIT="min-relay"
TRIES=3

state="$(systemctl show -p ActiveState --value "$UNIT" 2>/dev/null || echo unknown)"
if [ "$state" = "activating" ] || [ "$state" = "reloading" ]; then
  exit 0
fi

ok=0
for _ in $(seq 1 "$TRIES"); do
  if timeout 5 bash -c "exec 3<>/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
    ok=1
    break
  fi
  sleep 2
done

if [ "$ok" = "1" ]; then
  exit 0
fi

logger -t min-relay-health "FAIL: ${HOST}:${PORT} недоступен ${TRIES}x — перезапуск ${UNIT}"
systemctl restart "$UNIT" || true
sleep 3

# Код возврата = результат восстановления, а не сам факт сбоя: иначе oneshot
# всегда висит в `systemctl --failed` даже после успешного ремонта.
if [ "$(systemctl is-active "$UNIT" 2>/dev/null)" = "active" ]; then
  logger -t min-relay-health "OK: ${UNIT} поднят после перезапуска"
  exit 0
fi

logger -t min-relay-health "CRIT: ${UNIT} не поднялся после перезапуска"
exit 1
