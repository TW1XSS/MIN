#!/bin/bash
# Ротация логов реле (logrotate на DietPi нет — делаем сами).
# copytruncate: systemd держит fd в O_APPEND, переоткрывать не нужно.
# Лимит: (1 + KEEP) × MAX байт на диске максимум.
# Дёргается min-relay-logrotate.timer (раз в сутки + размер-чек).
set -u

DIR="/var/log/min-relay"
LOG="$DIR/relay.log"
MAX_BYTES=$((10 * 1024 * 1024))   # 10 MB
KEEP=3                            # храним .1 .2 .3

[ -f "$LOG" ] || exit 0

size="$(stat -c%s "$LOG" 2>/dev/null || echo 0)"
if [ "$size" -le "$MAX_BYTES" ]; then
  exit 0
fi

i=$((KEEP - 1))
while [ "$i" -ge 1 ]; do
  if [ -f "$LOG.$i" ]; then
    mv "$LOG.$i" "$LOG.$((i + 1))"
  fi
  i=$((i - 1))
done
cp "$LOG" "$LOG.1" || exit 1
truncate -s 0 "$LOG"

logger -t min-relay-logrotate "ротация: было $size байт → $LOG.1"
exit 0
