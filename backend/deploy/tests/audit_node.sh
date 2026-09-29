#!/usr/bin/env bash
# Read-only аудит узла MIN relay.
# НИЧЕГО не меняет: только факты и PASS/FAIL/WARN. Запускать под root.
#
#   bash audit_node.sh            # весь чек-лист
#   bash audit_node.sh -v         # + сырой вывод интересных команд
set -u

VERBOSE="${1:-}"
PASS=0; FAIL=0; WARN=0

sec()   { printf '\n== %s ==\n' "$1"; }
ok()    { printf '  PASS: %s\n' "$1"; PASS=$((PASS+1)); }
bad()   { printf '  FAIL: %s\n' "$1"; FAIL=$((FAIL+1)); }
wrn()   { printf '  WARN: %s\n' "$1"; WARN=$((WARN+1)); }
info()  { printf '  INFO: %s\n' "$1"; }
raw()   { [ "$VERBOSE" = "-v" ] && { printf '  ---\n'; "$@" 2>/dev/null | sed 's/^/  /'; printf '  ---\n'; }; return 0; }

[ "$(id -u)" = 0 ] || { echo "запускать под root (sudo bash audit_node.sh)"; exit 2; }

sec "1. Слушающие порты (наружу — только :22)"
bad_ext=0
while read -r line; do
  case "$line" in
    *127.0.0.1*|*"[::1]"*|*"[::]:22"*|*"0.0.0.0:22"*) : ;;
    *LISTEN*) echo "  наружу: $line"; bad_ext=$((bad_ext+1)) ;;
  esac
done < <(ss -tuln)
if [ "$bad_ext" = 0 ]; then ok "наружу слушает только SSH (:22), остальное — loopback"
else bad "наружу слушает что-то кроме SSH ($bad_ext шт.) — разобрать!"; fi
ss -tlnp 2>/dev/null | grep -q '127.0.0.1:3001' \
  && ok "frame API на 127.0.0.1:3001" || bad "нет слушателя 127.0.0.1:3001"
ss -tlnp 2>/dev/null | grep -q '127.0.0.1:3000' \
  && bad "слушает 3000 (mock REST) — в проде быть не должно" || ok "порт 3000 закрыт"

sec "2. Файрвол (ufw)"
ufw status 2>/dev/null | grep -q 'Status: active' \
  && ok "ufw active" || bad "ufw не активен"
ufw status verbose 2>/dev/null | grep -q 'deny (incoming)' \
  && ok "default deny incoming" || bad "incoming не deny"
raw ufw status verbose

sec "3. SSH"
grep -q '\-s' /etc/default/dropbear 2>/dev/null \
  && ok "Dropbear: пароли выключены (-s)" || wrn "нет -s в /etc/default/dropbear"
# root-only модель: root по ключу, лишних юзеров с shell быть не должно.
f=/root/.ssh/authorized_keys
if [ -f "$f" ]; then
  n=$(grep -c '^ssh-' "$f")
  # ключи хранятся без комментариев (анонимность) — показываем префикс, не тело
  info "root: ключей $n; префиксы: $(awk '$1=="ssh-ed25519"{print substr($2,1,10)"…"}' "$f" | tr '\n' ' ')"
else wrn "root: нет /root/.ssh/authorized_keys"; fi
extra_shells=$(awk -F: '$7 ~ /bash|sh|zsh/ && $1 !~ /^(root|debian-tor)$/{print $1}' /etc/passwd)
[ -z "$extra_shells" ] && ok "root-only: лишних shell-юзеров нет" \
  || bad "лишние shell-юзеры: $extra_shells"
attempts=$(journalctl -u dropbear --since -24h --no-pager 2>/dev/null | grep -ciE 'bad password|login attempt|failed' || true)
[ "${attempts:-0}" -gt 0 ] && info "SSH-попытки входа за 24 ч: $attempts (journal dropbear)" \
  || info "SSH-попыток отказов за 24 ч: 0"
raw grep -v '^#' /etc/default/dropbear

sec "4. Сервисы"
for s in min-relay tor dropbear; do
  a=$(systemctl is-active "$s" 2>/dev/null); e=$(systemctl is-enabled "$s" 2>/dev/null)
  [ "$a" = active ] && [ "$e" = enabled ] && ok "$s: active/enabled" || bad "$s: $a/$e"
done
systemctl is-active min-relay-health.timer >/dev/null 2>&1 \
  && ok "health-таймер активен" || bad "health-таймер не активен"
systemctl is-active min-relay-logrotate.timer >/dev/null 2>&1 \
  && ok "logrotate-таймер активен" || wrn "logrotate-таймер не активен"
systemctl is-active systemd-timesyncd >/dev/null 2>&1 \
  && ok "timesyncd активен (TTL!)" || bad "timesyncd не активен — TTL после ребута неверный"
grep -q '\-\-no-http' /etc/systemd/system/min-relay.service \
  && ok "юнит: --no-http (mock REST не поднимается)" || wrn "в юните нет --no-http"

sec "5. Ключи onion (права БЕЗ содержимого!)"
ONION_DIR=/var/lib/tor/min_relay
if [ -d "$ONION_DIR" ]; then
  m=$(stat -c %a "$ONION_DIR"); o=$(stat -c %U "$ONION_DIR")
  # 700/2700 норма: 2700 = setgid+700, так создаёт debian-tor (группа наследуется).
  case "$m" in 700|2700) ok "HS-каталог: $m (закрыт от всех, кроме владельца)" ;;
    *) bad "HS-каталог: права $m (нужно 700 или 2700)" ;; esac
  [ "$o" = debian-tor ] && ok "владелец: debian-tor" || wrn "владелец: $o"
  [ -s "$ONION_DIR/hostname" ] && ok "hostname есть" || bad "hostname отсутствует"
  info "публичный адрес: $(cat "$ONION_DIR/hostname")"
else bad "$ONION_DIR не найден"; fi

sec "6. Tor"
last=$(grep -iE 'bootstrapp' "$ONION_DIR/log/notices.log" 2>/dev/null | tail -1)
if [ -n "$last" ]; then
  echo "$last" | grep -q 'Done' && ok "Tor bootstrap: Done" \
    || wrn "Tor не в Done: $(echo "$last" | cut -c1-100) (см. §«Если сеть режет Tor»)"
else wrn "нет notices.log — Tor не писал"; fi

sec "7. Логи (метаданные)"
LOG=/var/log/min-relay/relay.log
if [ -f "$LOG" ]; then
  ok "op-лог есть ($(stat -c%s "$LOG") байт)"
  leaks=$(grep -cE 'pull_token=|envelope_hex=|envelope=' "$LOG" || true)
  [ "${leaks:-0}" = 0 ] && ok "в логе нет значений токенов/envelope" \
    || bad "в логе $leaks строк со значениями токенов/envelope!"
  long=$(awk 'length($0)>2000' "$LOG" | wc -l)
  [ "${long:-0}" = 0 ] && ok "нет гигантских строк (payload не пишется)" \
    || wrn "строк >2000 симв.: $long — проверить"
else wrn "op-лога нет: $LOG"; fi

sec "8. Часы (TTL!)"
systemctl is-active systemd-timesyncd >/dev/null 2>&1 \
  && ok "timesyncd активен" || wrn "timesyncd не активен — TTL после ребута рискован"
info "UTC сейчас: $(date -u '+%F %T')"

sec "9. Ресурсы"
free_mb=$(free -m | awk '/^Mem:/{print $7}')
[ "$free_mb" -gt 200 ] && ok "доступно RAM: ${free_mb}M" || wrn "мало RAM: ${free_mb}M"
disk_pct=$(df -P / | awk 'NR==2{print int($5)}')
[ "$disk_pct" -lt 80 ] && ok "диск: занято ${disk_pct}%" || wrn "диск: занято ${disk_pct}%"
swapon --show 2>/dev/null | grep -q . && info "swap: $(swapon --show --noheadings | awk '{print $1, $3}')" \
  || info "swap выключен"

sec "10. Бинарь и обновления"
[ -x /usr/local/bin/min-relay ] && ok "бинарь на месте: $(/usr/local/bin/min-relay --version 2>/dev/null)" \
  || bad "нет /usr/local/bin/min-relay"
info "sha256: $(sha256sum /usr/local/bin/min-relay 2>/dev/null | cut -c1-16) (сверить с артефактом сборки)"
up=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
[ "${up:-0}" = 0 ] && ok "обновлений нет" || wrn "доступно обновлений: $up (apt list --upgradable)"

sec "ИТОГ"
echo "  PASS=$PASS  WARN=$WARN  FAIL=$FAIL"
[ "$FAIL" = 0 ] && echo "  аудит: критических провалов нет" || echo "  аудит: ЕСТЬ FAIL — разобрать до продолжения беты"
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
