#!/usr/bin/env bash
# MIN relay — подготовка узла (запускается НА узле под root).
#
# Универсальный Debian-базис: сегодня это DietPi на Raspberry Pi 2 B v1.1,
# завтра — Debian/Ubuntu VPS, послезавтра — что угодно ещё. Всё, что зависит
# от DietPi, спрятано за проверками наличия файлов.
#
# Идемпотентен: повторный запуск ничего не ломает и не дублирует.
# ВСЕ изменения конфигов — с бэкапом *.min-backup и обратимы вручную.
#
# Что НЕ делает: не трогает роутер, не открывает порты наружу, не меняет
# сетевые настройки. Реле живёт только на loopback + Tor onion.
#
# Использование (на узле):
#   bash bootstrap_node.sh --log-mode beta            # бета: подробные логи на диск
#   bash bootstrap_node.sh --harden-ssh               # + выключить пароли SSH
#   bash bootstrap_node.sh --harden-root              # + выключить root-логин
#   bash bootstrap_node.sh --restore-tor-keys DIR     # вернуть прежний .onion
#
# Опции:
#   --log-mode beta|final   beta: journald на диск + debug-логи реле (default beta)
#   --swap-mb N             размер swap в MB (default 256; 0 = выключить swap)
#   --admin-user NAME       опциональный админ-юзер (default: none = root-only)
#   --frame-port N          порт frame API на loopback (default 3001)
#   --onion-name NAME       имя hidden service (default min_relay)
#   --harden-ssh            выключить парольную аутентификацию SSH
#   --harden-root           выключить root-логин (НЕ совмещать с root-only моделью!)
#   --restore-tor-keys DIR  восстановить ключи onion из каталога DIR
#   --no-firewall           не настраивать ufw
#   --no-tor                не настраивать Tor hidden service
#   --dry-run               только показать, что было бы сделано
set -euo pipefail

LOG_MODE="beta"
SWAP_MB="256"
ADMIN_USER=""
FRAME_PORT="3001"
ONION_NAME="min_relay"
HARDEN_SSH=0
HARDEN_ROOT=0
RESTORE_KEYS=""
DO_FIREWALL=1
DO_TOR=1
DRY_RUN=0
REPO_SRC_DIR=""   # каталог с unit/health/torrc (если переданы рядом со скриптом)

while [ $# -gt 0 ]; do
  case "$1" in
    --log-mode) LOG_MODE="$2"; shift 2 ;;
    --swap-mb) SWAP_MB="$2"; shift 2 ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --frame-port) FRAME_PORT="$2"; shift 2 ;;
    --onion-name) ONION_NAME="$2"; shift 2 ;;
    --harden-ssh) HARDEN_SSH=1; shift ;;
    --harden-root) HARDEN_ROOT=1; shift ;;
    --restore-tor-keys) RESTORE_KEYS="$2"; shift 2 ;;
    --no-firewall) DO_FIREWALL=0; shift ;;
    --no-tor) DO_TOR=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bootstrap_node.sh: неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done

case "$LOG_MODE" in beta|final) : ;; *) echo "--log-mode: beta|final" >&2; exit 2 ;; esac

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
say()  { echo "[min-bootstrap] $*"; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "  DRY: $*"; else "$@"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = "0" ] || { echo "bootstrap_node.sh: запускать под root" >&2; exit 1; }

say "узел: $(uname -m) / $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
say "режим логов: $LOG_MODE | frame-порт: 127.0.0.1:$FRAME_PORT | onion: $ONION_NAME"

# --- 0. Пакеты ---------------------------------------------------------------
# Минимум зависимостей: реле — статический musl-бинарь, ему ничего не нужно.
say "шаг 0: пакеты (ufw, tor, ca-certificates, tzdata)"
if [ "$DRY_RUN" = 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ufw ca-certificates tzdata >/dev/null
  [ "$DO_TOR" = 1 ] && apt-get install -y -qq tor >/dev/null
fi

skip() { [ "$DRY_RUN" = 1 ]; }

# Убрать legacy-юзеров (DietPi-дефолт и прежняя админ-роль): узел root-only.
# Идемпотентно: id вернёт ошибку, если юзера нет.
for u in ops dietpi; do
  if id "$u" >/dev/null 2>&1; then
    say "  удаляю legacy-юзера $u (узел root-only, ключи onion debian-tor не трогаем)"
    skip || userdel -r "$u" >/dev/null 2>&1 || true
  fi
done

# --- 1. Админ-ключ (root-only модель) ----------------------------------------
# Доступ: только root по ключу. Пароли выключены (--harden-ssh/-s).
# ssh <host> — из LAN; удалённый доступ через отдельный WG/onion-маршрут.
say "шаг 1: админ-доступ (root-only)"
skip || install -d -m 0700 -o root -g root /root/.ssh
if [ ! -s /root/.ssh/authorized_keys ]; then
  echo "  ВНИМАНИЕ: /root/.ssh/authorized_keys пуст — сначала ssh-copy-id!" >&2
else
  say "  ключей в /root/.ssh/authorized_keys: $(grep -c '^ssh-' /root/.ssh/authorized_keys)"
fi

# --- 1b. Гигиена/анонимность узла -------------------------------------------
# Ничего личного в hostname/timezone/телеметрии: узел не должен «звучать»
# как частная домашняя машина, а не идентифицируемый узел.
say "шаг 1b: гигиена (UTC, телеметрия off, SSH-сервер не удалить)"
if [ -f /boot/dietpi.txt ]; then
  skip || cp -n /boot/dietpi.txt /boot/dietpi.txt.min-backup
  skip || sed -i \
    -e 's|^AUTO_SETUP_TIMEZONE=.*|AUTO_SETUP_TIMEZONE=UTC|' \
    -e 's|^SURVEY_OPTED_IN=.*|SURVEY_OPTED_IN=0|' \
    -e 's|^AUTO_SETUP_SSH_SERVER_INDEX=.*|AUTO_SETUP_SSH_SERVER_INDEX=1|' \
    /boot/dietpi.txt
  say "  dietpi.txt: TZ=UTC, survey=off, SSH=Dropbear (чтобы будущий dietpi-software не снёс доступ)"
fi
# Часы: у Pi нет RTC → без NTP TTL после долгого выключения неверный (RT-11).
# DietPi-грабли (обе проверены на живом узле):
# 1) CONFIG_NTP_MODE=2 (дефолт DietPi) = oneshot: DietPi сам ОСТАНАВЛИВАЕТ
#    timesyncd после загрузки — нужен режим 4 (демон);
# 2) секция конфига — [Time], не [NTP] (иначе timesyncd молча игнорирует).
if [ "$DRY_RUN" = 0 ] && [ -f /boot/dietpi.txt ]; then
  cp -n /boot/dietpi.txt /boot/dietpi.txt.min-backup 2>/dev/null || true
  sed -i 's/^CONFIG_NTP_MODE=.*/CONFIG_NTP_MODE=4/' /boot/dietpi.txt
fi
skip || install -d -m 0755 /etc/systemd
if [ "$DRY_RUN" = 0 ]; then
  printf '[Time]\nNTP=debian.pool.ntp.org\nFallbackNTP=time.cloudflare.com time.google.com\n\n' \
    > /etc/systemd/timesyncd.conf
fi
skip || systemctl unmask systemd-timesyncd >/dev/null 2>&1 || true
skip || systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true
skip || systemctl restart systemd-timesyncd

# --- 2. Логи: бета обязана видеть ошибки после ребута/потери питания --------
if [ "$LOG_MODE" = "beta" ]; then
  say "шаг 2: persistent-логи (journald на диск; DietPi-RAMlog выключаем)"
  skip || cp -n /etc/fstab /etc/fstab.min-backup
  if grep -qE '^[[:space:]]*tmpfs[[:space:]]+/var/log' /etc/fstab; then
    skip || sed -i -E 's|^([[:space:]]*tmpfs[[:space:]]+/var/log.*)$|# MIN beta: \1|' /etc/fstab
    say "  /var/log: tmpfs закомментирован (вступит в силу после ребута)"
  fi
  if [ -f /boot/dietpi.txt ]; then
    skip || sed -i 's|^AUTO_SETUP_RAMLOG_MAXSIZE=.*|AUTO_SETUP_RAMLOG_MAXSIZE=0|' /boot/dietpi.txt
  fi
  skip || systemctl disable --now dietpi-ramlog.service >/dev/null 2>&1 || true
  skip || install -d -m 0755 /etc/systemd/journald.conf.d
  if [ "$DRY_RUN" = 0 ]; then
    cat > /etc/systemd/journald.conf.d/99-min-beta.conf <<'EOF'
# MIN beta: логи должны переживать ребут и потерю питания.
# final-режим: этот файл удалить, Storage=volatile вернётся сам.
[Journal]
Storage=persistent
SystemMaxUse=128M
RuntimeMaxUse=16M
RateLimitIntervalSec=0
RateLimitBurst=0
EOF
  fi
  skip || systemctl restart systemd-journald
  say "  journald: persistent (128M cap), лимиты на debug сняты"
else
  say "шаг 2: final-логи (RAMlog остаётся, /var/log в tmpfs)"
fi

# --- 3. Swap: 1 GB на SD-карте — износ и риск ------------------------------
current_mb="$(awk '/^\/var\/swap/ {print int($2/1024)}' /proc/swaps 2>/dev/null || true)"
current_mb="${current_mb:-0}"
if [ "$current_mb" = "$SWAP_MB" ]; then
  say "шаг 3: swap уже $SWAP_MB MB — пропуск"
else
  say "шаг 3: swap ${current_mb} MB → ${SWAP_MB} MB"
  if [ "$DRY_RUN" = 0 ]; then
    swapoff /var/swap 2>/dev/null || true
    rm -f /var/swap
    if [ "$SWAP_MB" = "0" ]; then
      sed -i -E 's|^([[:space:]]*/var/swap[[:space:]].*)$|# MIN: \1|' /etc/fstab
    else
      dd if=/dev/zero of=/var/swap bs=1M count="$SWAP_MB" status=none
      chmod 600 /var/swap
      mkswap /var/swap >/dev/null
      swapon /var/swap
      grep -qE '^[[:space:]]*/var/swap' /etc/fstab || echo '/var/swap none swap sw' >> /etc/fstab
    fi
  fi
fi


# --- 4. Бинарь реле ----------------------------------------------------------
# Один статический musl-бинарь: зависимостей на узле нет вообще.
# Доставка — с Mac: backend/deploy/build_relay.sh --deploy <host> (docs §1).
say "шаг 4: бинарь /usr/local/bin/min-relay"
if [ -x /usr/local/bin/min-relay ]; then
  say "  версия: $(/usr/local/bin/min-relay --version 2>/dev/null || echo '?')"
else
  say "  ОТСУТСТВУЕТ — залить с Mac: backend/deploy/build_relay.sh --deploy <host>"
fi

skip || install -d -m 0755 /etc/min-relay
if [ "$DRY_RUN" = 0 ]; then
  cat > /etc/min-relay/relay.env <<EOF
# MIN relay env (перекрывает Environment= из unit).
# Бета: trace — максимум деталей для отладки. Final: info.
RUST_LOG=$([ "$LOG_MODE" = beta ] && echo "min_relay=trace,info" || echo "info")
# Полные mailbox_id в логах — ТОЛЬКО на время конкретной отладки
# Логи — метаданные; политика хранения задаётся операционным режимом.
# MIN_LOG_FULL_IDS=1
EOF
  chmod 0644 /etc/min-relay/relay.env
fi

# --- 5. Tor hidden service ---------------------------------------------------
# Наружу не публикуем ничего: единственный вход — .onion (роутер не трогаем).
ONION_DIR="/var/lib/tor/$ONION_NAME"
if [ "$DO_TOR" = 1 ]; then
  say "шаг 5: Tor hidden service '$ONION_NAME'"
  skip || install -d -m 0700 -o debian-tor -g debian-tor "$ONION_DIR"
  skip || install -d -m 0700 -o debian-tor -g debian-tor "$ONION_DIR/log"

  if [ -n "$RESTORE_KEYS" ]; then
    # Переезд сервера с сохранением прежнего .onion-адреса (docs §8).
    for f in hs_ed25519_secret_key hs_ed25519_public_key hostname; do
      if [ -f "$RESTORE_KEYS/$f" ]; then
        skip || install -m 0600 -o debian-tor -g debian-tor "$RESTORE_KEYS/$f" "$ONION_DIR/$f"
        say "  восстановлен $f"
      else
        echo "  ВНИМАНИЕ: нет $RESTORE_KEYS/$f" >&2
      fi
    done
  else
    # Ключи сгенерирует Tor при первом старте (если hostname отсутствует).
    skip || rm -f "$ONION_DIR/hostname"
  fi

  if [ "$DRY_RUN" = 0 ]; then
    cp -n /etc/tor/torrc /etc/tor/torrc.min-backup 2>/dev/null || true
    # Блок MIN в torrc перезаписывается идемпотентно, между маркерами.
    sed -i '/^##### MIN-BEGIN #####/,/^##### MIN-END #####/d' /etc/tor/torrc
    snip="$(sed -e "s|/var/lib/tor/min_relay|$ONION_DIR|g" \
                -e "s|HiddenServicePort 3001 127.0.0.1:3001|HiddenServicePort $FRAME_PORT 127.0.0.1:$FRAME_PORT|" \
                "$SRC_DIR/tor/min-relay.conf")"
    {
      echo "##### MIN-BEGIN #####"
      echo "$snip"
      echo "##### MIN-END #####"
    } >> /etc/tor/torrc
    chmod 0644 /etc/tor/torrc
  fi
  skip || systemctl enable tor >/dev/null 2>&1 || true
  skip || systemctl restart tor
  [ "$DRY_RUN" = 0 ] && sleep 3
  if [ "$DRY_RUN" = 0 ] && [ -f "$ONION_DIR/hostname" ]; then
    say "  .onion: $(cat "$ONION_DIR/hostname")"
  fi
fi

# --- 6. systemd: реле + health-timer + ротация логов -------------------------
say "шаг 6: systemd (min-relay, health-timer, logrotate, purge)"
skip || install -m 0644 "$SRC_DIR/systemd/min-relay.service" /etc/systemd/system/min-relay.service
skip || install -m 0755 "$SRC_DIR/health/min-relay-health.sh" /usr/local/bin/min-relay-health.sh
skip || install -m 0644 "$SRC_DIR/health/min-relay-health.service" /etc/systemd/system/min-relay-health.service
skip || install -m 0644 "$SRC_DIR/health/min-relay-health.timer" /etc/systemd/system/min-relay-health.timer
# Логи: ротация (logrotate на DietPi нет) + кнопка полного стирания.
skip || install -m 0755 "$SRC_DIR/logrotate/min-relay-logrotate.sh" /usr/local/bin/min-relay-logrotate.sh
skip || install -m 0644 "$SRC_DIR/logrotate/min-relay-logrotate.service" /etc/systemd/system/min-relay-logrotate.service
skip || install -m 0644 "$SRC_DIR/logrotate/min-relay-logrotate.timer" /etc/systemd/system/min-relay-logrotate.timer
skip || install -m 0755 "$SRC_DIR/logrotate/min-relay-logpurge" /usr/local/bin/min-relay-logpurge
# Каталог логов: tmpfiles.d (создаётся рано при загрузке, до старта юнита).
skip || install -m 0644 "$SRC_DIR/systemd/min-relay-tmpfiles.conf" /etc/tmpfiles.d/min-relay.conf
skip || systemd-tmpfiles --create /etc/tmpfiles.d/min-relay.conf
skip || systemctl daemon-reload
skip || systemctl enable min-relay >/dev/null 2>&1 || true
skip || systemctl enable --now min-relay-health.timer >/dev/null 2>&1 || true
skip || systemctl enable --now min-relay-logrotate.timer >/dev/null 2>&1 || true
if [ "$DRY_RUN" = 0 ] && [ -x /usr/local/bin/min-relay ]; then
  systemctl restart min-relay || true
  sleep 2
  say "  min-relay: $(systemctl is-active min-relay) / enabled: $(systemctl is-enabled min-relay 2>/dev/null)"
  say "  health-timer: $(systemctl is-active min-relay-health.timer)"
  say "  logrotate-timer: $(systemctl is-active min-relay-logrotate.timer)"
  say "  логи: /var/log/min-relay/relay.log (tail -f)"
fi

# --- 7. Файрвол (только узел; роутер — никогда) -----------------------------
# Входящие: SSH из приватных сетей (чтобы переезд на другой роутер не отрезал
# доступ) + всё остальное запрещено. Исходящие: разрешены (Tor обязан выходить).
if [ "$DO_FIREWALL" = 1 ]; then
  say "шаг 7: ufw (deny incoming; SSH из RFC1918)"
  if [ "$DRY_RUN" = 0 ]; then
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
      ufw allow from "$net" to any port 22 proto tcp >/dev/null
    done
    ufw allow out 53/udp >/dev/null   # DNS
    ufw allow out 53/tcp >/dev/null
    ufw allow out 80/tcp  >/dev/null  # HTTP (Tor directory)
    ufw allow out 443/tcp >/dev/null  # HTTPS / OR-port
    ufw allow out 9001/tcp >/dev/null # Tor OR fallback
    ufw allow out 123/udp >/dev/null  # NTP
    ufw --force enable >/dev/null
  fi
  skip || ufw status verbose | head -14 | sed 's/^/  /'
fi



# --- 8. Харденинг SSH (аккуратно: доступ не теряем) --------------------------
# На DietPi стоит Dropbear (не OpenSSH) — конфиг через DROPBEAR_EXTRA_ARGS.
# Флаги dropbear: -s = запрет паролей вообще, -w = запрет входа root.
# -w несовместим с root-only моделью доступа (только если есть --admin-user).
apply_dropbear_args() {
  local extra="$1" conf="/etc/default/dropbear"
  cp -n "$conf" "$conf.min-backup" 2>/dev/null || true
  if grep -q '^DROPBEAR_EXTRA_ARGS=' "$conf"; then
    sed -i "s|^DROPBEAR_EXTRA_ARGS=.*|DROPBEAR_EXTRA_ARGS=\"$extra\"|" "$conf"
  else
    echo "DROPBEAR_EXTRA_ARGS=\"$extra\"" >> "$conf"
  fi
  say "  /etc/default/dropbear: DROPBEAR_EXTRA_ARGS=\"$extra\""
}

if [ "$HARDEN_SSH" = 1 ] || [ "$HARDEN_ROOT" = 1 ]; then
  say "шаг 8: харденинг SSH"
  if [ "$HARDEN_ROOT" = 1 ] && [ -z "$ADMIN_USER" ]; then
    echo "  ОТКАЗ: --harden-root требует --admin-user (иначе потеряешь доступ)" >&2
    HARDEN_ROOT=0
  fi
  if have dropbear || [ -f /etc/default/dropbear ]; then
    extra=""
    [ "$HARDEN_SSH" = 1 ] && extra="$extra -s"
    [ "$HARDEN_ROOT" = 1 ] && extra="$extra -w"
    extra="${extra# }"
    if [ -n "$extra" ]; then
      skip || apply_dropbear_args "$extra"
      skip || systemctl restart dropbear
      say "  dropbear перезапущен (текущая сессия живёт, новые — по ключу)"
    fi
  elif [ -f /etc/ssh/sshd_config ]; then
    if [ "$DRY_RUN" = 0 ]; then
      install -d -m 0755 /etc/ssh/sshd_config.d
      {
        echo "# MIN: харденинг процесса"
        if [ "$HARDEN_SSH" = 1 ]; then
          echo "PasswordAuthentication no"
          echo "KbdInteractiveAuthentication no"
        fi
        [ "$HARDEN_ROOT" = 1 ] && echo "PermitRootLogin prohibit-password"
      } > /etc/ssh/sshd_config.d/99-min.conf
      sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd; }
    fi
    say "  /etc/ssh/sshd_config.d/99-min.conf применён"
  else
    say "  SSH-сервер не найден — пропуск"
  fi
fi

# --- 9. Итог и подсказки для DoD ---------------------------------------------
say "готово. Проверки: см. операционные smoke-команды ниже."
cat <<'EOF'
  systemctl status min-relay --no-pager
  journalctl -u min-relay -n 30 --no-pager
  ss -tlnp | grep -E '3001|3000'          # 3001 на 127.0.0.1; 3000 быть не должно
  cat /var/lib/tor/min_relay/hostname      # .onion-адрес
  ufw status verbose
  # мусорный кадр → BadRequest, процесс жив (nc/xxd на DietPi нет — python3):
  python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",3001),timeout=5);s.sendall(b"\x00\x00\x00\x02\xff\xff");print(s.recv(64).hex())'
  # бэкап ключей onion на Mac (сделать сразу — иначе потеряешь адрес;
  # scp с Dropbear не работает, поэтому tar через ssh):
  #   ssh -i ~/.ssh/id_ed25519_pi root@<host> 'tar czf - -C /var/lib/tor min_relay' > onion-keys.tar.gz
EOF
