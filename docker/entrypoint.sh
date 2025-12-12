#!/usr/bin/env bash
set -euo pipefail

log(){ echo "[entrypoint] $*"; }

# --- bootstrap /vpn из "золотой копии" ---
if [ ! -e /vpn/sing-box ]; then
  log "/vpn/sing-box missing -> seeding from /opt/seed/vpn"
  mkdir -p /vpn
  cp -f /opt/seed/vpn/sing-box /vpn/sing-box
  chmod +x /vpn/sing-box
fi

if [ ! -e /vpn/server.json ]; then
  log "/vpn/server.json missing -> seeding from /opt/seed/vpn"
  cp -f /opt/seed/vpn/server.json /vpn/server.json
fi

# Проверки на наличие бинарей/конфигов, которые нужны рантайм-сервисам
if [ ! -x /vpn/sing-box ]; then
  echo "[ERR] /vpn/sing-box not found or not executable" >&2
  exit 1
fi


# === ONE-SHOT СТАДИЯ ===
# 1) setconfiguration: кладет serverlist.json в /vpn, читает публичный IP, пишет /vpn/server_configuration.json и /vpn/domain.txt и обновляет SQLite.
if ! /usr/bin/python3 /app/scripts/04_setconfiguration.py; then
  echo "[ERR] setconfiguration failed. Проверь /app/configs/serverlist.json и доступ к интернету для api.ipify.org" >&2
  exit 1
fi

# =========================
# TLS issue/renew AFTER setconfiguration
# deSEC DNS-01, no 80/443 needed
# Produces: /opt/ssl/sert.crt, sert.key, sert.crt.key
# =========================
log "TLS stage (deSEC) after setconfiguration..."

: "${EMAIL:?EMAIL env is required for ACME}"
: "${DESEC_TOKEN:?DESEC_TOKEN env is required for deSEC}"

LEGO_PATH="${LEGO_PATH:-/data/lego}"
OUT_DIR="/opt/ssl"
mkdir -p "$LEGO_PATH" "$OUT_DIR"

# Можно оставить lock, если LEGO_PATH шарится между подами/нодами
LOCK_FILE="$LEGO_PATH/.acme.lock"
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -x 9
log "acquired global ACME lock: $LOCK_FILE"

# --- Домены ---
DOMAINS_FROM_ENV="${DOMAINS:-}"
DOMAINS_FROM_FILE=""
if [ -f /vpn/domain.txt ]; then
  DOMAINS_FROM_FILE="$(tr -d ' \n\r' </vpn/domain.txt)"
fi

DOMAINS_FINAL="$DOMAINS_FROM_ENV"
if [ -z "$DOMAINS_FINAL" ]; then
  DOMAINS_FINAL="$DOMAINS_FROM_FILE"
fi

if [ -z "$DOMAINS_FINAL" ]; then
  echo "[ERR] no domains found. Set DOMAINS env or ensure /vpn/domain.txt exists" >&2
  exit 1
fi

log "domains for cert: $DOMAINS_FINAL"

# "a,b,c" -> "--domains a --domains b --domains c"
domain_args=""
OLD_IFS="$IFS"; IFS=","
for d in $DOMAINS_FINAL; do
  d="$(echo "$d" | tr -d ' \n\r')"
  [ -n "$d" ] && domain_args="$domain_args --domains $d"
done
IFS="$OLD_IFS"

# Берём первый домен как основной CN
first_domain="$(echo "$DOMAINS_FINAL" | cut -d',' -f1 | tr -d ' \n\r')"

issue_cert() {
  log "issuing cert via lego (desec)"
  /usr/local/bin/lego \
    --accept-tos \
    --email="$EMAIL" \
    --dns="desec" \
    $domain_args \
    --path="$LEGO_PATH" \
    run
}

renew_cert() {
  log "renewing cert if needed..."
  /usr/local/bin/lego \
    --email="$EMAIL" \
    --dns="desec" \
    $domain_args \
    --path="$LEGO_PATH" \
    renew \
    --days "${RENEW_BEFORE_DAYS:-30}"
}

copy_from_lego() {
  local dom="$1"
  local crt="$LEGO_PATH/certificates/${dom}.crt"
  local key="$LEGO_PATH/certificates/${dom}.key"

  if [ ! -f "$crt" ] || [ ! -f "$key" ]; then
    log "[WARN] copy_from_lego: no cert/key for $dom"
    return 1
  fi

  cp -f "$crt" "$OUT_DIR/sert.crt"
  cp -f "$key" "$OUT_DIR/sert.key"
  cat "$OUT_DIR/sert.crt" "$OUT_DIR/sert.key" > "$OUT_DIR/sert.crt.key"
  chmod 600 "$OUT_DIR/sert.key" "$OUT_DIR/sert.crt.key"

  log "wrote LE cert to:"
  log "  $OUT_DIR/sert.crt"
  log "  $OUT_DIR/sert.key"
  log "  $OUT_DIR/sert.crt.key"
}

try_issue() {
  local max_tries="${ISSUE_MAX_TRIES:-5}"
  local i=1
  while [ "$i" -le "$max_tries" ]; do
    if issue_cert; then
      return 0
    fi
    log "[WARN] issue failed, retry $i/$max_tries after 60s..."
    sleep 60
    i=$((i+1))
  done
  return 1
}

# 2) Первичный сертификат:
if [ ! -d "$LEGO_PATH/certificates" ] || [ -z "$(ls -A "$LEGO_PATH/certificates" 2>/dev/null)" ]; then
  log "no existing certificates in $LEGO_PATH, trying to issue..."
  if ! try_issue; then
    echo "[ERR] initial LE issue failed after multiple attempts" >&2
    exit 1
  fi
else
  log "certificates already exist in $LEGO_PATH, skipping initial issue"
fi

# 3) Копируем сертификат в /opt/ssl
if ! copy_from_lego "$first_domain"; then
  echo "[ERR] lego did not produce cert/key for $first_domain" >&2
  exit 1
fi

# 4) Background auto-renew
(
  RENEW_INTERVAL="${RENEW_INTERVAL:-21600}"   # 6 часов
  while true; do
    sleep "$RENEW_INTERVAL"

    log "auto-renew: running lego renew..."
    if renew_cert; then
      if copy_from_lego "$first_domain"; then
        log "auto-renew: cert renewed and files updated"

        if pidof haproxy >/dev/null 2>&1; then
          log "auto-renew: reloading haproxy to apply renewed cert"
          haproxy -c -f /etc/haproxy/haproxy.cfg && \
          kill -USR2 "$(pidof haproxy | awk '{print $1}')"
        fi
      else
        log "[WARN] auto-renew: LE cert files missing after renew"
      fi
    else
      log "[WARN] auto-renew: lego renew failed, will retry next interval"
    fi
  done
) &

/usr/local/bin/publish-node-domain.sh || true


# 2) mutate_server_json: генерирует ключи/пароли, правит /vpn/server.json, записывает chosen fake domains в БД и формирует /vpn/changes_dict.json
if ! /usr/bin/python3 /app/scripts/10_mutate_server_json.py; then
  echo "[ERR] mutate_server_json failed" >&2
  exit 1
fi

# 3) apply_haproxy_changes: применяет изменения путей и доменов в /etc/haproxy/haproxy.cfg
if ! /usr/bin/python3 /app/scripts/11_apply_haproxy_changes.py; then
  echo "[ERR] apply_haproxy_changes failed" >&2
  exit 1
fi

# Быстрая валидация конфигов
if ! /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg; then
  echo "[ERR] haproxy.cfg invalid after apply" >&2
  exit 1
fi
if ! /vpn/sing-box check -c /vpn/server.json; then
  echo "[ERR] sing-box server.json invalid after mutate" >&2
  exit 1
fi

# === УСТАНОВКА NODE_EXPORTER (если не установлен) ===
NODE_EXPORTER_VERSION="1.7.0"
NODE_EXPORTER_BIN="/usr/bin/node_exporter"
NODE_EXPORTER_SUP_CONF="/etc/supervisor/conf.d/node_exporter.conf"

log "checking node_exporter..."

if ! command -v node_exporter >/dev/null 2>&1 && [ ! -x "$NODE_EXPORTER_BIN" ]; then
  log "node_exporter not found -> installing v${NODE_EXPORTER_VERSION}"

  apt-get update && apt-get install -y wget ca-certificates || true

  cd /tmp
  wget "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
  tar xvf node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz

  mv node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter "$NODE_EXPORTER_BIN"
  chmod +x "$NODE_EXPORTER_BIN"
  rm -rf /tmp/node_exporter*
else
  log "node_exporter already installed"
fi

if ! id -u node_exporter >/dev/null 2>&1; then
  log "creating user node_exporter"
  useradd -rs /bin/false node_exporter || true
fi

if [ ! -f "$NODE_EXPORTER_SUP_CONF" ]; then
  log "creating supervisor config for node_exporter at $NODE_EXPORTER_SUP_CONF"
  cat <<EOF > "$NODE_EXPORTER_SUP_CONF"
[program:node_exporter]
command=$NODE_EXPORTER_BIN
user=node_exporter
autostart=true
autorestart=true
stdout_logfile=/var/log/node_exporter.log
stderr_logfile=/var/log/node_exporter_err.log
EOF
else
  log "supervisor config for node_exporter already exists"
fi

if ! "$NODE_EXPORTER_BIN" --version >/dev/null 2>&1; then
  log "[WARN] node_exporter seems not working correctly"
fi


log "one-shot stage complete; starting supervisor..."

# === РАНТАЙМ СТАДИЯ ===
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
