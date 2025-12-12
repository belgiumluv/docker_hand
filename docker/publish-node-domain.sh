#!/usr/bin/env bash
set -euo pipefail

DOMAIN_FILE="/vpn/domain.txt"

# env могут не прийти — поэтому считаем это опциональным
NODE_NAME="${MY_NODE_NAME:-}"
POD_NAME="${POD_NAME:-}"
POD_NAMESPACE="${POD_NAMESPACE:-default}"

# если MY_NODE_NAME пуст — читаем spec.nodeName через API Pod
if [[ -z "$NODE_NAME" && -n "$POD_NAME" ]]; then
  TOKEN="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
  CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  API="https://kubernetes.default.svc"

  POD_JSON="$(curl -sS --cacert "$CA" \
    -H "Authorization: Bearer $TOKEN" \
    "$API/api/v1/namespaces/$POD_NAMESPACE/pods/$POD_NAME")"

  # парсим nodeName надёжно через python
  NODE_NAME="$(python3 - <<'PY'
import json,sys
try:
    data=json.load(sys.stdin)
    print(data.get("spec",{}).get("nodeName",""))
except Exception:
    print("")
PY
  <<<"$POD_JSON")"
fi

if [[ -z "$NODE_NAME" ]]; then
  echo "[publish-node-domain] Node name not found (env+API empty)"
  exit 0
fi

# домен из файла
if [[ ! -f "$DOMAIN_FILE" ]]; then
  echo "[publish-node-domain] domain file not found: $DOMAIN_FILE"
  exit 0
fi

DOMAIN="$(tr -d '\r\n ' < "$DOMAIN_FILE")"
if [[ -z "$DOMAIN" ]]; then
  echo "[publish-node-domain] domain.txt is empty"
  exit 0
fi

TOKEN="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API="https://kubernetes.default.svc"

echo "[publish-node-domain] Node:   $NODE_NAME"
echo "[publish-node-domain] Domain: $DOMAIN"

PATCH='{"metadata":{"annotations":{"node-domain":"'"$DOMAIN"'"},"labels":{"node-domain":"'"$DOMAIN"'"}}}'

curl -sS --cacert "$CA" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/merge-patch+json" \
  -X PATCH \
  --data "$PATCH" \
  "$API/api/v1/nodes/$NODE_NAME" \
  >/dev/null

echo "[publish-node-domain] DONE"
