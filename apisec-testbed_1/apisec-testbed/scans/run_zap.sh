#!/usr/bin/env bash
# Varredura ativa DAST com OWASP ZAP contra o gateway.
# Uso:  ./run_zap.sh <perfil>     perfil = vulneravel | protegido
set -euo pipefail
PROFILE="${1:-vulneravel}"
TARGET="${ZAP_TARGET:-http://gateway:8080}"
OPENAPI="${ZAP_OPENAPI:-http://gateway:8080/v3/api-docs}"
OUT="/zap/results"
mkdir -p "$OUT"

echo "[ZAP] perfil=$PROFILE alvo=$TARGET"

# 0) sem ZAP_BEARER o scan roda sem autenticacao e as rotas protegidas voltam 401/403.
#    Obtem um token do usuario de teste (alice) quando nenhum foi informado.
#    Protegido: token do Keycloak (unico emissor aceito pelo gateway e pelo target).
#    Vulneravel: login local (o gateway nao valida JWT e o target aceita o token local).
if [ -z "${ZAP_BEARER:-}" ]; then
  ZAP_BEARER=$(python3 - "$TARGET" "$PROFILE" <<'PY'
import json, sys, urllib.parse, urllib.request
base, profile = sys.argv[1], sys.argv[2]
if profile == "protegido":
    url = "http://keycloak:8080/realms/apisec/protocol/openid-connect/token"
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "apisec-client",
                                   "username": "alice", "password": "alice123"}).encode()
    ctype = "application/x-www-form-urlencoded"
else:
    url = base + "/api/auth/login"
    data = json.dumps({"username": "alice", "password": "alice123"}).encode()
    ctype = "application/json"
req = urllib.request.Request(url, data=data, headers={"Content-Type": ctype})
print(json.load(urllib.request.urlopen(req, timeout=10))["access_token"])
PY
  ) || { echo "[ZAP] falha ao obter token de autenticacao"; exit 1; }
  export ZAP_BEARER
  echo "[ZAP] token de alice obtido para o replacer"
fi

# 1) importa o contrato OpenAPI para popular a arvore de rotas
zap.sh -cmd -quickurl "$TARGET" -quickout "$OUT/_warmup.xml"

# 2) baseline + active scan guiado pela especificacao OpenAPI (api scan)
zap-api-scan.py \
  -t "$OPENAPI" -f openapi \
  -O "$TARGET" \
  -J "zap-${PROFILE}.json" \
  -x "zap-${PROFILE}.xml" \
  -r "zap-${PROFILE}.html" \
  -d -I \
  -z "-config replacer.full_list(0).description=auth \
      -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).replacement=Bearer ${ZAP_BEARER:-}"
# -I (acima) impede que alertas (WARN) retornem erro; falhas reais param o script (set -e)

cp -f /zap/wrk/zap-${PROFILE}.* "$OUT/" 2>/dev/null || true
echo "[ZAP] relatorios em results/zap-${PROFILE}.{json,xml,html}"
