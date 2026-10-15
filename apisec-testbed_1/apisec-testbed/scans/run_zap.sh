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
