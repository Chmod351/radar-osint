#!/bin/bash
# web_discovery.sh

set -euo pipefail

source "$(dirname "$0")/../env.sh"

TARGET="${1:-}"
OP_DIR="$RESULTS_BASE/$TARGET"
INPUT_JSON="$OP_DIR/lowNoice.json"
OUTPUT_WEB="$OP_DIR/web_intel.json"

# === VALIDACIONES ===
if [[ -z "$TARGET" ]]; then
    echo "[-] Uso: $0 <target>"
    exit 1
fi

if [[ ! -f "$INPUT_JSON" ]]; then
    echo "[-] No existe: $INPUT_JSON"
    exit 1
fi

command -v jq >/dev/null || { echo "[-] jq no instalado"; exit 1; }
command -v whatweb >/dev/null || { echo "[-] whatweb no instalado"; exit 1; }

echo "[*] Iniciando Web Discovery sobre: $TARGET"

# Inicializar JSON válido
echo "{}" > "$OUTPUT_WEB"

# === EXTRAER HOSTS WEB ===
mapfile -t DOMAINS < <(
jq -r ".\"$TARGET\".subdomains[]
| select(.ports and any(.ports[]?.port; . == 80 or . == 443 or . == 8080 or . == 8443))
| .host" "$INPUT_JSON" | sort -u
)

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    echo "[!] No hay dominios con puertos web"
    exit 0
fi

# === LOOP PRINCIPAL ===
for domain in "${DOMAINS[@]}"; do

    echo "[+] Escaneando: $domain"

    RAW_DATA=$(whatweb --level 2 --color=never --log-json=- "$domain" 2>/dev/null || true)

    # === FALLBACK 1: sin respuesta ===
    if [[ -z "$RAW_DATA" || "$RAW_DATA" == "[]" ]]; then
        echo "[!] WhatWeb vacío → fallback HTTP headers"

        SERVER=$(curl -sI --max-time 5 "http://$domain" 2>/dev/null | grep -i "^Server:" | cut -d' ' -f2- | tr -d '\r')

        if [[ -z "$SERVER" ]]; then
            TECHS='[]'
        else
            TECHS=$(jq -c -n --arg s "$SERVER" '[{name: $s, version: "unknown"}]')
        fi
    else
        # === PROCESAMIENTO NORMAL ===
        TECHS=$(echo "$RAW_DATA" | jq -c '
            if length > 0 and .[0].plugins then
                .[0].plugins
                | to_entries
                | map({
                    name: .key,
                    version: (.value.version[0] // "unknown")
                })
            else
                []
            end
        ')
    fi

    # === FALLBACK 2: asegurar JSON válido ===
    if [[ -z "$TECHS" || "$TECHS" == "null" ]]; then
        TECHS='[]'
    fi

    # === ESCRITURA SEGURA ===
    TMP=$(mktemp)

    jq --arg dom "$domain" --argjson techs "$TECHS" \
    '.[$dom] = { "web_tech": $techs }' \
    "$OUTPUT_WEB" > "$TMP" && mv "$TMP" "$OUTPUT_WEB"

    sleep 0.5
done

echo "[✓] Web discovery terminado: $OUTPUT_WEB"
