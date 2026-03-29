#!/bin/bash
# web_discovery.sh

source "$(dirname "$0")/../env.sh" 

TARGET="$1"
OP_DIR="$RESULTS_BASE/$TARGET"
INPUT_JSON="$OP_DIR/lowNoice.json"
# Este es el archivo que luego leerá el Merger
OUTPUT_WEB="$OP_DIR/web_intel.json"

if [[ ! -f "$INPUT_JSON" ]]; then echo "[-] Error: No hay lowNoice.json"; exit 1; fi

log_info "--------------------------------------------------------------------------"
log_info "---[WHATWEB] Normalizando tecnologías para el Master...-----------------"
log_info "--------------------------------------------------------------------------"

# Inicializamos como objeto vacío
echo "{}" > "$OUTPUT_WEB"

# Extraemos los hosts con puertos web (80, 443, 8080, 8443)
jq -r ".\"$TARGET\".subdomains[] | select(.ports[]?.port | IN(80, 443, 8080, 8443)) | .host" "$INPUT_JSON" | sort -u | while read -r domain; do

    echo "[+] Escaneando: $domain"
    
    # Ejecutamos y guardamos en variable
    # --log-json=- manda el JSON a la salida estándar
    RAW_DATA=$(whatweb --level 1 --color=never --log-json=- "$domain" 2>/dev/null)

    if [[ -n "$RAW_DATA" && "$RAW_DATA" != "[]" ]]; then
        # ESTRUCTURA CRÍTICA PARA EL MERGER:
        # Transformamos el array de plugins de WhatWeb en un objeto simple:
        # "domain.com": { "web_tech": ["WordPress", "PHP", "Apache"] }
        
        PROCESSED_DATA=$(echo "$RAW_DATA" | jq -c '.[0].plugins | to_entries | map({name: .key, version: (.value.version[0] // "unknown")})')

        jq --arg dom "$domain" --argjson techs "$PROCESSED_DATA" \
        '.[$dom] = { "web_tech": $techs }' \
        "$OUTPUT_WEB" > "$OUTPUT_WEB.tmp" && mv "$OUTPUT_WEB.tmp" "$OUTPUT_WEB"
    fi
    sleep 1
done

log_success "[DONE] Datos web listos en: $OUTPUT_WEB"
