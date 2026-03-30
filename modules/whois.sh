#!/bin/bash

source "$(dirname "$0")/../env.sh"
TARGET="$1"
OP_DIR="$RESULTS_BASE/$TARGET"
INPUT_JSON="$OP_DIR/lowNoice.json"
OUTPUT_FILE="$OP_DIR/whois_ips.json"

if [[ ! -f "$INPUT_JSON" ]]; then
    log_error "No existe el reporte de la Fase 1 ($INPUT_JSON)"
    exit 1
fi

log_info "---[INTEL ENHANCED] Enriqueciendo con WHOIS y DIG (DNS)---"
echo "{}" > "$OUTPUT_FILE"

identify_provider() {
    local ip=$1
    local ptr=$(host "$ip" 2>/dev/null | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
    
    if [[ "$ptr" =~ "amazonaws" ]]; then echo "Amazon"; return 1; fi
    if [[ "$ptr" =~ "cloudflare" ]]; then echo "Cloudflare"; return 1; fi
    if [[ "$ptr" =~ "google" ]]; then echo "Google"; return 1; fi
    if [[ "$ptr" =~ "msn.com" || "$ptr" =~ "azure" ]]; then echo "Microsoft"; return 1; fi
    if [[ "$ip" =~ ^10\. || "$ip" =~ ^172\.16\. || "$ip" =~ ^192\.168\. ]]; then echo "Internal_Leak"; return 1; fi
    
    echo "Self-Hosted/Local"
    return 0
}

# --- LOOP DE PROCESAMIENTO ---
jq -r --arg t "$TARGET" '.[$t].subdomains[] | "\(.host) \(.ip)"' "$INPUT_JSON" | while read -r domain ip; do
    
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then continue; fi

    PROVIDER=$(identify_provider "$ip")
    IS_LOCAL=$? 

    if [ $IS_LOCAL -eq 1 ]; then
        echo -e "${YELLOW}[-]${NC} Cloud detectado ($PROVIDER): $domain"
        jq --arg dom "$domain" --arg ip "$ip" --arg prov "$PROVIDER" \
           '.[$dom] = { "ip": $ip, "infra": { "provider": $prov, "type": "cloud" }, "status": "protected" }' \
           "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
        continue
    fi

    echo -e "${GREEN}[+]${NC} Analizando PROFUNDO (Local): ${CYAN}$domain${NC} ($ip)"

    # 1. Obtención de Raw Data
    RAW_WHOIS=$(whois "$ip" 2>/dev/null)

    # 2. PARSER DE BLOQUES (Texto -> Array de Objetos)
    # Separamos por doble salto de línea, limpiamos y convertimos cada bloque en objeto
    WHOIS_ARRAY=$(echo "$RAW_WHOIS" | jq -Rs '
      split("\n\n") | 
      map(
        split("\n") | 
        map(select(contains(": "))) | 
        map(split(": ")) | 
        map({(.[0] | gsub("^\\s+|\\s+$"; "")): (.[1:] | join(": ") | gsub("^\\s+|\\s+$"; ""))}) | 
        add
      ) | map(select(. != null))
    ')

# ... (después del WHOIS_ARRAY que ya tenés)
# ---------------------------------------------------------------------------------
    # 3. FILTRADO QUIRÚRGICO (Buscamos el bloque con 'inetnum' para el Dashboard)
    # Esto ignora los comentarios de LACNIC (% IP Client, etc.)
    DATA_BLOCK=$(echo "$WHOIS_ARRAY" | jq -c '.[] | select(has("inetnum"))' | head -n1)

    # Si por alguna razón no hay inetnum (raro), buscamos cualquier bloque con owner o descr
    if [[ -z "$DATA_BLOCK" || "$DATA_BLOCK" == "null" ]]; then
        DATA_BLOCK=$(echo "$WHOIS_ARRAY" | jq -c '.[] | select(has("owner") or has("descr"))' | head -n1)
    fi

    # Extraemos las variables limpias para la "cara visible" del reporte
    ORG=$(echo "$DATA_BLOCK" | jq -r '.owner // .orgname // .descr // "unknown"')
    RANGE=$(echo "$DATA_BLOCK" | jq -r '.inetnum // .route // "unknown"')
    COUNTRY=$(echo "$DATA_BLOCK" | jq -r '.country // "unknown"')
    
    # 4. INYECCIÓN MAESTRA (Actualizada)
    jq --arg dom "$domain" --arg ip "$ip" \
       --arg org "$ORG" --arg range "$RANGE" --arg count "$COUNTRY" \
       --argjson full "$WHOIS_ARRAY" \
       '.[$dom] = {
           "ip": $ip,
           "infra": { 
               "provider": "Self-Hosted", 
               "owner": $org, 
               "range": $range, 
               "country": $count 
           },
           "full_whois": $full,
           "status": "exposed"
       }' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"


    WAIT=$(( ( RANDOM % 2 ) + 2 ))
    sleep $WAIT
done

log_success "Intel consolidado en: $OUTPUT_FILE"
