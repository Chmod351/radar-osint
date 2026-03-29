#!/bin/bash

# 1. Cargas las rutas base
source "$(dirname "$0")/../env.sh"

# 2. Tomas el target del argumento
TARGET="$1"

OP_DIR="$RESULTS_BASE/$TARGET"



INPUT_JSON="$OP_DIR/lowNoice.json"
OUTPUT_FILE="$OP_DIR/whois_ips.json"

# Verificación de entrada
if [[ ! -f "$INPUT_JSON" ]]; then
    log_error "No existe el reporte de la Fase 1 ($INPUT_JSON)"
    exit 1
fi

log_info "---[INTEL ENHANCED] Enriqueciendo con WHOIS y DIG (DNS)---"
echo "{}" > "$OUTPUT_FILE"

# Acceso seguro a la llave dinámica del JSON
jq -r --arg t "$TARGET" '.[$t].subdomains[] | "\(.host) \(.ip)"' "$INPUT_JSON" | while read -r domain ip; do

    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_warn "Saltando $domain: IP inválida ($ip)"
        continue
    fi

    echo -e "${GREEN}[+]${NC} Analizando: ${CYAN}$domain${NC} ($ip)"

    # --- 1. CAPA WHOIS ---
    IP_DATA=$(whois "$ip" 2>/dev/null)
    NET=$(echo "$IP_DATA" | awk -F': *' 'tolower($1) ~ /netname/ {print $2}' | head -n1 | xargs)
    ORG=$(echo "$IP_DATA" | awk -F': *' 'tolower($1) ~ /orgname|organization|descr/ {print $2}' | head -n1 | xargs)
    COUNTRY=$(echo "$IP_DATA" | awk -F': *' 'tolower($1) ~ /country/ {print $2}' | head -n1 | xargs)
    
    DOM_DATA=$(whois "$domain" 2>/dev/null)
    REGISTRAR=$(echo "$DOM_DATA" | awk -F': *' 'tolower($1) ~ /registrar/ {print $2}' | head -n1 | xargs)
    CREATED=$(echo "$DOM_DATA" | awk -F': *' 'tolower($1) ~ /creation date|created/ {print $2}' | head -n1 | xargs)

    # --- 2. CAPA DIG ---
    MX_REC=$(dig +short MX "$domain" | tr '\n' ',' | sed 's/,$//')
    TXT_REC=$(dig +short TXT "$domain" | tr '\n' ' ' | xargs)
    NS_REC=$(dig +short NS "$domain" | tr '\n' ',' | sed 's/,$//')

    # --- 3. INYECCIÓN ---
    jq --arg dom "$domain" \
       --arg ip "$ip" \
       --arg net "${NET:-unknown}" \
       --arg org "${ORG:-unknown}" \
       --arg count "${COUNTRY:-unknown}" \
       --arg reg "${REGISTRAR:-unknown}" \
       --arg cre "${CREATED:-unknown}" \
       --arg mx "${MX_REC:-none}" \
       --arg txt "${TXT_REC:-none}" \
       --arg ns "${NS_REC:-none}" \
       '.[$dom] = {
           "ip": $ip,
           "whois": {
               "ip_info": { "netname": $net, "org": $org, "country": $count },
               "domain_info": { "registrar": $reg, "created": $cre }
           },
           "dns_records": { "mx": $mx, "ns": $ns, "txt": $txt }
       }' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp" && mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

    WAIT=$(( ( RANDOM % 3 ) + 2 )) # Bajé un poco el delay para que no sea eterno
    echo -e "    ${YELLOW}waiting ${WAIT}s...${NC}"
    sleep $WAIT
done

log_success "Intel consolidado (Whois + DNS) en: $OUTPUT_FILE"
