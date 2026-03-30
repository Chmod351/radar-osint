#!/bin/bash

source "$(dirname "$0")/../env.sh"

TARGET="$1"
REPORT="$RESULTS_BASE/$TARGET/MASTER_REPORT.json"
VULNS_FILE="$RESULTS_BASE/$TARGET/vulnerabilities.json"

if [[ ! -f "$REPORT" ]]; then
    echo -e "\e[31m[-] No se encontró el reporte maestro en $REPORT\e[0m"
    exit 1
fi

# === PALETA DE COLORES ===
GREEN='\e[32m'
RED='\e[31m'
CYAN='\e[36m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
NC='\e[0m'

echo -e "${BLUE}=== DASHBOARD OPERATIVO: $TARGET ===${NC}\n"

# Encabezado
printf "%-35s | %-15s | %-12s | %-18s\n" "HOST" "IP" "STATUS" "RANGE/CIDR"
echo "---------------------------------------------------------------------------------------"

# Iteración segura
jq -r --arg t "$TARGET" '.[$t].subdomains[] | @base64' "$REPORT" | while read -r row; do
    
    decode_row=$(echo "$row" | base64 --decode)

    # === FUNCION SAFE GET ===
    _get() {
        local val=$(echo "$decode_row" | jq -r "$1 // empty")
        [[ "$val" == "null" || "$val" == "Unknown" || -z "$val" ]] && echo "-" || echo "$val"
    }

    HOST=$(_get '.host')
    IP=$(_get '.ip')
    STATUS=$(_get '.status')

    RANGE=$(_get '.infra.range')
    OWNER=$(_get '.infra.owner')
    COUNTRY=$(_get '.infra.country')
    PROVIDER=$(_get '.infra.provider')

    ASN=$(echo "$decode_row" | jq -r '.infra.asn // empty' | grep -oE "AS[0-9]+" || echo "-")

    CONTACT=$(echo "$decode_row" | jq -r '.full_whois[]? | select(has("e-mail")) | ."e-mail"' | head -n1)
    [[ -z "$CONTACT" ]] && CONTACT="-"

    [[ "$STATUS" == "exposed" ]] && S_COL="${RED}${STATUS}${NC}" || S_COL="${GREEN}${STATUS}${NC}"

    # === HEADER PRINCIPAL ===
    printf "%-44b | %-15s | %-18b | %-18s\n" "$CYAN$HOST$NC" "$IP" "$S_COL" "$RANGE"

    # === PORTS ===
    echo -e "${YELLOW}    [PORTS]${NC}"

    PORTS_RAW=$(echo "$decode_row" | jq -r '.ports[]? | "\(.port)|\(.service)|\(.version // "unknown")"' 2>/dev/null)

    if [[ -n "$PORTS_RAW" ]]; then
        while IFS="|" read -r PORT SERVICE VERSION; do

            if [[ "$PORT" == "22" || "$SERVICE" == "ssh" ]]; then
                COLOR=$RED
            elif [[ "$PORT" == "80" || "$PORT" == "443" ]]; then
                COLOR=$GREEN
            else
                COLOR=$CYAN
            fi

            printf "      - %b\n" "${COLOR}${PORT}/${SERVICE} (${VERSION})${NC}"

        done <<< "$PORTS_RAW"
    else
        echo -e "      ${MAGENTA}No ports detected.${NC}"
    fi

    # === INTEL ===
    echo -e "${BLUE}    [INTEL]${NC}"

    SHORT_OWNER=$(echo "$OWNER" | cut -c1-40)

    printf "      Org: %-40s | Country: %s\n" "$SHORT_OWNER" "$COUNTRY"
    printf "      ASN: %-15s | Prov: %-15s | Admin: %s\n" "$ASN" "$PROVIDER" "$CONTACT"

    # === VULNERABILIDADES ===
    if [[ -f "$VULNS_FILE" ]]; then
        echo -e "${RED}    [VULNS]${NC}"

        VULN_DATA=$(jq -r --arg h "$HOST" '
            .matches[]? 
            | select(.host == $h or .host == "all") 
            | "      - [!] \(.title)\n        Link: \(.link)"
        ' "$VULNS_FILE" 2>/dev/null | head -n 4)

        if [[ -n "$VULN_DATA" ]]; then
            echo -e "$VULN_DATA"
        else
            echo -e "      ${GREEN}No known exploits found.${NC}"
        fi
    fi

    echo "---------------------------------------------------------------------------------------"

done

echo -e "\n${GREEN}● [$(whoami)@archlinux] radar de largo alcance sincronizado.${NC}"
