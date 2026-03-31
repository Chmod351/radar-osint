#!/bin/bash
# modules/http.sh

# 1. Cargas las rutas base
source "$(dirname "$0")/../env.sh"

# 2. Tomas el target del argumento
TARGET="$1"

OP_DIR="$RESULTS_BASE/$TARGET"
OUTPUT="$OP_DIR/http.json"

# Crear la carpeta del target si no existe (importante para el primer módulo)
mkdir -p "$OP_DIR"

if [[ -z "$TARGET" ]]; then
    echo "[!] Uso: $0 scanme.nmap.org"
    exit 1
fi

# 1. Preparación del entorno (Cimiento sólido)
if [ ! -f "$OUTPUT" ] || [ ! -s "$OUTPUT" ]; then
    echo "{}" > "$OUTPUT"
fi

log_info "[+] Obteniendo headers de $TARGET..."

# 2. Obtener headers (Seguimos con el radar en bajo ruido)
HEADERS=$(curl -I -s -L -A "Mozilla/5.0" --max-time 5 "$TARGET" 2>/dev/null)

# 3. Extraer campos con AWK (Limpiando retornos de carro \r)
SERVER=$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="server" {print $2}' | tr -d '\r' | xargs)
POWERED=$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="x-powered-by" {print $2}' | tr -d '\r' | xargs)
CONTENT=$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="content-type" {print $2}' | tr -d '\r' | xargs)

# Fallbacks para no tener campos vacíos
SERVER=${SERVER:-"unknown"}
POWERED=${POWERED:-"unknown"}
CONTENT=${CONTENT:-"unknown"}

# 4. Inyección Atómica con JQ
jq --arg target "$TARGET" \
   --arg server "$SERVER" \
   --arg powered "$POWERED" \
   --arg content "$CONTENT" \
   '.[$target] += { "http": { 
       server: $server, 
       powered_by: ($powered | split(", ")), 
       content_type: $content 
   }}' "$OUTPUT" > "$OUTPUT.tmp" && mv "$OUTPUT.tmp" "$OUTPUT"

log_success "[DONE] HTTP Info inyectada en $OUTPUT"
