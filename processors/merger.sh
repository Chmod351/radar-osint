#!/bin/bash
source "$(dirname "$0")/../env.sh"
TARGET="$1"
OP_DIR="$RESULTS_BASE/$TARGET"

# Archivos de entrada (Los fragmentos)
LOW_NOISE="$OP_DIR/lowNoice.json"
WHOIS="$OP_DIR/whois_ips.json"
INTEL="$OP_DIR/intel.json"
HTTP_JSON="$OP_DIR/http.json"

# Archivo de salida (El Objeto Maestro)
OUTPUT_MAESTRO="$OP_DIR/MASTER_REPORT.json"

log_info "[+] Iniciando consolidación en: $OP_DIR"

# Verificación de existencia de la base
if [[ ! -f "$LOW_NOISE" ]]; then
    log_error "[-] Error: No se encuentra la base lowNoice.json en $OP_DIR"
    exit 1
fi

# Usamos --argjson para pasar los archivos si existen, o un objeto vacío si no.
# ... dentro de merger.sh
jq --arg target "$TARGET" \
   --argjson whois "$(cat "$WHOIS" 2>/dev/null || echo '{}')" \
   --argjson intel "$(cat "$INTEL" 2>/dev/null || echo '{}')" \
   --argjson http "$(cat "$HTTP_JSON" 2>/dev/null || echo '{}')" \
   '
   .[$target].subdomains |= map(
     .host as $h | 
     # Usamos * para que los datos se fusionen recursivamente
     . * ($intel[$h] // {}) * ($whois[$h] // {}) * ($http[$h] // {})
   )
' "$LOW_NOISE" > "$OUTPUT_MAESTRO"

log_success "[DONE] Master JSON consolidado en: $OUTPUT_MAESTRO"
