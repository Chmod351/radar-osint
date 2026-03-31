#!/bin/bash
source "$(dirname "$0")/../env.sh"
TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "[!] Uso: $0 dominio.com"
    exit 1
fi

OP_DIR="$RESULTS_BASE/$TARGET"
mkdir -p "$OP_DIR"

# 1. ENUM
subfinder -d "$TARGET" -silent > "$OP_DIR/subs_raw.txt"
assetfinder --subs-only "$TARGET" >> "$OP_DIR/subs_raw.txt"
sort -u "$OP_DIR/subs_raw.txt" > "$OP_DIR/subdominios.txt"
rm "$OP_DIR/subs_raw.txt"

# 2. DNS
dnsx -silent -nc -a -resp -l "$OP_DIR/subdominios.txt" > "$OP_DIR/dns.txt"
cut -d' ' -f1 "$OP_DIR/dns.txt" > "$OP_DIR/resueltos.txt"

# =========================
# 3. HTTP CHECK (Fase Crítica)
# =========================
echo "[+] Lanzando HTTP Check (Fase 3)..."
httpx-toolkit -silent -no-color -threads 50 -l "$OP_DIR/resueltos.txt" -o "$OP_DIR/lowNoice.txt" 2>"$OP_DIR/httpx_error.log"

if [ $? -ne 0 ]; then
    echo "[!] FASE 3 FALLÓ: httpx-toolkit abortó. Revisando daños..."
    if [ ! -s "$OP_DIR/lowNoice.txt" ]; then
        echo "[!] lowNoice.txt está vacío. Clonando resueltos.txt para no romper el flujo."
        # Si httpx muere, al menos pretendemos que los dominios están vivos en puerto 80
        awk '{print "http://"$0}' "$OP_DIR/resueltos.txt" > "$OP_DIR/lowNoice.txt"
    fi
else
    echo "[✓] FASE 3 Completada con éxito."
fi

# =========================
# 4. ANALISIS (Fase de Metadatos)
# =========================
echo "[+] Lanzando Análisis de Títulos/Server (Fase 4)..."
# Usamos un archivo temporal para no pisar si falla
httpx-toolkit -silent -no-color -title -web-server -threads 50 -l "$OP_DIR/lowNoice.txt" > "$OP_DIR/analisis_tmp.txt" 2>>"$OP_DIR/httpx_error.log"

if [ $? -ne 0 ] || [ ! -s "$OP_DIR/analisis_tmp.txt" ]; then
    echo "[!] FASE 4 FALLÓ o devolvió vacío. Creando analisis.json vacío por seguridad."
    echo "{}" > "$OP_DIR/analisis.json"
    touch "$OP_DIR/analisis.txt"
else
    mv "$OP_DIR/analisis_tmp.txt" "$OP_DIR/analisis.txt"
    echo "[✓] FASE 4 Completada."
fi# =========================
# 5. INDEXACIÓN
# =========================

# dns.json
awk '{ ip="0.0.0.0"; for(i=1;i<=NF;i++) { if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { ip=$i; break } } if (ip != "0.0.0.0") printf "%s %s\n", $1, ip }' "$OP_DIR/dns.txt" \
| jq -R 'split(" ") | {key: .[0], value: .[1]}' | jq -s 'from_entries' > "$OP_DIR/dns.json"

# vivos.json
if [[ -s "$OP_DIR/lowNoice.txt" ]]; then
    awk '{ url=$0; gsub(/^https?:\/\//,"",url); host=url; sub(/\/.*/,"",host); printf "%s %s\n", host, $0 }' "$OP_DIR/lowNoice.txt" \
    | jq -R 'split(" ") | {key: .[0], value: .[1]}' | jq -s 'from_entries' > "$OP_DIR/vivos.json"
else
    echo "{}" > "$OP_DIR/vivos.json"
fi

# analisis.json
if [[ -s "$OP_DIR/analisis.txt" ]]; then
    awk '{ url=$1; gsub(/^https?:\/\//,"",url); host=url; sub(/\/.*/,"",host); cdn="none"; if (tolower($0) ~ /cloudflare/) cdn="cloudflare"; else if (tolower($0) ~ /akamai/) cdn="akamai"; printf "%s %s\n", host, cdn }' "$OP_DIR/analisis.txt" \
    | jq -R 'split(" ") | {key: .[0], value: {cdn: .[1]}}' | jq -s 'from_entries' > "$OP_DIR/analisis.json"
else
    echo "{}" > "$OP_DIR/analisis.json"
fi

# =========================
# 5.5 ASN ENRICHMENT (WITH CONSOLE LOGS)
# =========================
echo "[+] TRACKING ASN: Iniciando proceso..."
echo "{}" > "$OP_DIR/asn.json"

# Verificamos si dns.json tiene datos
COUNT=$(jq '. | length' "$OP_DIR/dns.json")
echo "[+] TRACKING ASN: $COUNT hosts encontrados para procesar."

jq -r 'to_entries[] | "\(.key) \(.value)"' "$OP_DIR/dns.json" | while read -r host ip; do
    echo "    [i] Consultando ASN para: $host ($ip)"
    
    # Invertir IP
    rev_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
    
    # Consulta DNS forzada a Google para bypass de tu red
    asn_raw=$(dig +short "${rev_ip}.origin.asn.cymru.com" TXT @8.8.8.8 2>/dev/null | tr -d '"')
    asn=$(echo "$asn_raw" | awk -F'|' '{print $1}' | xargs)
    
    if [[ -z "$asn" ]]; then
        echo "    [!] No se obtuvo ASN para $ip (Cymru vacío)"
        asn="0"
    else
        echo "    [✓] ASN detectado: $asn"
    fi
    
    # Inyectar al JSON temporal
    jq --arg h "$host" --arg a "$asn" '. + {($h): $a}' "$OP_DIR/asn.json" > "$OP_DIR/asn.json.tmp" && mv "$OP_DIR/asn.json.tmp" "$OP_DIR/asn.json"
done

echo "[+] TRACKING ASN: Finalizado. Contenido: $(cat "$OP_DIR/asn.json")"

# =========================
# 6. BUILD FINAL JSON
# =========================
echo "[+] Consolidando lowNoice.json final..."
OUTPUT_JSON="$OP_DIR/lowNoice.json"

jq -n \
  --arg target "$TARGET" \
  --slurpfile dns "$OP_DIR/dns.json" \
  --slurpfile vivos "$OP_DIR/vivos.json" \
  --slurpfile analisis "$OP_DIR/analisis.json" \
  --slurpfile asn "$OP_DIR/asn.json" '
{
  ($target): {
    subdomains: [
      ($dns[0] | keys[]) as $host |
      {
        host: $host,
        ip: $dns[0][$host],
        url: ($vivos[0][$host] // ""),
        alive: ($vivos[0][$host] != null),
        cdn: ($analisis[0][$host].cdn // "none"),
        asn: ($asn[0][$host] // "0"),
        status: (
          if (
            (($analisis[0][$host].cdn // "none") != "none")
            or
            (($asn[0][$host] // "0") | tostring | test("^(13335|15169|16509|16625|8075)$"))
          )
          then "protected"
          else "exposed"
          end
        )
      }
    ]
  }
}
' > "$OUTPUT_JSON"

echo "[✓] PROCESO COMPLETADO."
