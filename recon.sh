#!/bin/bash

# IMPORTAR RUTAS (Subimos un nivel desde /modules para encontrar env.sh)
source "$(dirname "$0")/env.sh"
# --- TARGETING ---
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "❌ Error: No se especificó un objetivo."
    echo "Uso: radar <target>"
    exit 1
fi

# Definimos la carpeta específica para este escaneo
export OUTPUT_DIR="$RESULTS_BASE/$TARGET"
mkdir -p "$OUTPUT_DIR"

echo "📡 Radar Operativo | Target: $TARGET"
echo "📂 Resultados en: $TARGET_RESULTS"


echo "[FASE 1] Low Noise..."
bash "$MODULES_DIR/lowNoice.sh" "$TARGET"
echo ""
echo "[FASE 2] WHOIS sobre resultados..."
bash "$MODULES_DIR/whois.sh" "$TARGET"


echo "[FASE 3] Correlacion..."
bash "$MODULES_DIR/intel.sh" "$TARGET" 

echo "[FASE 4] Intervención manual requerida"

echo "[+] Targets EXPUESTOS detectados (sin CDN):"
EXPOSED_LIST=$(jq -r ".\"$TARGET\".subdomains[] | select(.status == \"exposed\") | .host" "$RESULTS_BASE/$TARGET/lowNoice.json")

if [[ -n "$EXPOSED_LIST" ]]; then
    echo "$EXPOSED_LIST" | nl -w2 -s'. '
else
    echo "[!] No se detectaron targets expuestos directamente."
fi

echo ""
read -p "Presioná ENTER para continuar con análisis manual..."

# ----------------------------------------------
echo "[FASE 5] Selección de objetivo"

DEFAULT_TARGET=$(echo "$EXPOSED_LIST" | head -n 1)

read -p "Ingresá URL o dominio [$DEFAULT_TARGET]: " SELECTED_URL

# Si el usuario le da ENTER, usamos el default. Si no hay default, usamos el TARGET original.
SELECTED_URL=${SELECTED_URL:-${DEFAULT_TARGET:-$TARGET}}

echo "[+] Objetivo seleccionado: $SELECTED_URL"

HOST=$(echo "$SELECTED_URL" | sed 's|http[s]*://||')

echo "[FASE 6] Identificando Tecnologías Web en $HOST..."
# Corremos WhatWeb antes de Nmap para saber a qué nos enfrentamos
bash "$MODULES_DIR/web_discovery.sh" "$HOST"

echo ""
echo "[!] Tecnologías detectadas podrían influir en el tipo de escaneo."
read -p "¿Ejecutar Nmap sobre $HOST? (y/n): " CONFIRM

if [[ "$CONFIRM" == "y" ]]; then
    echo "//------------------------------//"
    echo "[FASE 7] PORT SCAN (Nmap)"
    bash "$MODULES_DIR/ports.sh" "$HOST"
else
    echo "[INFO] Nmap cancelado."
fi

echo "[+] Generando reporte maestro final..."
bash "$PROCESSORS_DIR/merger.sh" "$TARGET"

echo "[FASE 8] Buscando Vulnerabilidades Conocidas..."

bash "$PROCESSORS_DIR/vulnerability_matcher.sh" "$TARGET"

bash "$UI_DIR/dashboard.sh" "$TARGET"



echo -e "\n--- [ OPERACIÓN COMPLETADA ] ---"
