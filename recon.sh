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
echo "[FASE 3.5] Analisis de Headers..."
bash "$MODULES_DIR/http.sh" "$TARGET" 
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
echo -e "\n[FASE 5] Evaluación de Objetivos Expuestos"

# 1. Informamos al operador qué hay "en bolas" (sin CDN)
if [[ -n "$EXPOSED_LIST" ]]; then
    echo -e "\e[32m[+] Los siguientes activos se encontraron EXPUESTOS (Sin WAF/CDN):\e[0m"
    echo "$EXPOSED_LIST" | sed 's/^/  --> /'
else
    echo -e "\e[33m[!] No se detectaron activos expuestos directamente.\e[0m"
fi

echo -e "\n\e[1;37m[i] El análisis profundo se ejecutará sobre el objetivo raíz:\e[0m \e[36m$TARGET\e[0m"
read -p "Presioná ENTER para proseguir con el análisis manual..."

# 2. Normalizamos el HOST para las fases siguientes (Siempre el TARGET)
SELECTED_URL="$TARGET"
HOST=$(echo "$SELECTED_URL" | sed 's|http[s]*://||; s|/||g')

echo -e "\n[+] Objetivo en la mira: \e[1;32m$HOST\e[0m"
echo "[FASE 6] Identificando Tecnologías Web en $HOST..."
# Corremos WhatWeb antes de Nmap para saber a qué nos enfrentamos

read -p "¿Ejecutar Nmap sobre $HOST? (y/n): " CONFIRM

if [[ "$CONFIRM" == "y" ]]; then
    echo "//------------------------------//"
    echo "[FASE 7] PORT SCAN (Nmap)"
    bash "$MODULES_DIR/ports.sh" "$HOST"
else
    echo "[INFO] Nmap cancelado."
fi

bash "$MODULES_DIR/web_discovery.sh" "$HOST"

echo ""
echo "[+] Generando reporte maestro final..."
bash "$PROCESSORS_DIR/merger.sh" "$TARGET"

echo "[FASE 8] Buscando Vulnerabilidades Conocidas..."

bash "$PROCESSORS_DIR/vulnerability_matcher.sh" "$TARGET"

bash "$UI_DIR/dashboard.sh" "$TARGET"



echo -e "\n--- [ OPERACIÓN COMPLETADA ] ---"
