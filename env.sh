#!/bin/bash
# env.sh - Central de Rutas Universales

# Detecta la raíz real del proyecto
export RADAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# mapa de carpetas
export MODULES_DIR="$RADAR_ROOT/modules"
export PROCESSORS_DIR="$RADAR_ROOT/processors"
export UI_DIR="$RADAR_ROOT/ui"
export RESULTS_BASE="$RADAR_ROOT/results"
export DEPENDENCIES=(nmap jq curl whois whatweb searchsploit dnsx sed awk httpx-toolkit dig subfinder assetfinder)





GREEN='\e[32m'
RED='\e[31m'
YELLOW='\e[33m'
CYAN='\e[36m'
NC='\e[0m'

log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_error() { echo -e "${RED}[-] ERROR: $1${NC}"; }
log_info() { echo -e "${CYAN}[*] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }


# Exportamos las funciones para que los sub-procesos las vean
export -f log_success
export -f log_error
export -f log_info
export -f log_warn


show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    _______  _______  ______   _______  _______ 
   (  ____ )(  ___  )(  __  \ (  ___  )(  ____ )
   | (    )|| (   ) || (  \  )| (   ) || (    )|
   | (____)|| (___) || |   ) || (___) || (____)|
   |     __)|  ___  || |   | ||  ___  ||  __  )
   | (\ (   | (   ) || |   ) || (   ) || (  \  )
   | ) \ \__| )   ( || (__/  )| )   ( || )   \ \
   |/   \__/|/     \|(______/ |/     \||/     \|
EOF
    echo -e "${NC}          [ Low-Noise Reconnaissance Framework ]"
    echo -e "${YELLOW}------------------------------------------------------------${NC}"
}


