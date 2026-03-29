#!/bin/bash
# install.sh

# 1. IMPORTAMOS EL ENTORNO (Para usar las rutas y DEPS centralizadas)
# Si el env.sh está en la misma carpeta:
source "./env.sh"

# Sobrescribimos o usamos las rutas de env.sh para el despliegue
INSTALL_PATH="$HOME/.local/share/radar"
BIN_PATH="$HOME/.local/bin/radar"

echo -e "${YELLOW}🚀 Iniciando instalación de Radar...${NC}"

# 2. CHEQUEO DE DEPENDENCIAS (Usando el array de env.sh)
check_deps() {
    echo -e "\n[*] Verificando herramientas de sistema..."
    MISSING_DEPS=()

    # Usamos "${DEPS[@]}" que viene de env.sh
    for cmd in "${DEPS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            MISSING_DEPS+=("$cmd")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
        log_error "Faltan las siguientes dependencias:"
        for dep in "${MISSING_DEPS[@]}"; do
            echo -e "    - $dep"
        done
        echo -e "\n${YELLOW}👉 Instalas con: pacman -S o tu AUR helper.${NC}"
        # Decidí si querés que el script se detenga (exit 1) o siga.
    else
        log_success "Todas las dependencias están presentes."
    fi
}

deploy_radar() {
    log_info "Desplegando archivos en $INSTALL_PATH..."
    mkdir -p "$INSTALL_PATH"
    mkdir -p "$HOME/.local/bin"

    # Copiamos el proyecto (excluyendo basura si querés ser fino)
    cp -r . "$INSTALL_PATH"

    # Permisos de ejecución
    find "$INSTALL_PATH" -name "*.sh" -exec chmod +x {} \;

    # Link simbólico
    ln -sf "$INSTALL_PATH/recon.sh" "$BIN_PATH"
}

# --- EJECUCIÓN ---
check_deps
deploy_radar

echo -e "\n${GREEN}============================================"
echo -e "✅ RADAR INSTALADO CORRECTAMENTE"
echo -e "👉 Comando: radar <target>"
echo -e "⚠️  Asegurate que $HOME/.local/bin esté en tu PATH"
echo -e "============================================${NC}"
