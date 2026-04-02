```bash
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
    echo -e "${NC}          [ Version 1.0 - Pure Bash ]\n"
}# clone the repository:

Identificación de "Ruidosos" vs "Silenciosos"

En tu arquitectura actual, podrías clasificar las tareas así:
Tarea	Tipo	Riesgo	¿Necesita Cola?
dnsx / subfinder	Red	Baneo de IP / Saturación Router	Sí (Media)
WhatWeb / HTTP	Red	WAF / Bloqueo por User-Agent	Sí (Alta/Stealth)
Searchsploit	Local	Saturación de CPU / Disco	Sí (Baja - Concurrencia 10-20)
