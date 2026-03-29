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

 ´´´git clone [https://github.com/tu-usuario/radar.git](https://github.com/tu-usuario/radar.git)
   cd radar ´´´

### Requieremnts :

´bash´

-> then install this dependencies

´nmap jq curl whois whatweb searchsploit dnsx sed awk httpx-toolkit dig subfinder assetfinder´

### Then execute the installer

´´´chmod +x install.sh
   ./install.sh
´´´

## To use it use the command: 

´radar´

eg:

´radar nmap.scanme.org´ (the script is gonna ask u for sude when necesary)

its results is gonna be stored in ´/results/ ´ using the target name in json format

eg:

´´
results/
└── nmap.scanme.org/
    ├── http.json
    ├── ports.json
    ├── dns.json
    └── master_report.json
´´
