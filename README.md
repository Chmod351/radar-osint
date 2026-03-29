```bash
  _______  _______  ______   _______  _______ 
 (  ____ )(  ___  )(  __  \ (  ___  )(  ____ )
 | (    )|| (   ) || (  \  )| (   ) || (    )|
 | (____)|| (___) || |   ) || (___) || (____)|
 |     __)|  ___  || |   | ||  ___  ||  __  )
 | (\ (   | (   ) || |   ) || (   ) || (  \  )
 | ) \ \__| )   ( || (__/  )| )   ( || )   \ \
 |/   \__/|/     \|(______/ |/     \||/     \|

```

#   Clone the repository:
```git clone [https://github.com/tu-usuario/radar.git](https://github.com/tu-usuario/radar.git) cd radar```

### Requieremnts :

```bash```

-> then install this dependencies
```nmap jq curl whois whatweb searchsploit dnsx sed awk httpx-toolkit dig subfinder assetfinder```



# ⚠️ DEPENDENCY NOTICE

The RADAR framework relies on external tools that must be installed on your system. Package names can vary significantly depending on your Linux distribution.
Critical Package Mappings:
Tool	Arch Linux (Pacman/AUR)	Debian / Ubuntu / Kali
dig	bind	dnsutils
httpx	httpx-bin	httpx-toolkit
dnsx	dnsx-bin	dnsx
searchsploit	exploitdb	exploitdb
whois	whois	whois

`IMPORTANT: If your distribution cannot find a specific package, search for the binary name. The installer checks for the command's existence in your $PATH, not the distribution's package name.`

    
### Then execute the installer

```chmod +x install.sh  ./install.sh```

## To use it use the command: 

```radar```

eg:

```radar nmap.scanme.org``` (the script is gonna ask u for sude when necesary)

its results is gonna be stored in ```/results/``` using the target name in json format

eg:

```
results/
└── nmap.scanme.org/
    ├── http.json
    ├── ports.json
    ├── dns.json
    └── master_report.json
```
