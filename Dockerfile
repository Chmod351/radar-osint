FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive


RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

RUN apt-get update && apt-get upgrade -y

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    bash \
    curl \
    jq \
    sed \
    gawk \
    dnsutils \
    whois \
    nmap \
    whatweb \
    exploitdb \
    # Herramientas de ProjectDiscovery (Nativas de Kali)
    subfinder \
    httpx-toolkit \
    dnsx \
    assetfinder \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN find . -name "*.sh" -exec chmod +x {} +

USER root

ENTRYPOINT ["./recon.sh"]
