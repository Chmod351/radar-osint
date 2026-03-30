FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    jq \
    nmap \
    whois \
    whatweb \
    exploitdb \
    dnsx \
    sed \
    awk \
    httpx-toolkit \
    dnsutils \
    subfinder \
    assetfinder \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN find . -name "*.sh" -exec chmod +x {} +

ENTRYPOINT ["./recon.sh"]
