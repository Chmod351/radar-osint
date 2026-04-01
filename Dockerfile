FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive

# Repositorios y actualizaciones
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    bash curl jq dnsutils nmap whatweb ruby-full build-essential \
    subfinder httpx-toolkit dnsx assetfinder \
    && gem install resolv-replace \
    && rm -rf /var/lib/apt/lists/*

# --- INSTALACIÓN DE BUN ---
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

WORKDIR /app
COPY . .

# Instalamos las dependencias de tu proyecto (execa, etc.)
RUN bun install

RUN find . -name "*.sh" -exec chmod +x {} +
USER root
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["./recon.sh"]
