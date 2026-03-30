FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
    curl jq bash sed gawk dnsutils whois \
    nmap whatweb exploitdb golang

ENV PATH="/root/go/bin:${PATH}"

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

WORKDIR /app

COPY . .

RUN find . -name "*.sh" -exec chmod +x {} +

ENTRYPOINT ["./recon.sh"]
