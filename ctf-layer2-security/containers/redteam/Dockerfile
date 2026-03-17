# Red Team - Kali Rolling con herramientas ofensivas
# Contenedor del atacante con Scapy, tcpdump y scripts custom
FROM kalilinux/kali-rolling

# Herramientas ofensivas y de red
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-scapy \
    tcpdump \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    arping \
    nmap \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Directorio para scripts ofensivos
RUN mkdir -p /tools /captures

COPY tools/ /tools/
WORKDIR /tools

# Mantener el contenedor corriendo
CMD ["bash", "-c", "echo '[RedTeam] Listo para atacar.' && tail -f /dev/null"]
