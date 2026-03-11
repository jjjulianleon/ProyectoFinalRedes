# Blue Team - Kali Rolling con herramientas defensivas
# Contenedor del defensor con Scapy, herramientas de analisis
FROM kalilinux/kali-rolling

# Herramientas defensivas y de analisis
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-scapy \
    tcpdump \
    tshark \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    arping \
    && rm -rf /var/lib/apt/lists/*

# Directorio para scripts defensivos
RUN mkdir -p /tools /logs

COPY tools/ /tools/
WORKDIR /tools

# Mantener el contenedor corriendo
CMD ["bash", "-c", "echo '[BlueTeam] Listo para defender.' && tail -f /dev/null"]
