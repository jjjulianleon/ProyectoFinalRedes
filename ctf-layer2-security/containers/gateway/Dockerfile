# Gateway/Router - Imagen ligera Alpine
# Simula el gateway de una red corporativa
# IP forwarding se habilita via sysctls en docker-compose.yml
FROM alpine:3.19

# Instalamos herramientas de red basicas para diagnostico
RUN apk add --no-cache \
    iproute2 \
    iputils \
    iptables \
    tcpdump \
    net-tools \
    bash

# Script de inicio que configura el gateway
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
