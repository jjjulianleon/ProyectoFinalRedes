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
    lsb-release \
    adduser \
    && rm -rf /var/lib/apt/lists/*

# Instalar agente Wazuh HIDS 4.9.2
# policy-rc.d evita que dpkg intente arrancar el servicio con systemctl (no hay systemd en Docker)
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && curl -sL https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb \
      -o /tmp/wazuh-agent.deb \
    && dpkg -i /tmp/wazuh-agent.deb \
    && rm /tmp/wazuh-agent.deb /usr/sbin/policy-rc.d

# Sobrescribir config por defecto con la config del CTF
COPY agent-ossec.conf /var/ossec/etc/ossec.conf

# Directorio para scripts defensivos
RUN mkdir -p /tools /logs

COPY tools/ /tools/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
WORKDIR /tools

ENTRYPOINT ["/entrypoint.sh"]
