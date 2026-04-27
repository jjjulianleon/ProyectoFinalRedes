# Victim - Imagen Python slim
# Hosts con servicios HTTP vulnerables y flags ocultas
FROM python:3.11-slim

ARG VICTIM_ID=1

# Herramientas de red para diagnostico y monitoreo
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    curl \
    lsb-release \
    adduser \
    && rm -rf /var/lib/apt/lists/*

# requests es necesario para victim3 (envio de reportes al gateway)
RUN pip3 install --no-cache-dir requests

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

# Directorio de trabajo para servicios y flags
RUN mkdir -p /app /flags

# Copiar todos los servicios HTTP (el entrypoint selecciona el correcto)
COPY services/ /app/services/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
