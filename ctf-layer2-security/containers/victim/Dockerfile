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
    && rm -rf /var/lib/apt/lists/*

# requests es necesario para victim3 (envio de reportes al gateway)
RUN pip3 install --no-cache-dir requests

# Directorio de trabajo para servicios y flags
RUN mkdir -p /app /flags

# Copiar todos los servicios HTTP (el entrypoint selecciona el correcto)
COPY services/ /app/services/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
