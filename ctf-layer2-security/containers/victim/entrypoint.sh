#!/bin/bash
# Victim entrypoint - Lanza el servicio HTTP correspondiente segun VICTIM_ID

echo "[Victim-${VICTIM_ID}] Iniciando host victima..."
echo "[Victim-${VICTIM_ID}] IP: $(hostname -I)"

# Configurar y arrancar agente Wazuh HIDS
MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed "s/MANAGER_IP/${MANAGER_IP}/g; s/AGENT_NAME/$(hostname)/g" \
    /var/ossec/etc/ossec.conf > /tmp/ossec_rendered.conf && \
    mv /tmp/ossec_rendered.conf /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1514" 2>/dev/null; do sleep 2; done
sleep 10
# Foreground con & es más robusto en contenedores sin systemd
/var/ossec/bin/wazuh-agentd -f &
sleep 3
echo "[Victim-${VICTIM_ID}] Agente Wazuh arrancado."

case "${VICTIM_ID}" in
    1)
        echo "[Victim-1] Lanzando servidor HTTP con flag en comentario HTML"
        exec python3 /app/services/http_server_v1.py
        ;;
    2)
        echo "[Victim-2] Lanzando file server con flag en archivo"
        exec python3 /app/services/http_server_v2.py
        ;;
    3)
        echo "[Victim-3] Lanzando agente de monitoreo con flag en reportes"
        exec python3 /app/services/http_server_v3.py
        ;;
    *)
        echo "[Victim-${VICTIM_ID}] ID no reconocido, lanzando servidor basico"
        exec python3 -m http.server 80 --directory /app
        ;;
esac
