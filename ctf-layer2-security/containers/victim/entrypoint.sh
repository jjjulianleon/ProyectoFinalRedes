#!/bin/bash
# Victim entrypoint - Lanza el servicio HTTP correspondiente segun VICTIM_ID

echo "[Victim-${VICTIM_ID}] Iniciando host victima..."
echo "[Victim-${VICTIM_ID}] IP: $(hostname -I)"

# Configurar y arrancar agente Wazuh HIDS
sed -i "s/MANAGER_IP/${WAZUH_MANAGER_IP:-172.20.0.240}/g" /var/ossec/etc/ossec.conf
sed -i "s/AGENT_NAME/$(hostname)/g" /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-control start &>/dev/null &
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
