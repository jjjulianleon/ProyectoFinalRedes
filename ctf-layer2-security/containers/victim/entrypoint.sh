#!/bin/bash
# Victim entrypoint - Lanza el servicio HTTP correspondiente segun VICTIM_ID

echo "[Victim-${VICTIM_ID}] Iniciando host victima..."
echo "[Victim-${VICTIM_ID}] IP: $(hostname -I)"

# Script de conteo ARP con categorizacion (para deteccion de MAC Flooding via <match>)
cat > /usr/local/bin/arp-count-status.sh << 'SCRIPT'
#!/bin/sh
COUNT=$(arp -n 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
if [ "$COUNT" -ge 100 ]; then
    echo "MAC_FLOOD_CRITICAL:count=$COUNT"
elif [ "$COUNT" -ge 20 ]; then
    echo "MAC_FLOOD_WARNING:count=$COUNT"
else
    echo "ARP_NORMAL:count=$COUNT"
fi
SCRIPT
chmod +x /usr/local/bin/arp-count-status.sh

# Script de deteccion de cambio de MAC del gateway (reemplaza check_diff)
cat > /usr/local/bin/gw-mac-check.sh << 'SCRIPT'
#!/bin/sh
NEW=$(arp -n 2>/dev/null | grep 172.20.0.2 | awk '{print $3}')
OLD=$(cat /tmp/.gw_mac_baseline 2>/dev/null)
echo "$NEW" > /tmp/.gw_mac_baseline
if [ -z "$OLD" ]; then
    echo "MAC_BASELINE:$NEW"
elif [ "$NEW" = "$OLD" ]; then
    echo "MAC_STABLE:$NEW"
else
    echo "MAC_CHANGED:old=$OLD new=$NEW"
fi
SCRIPT
chmod +x /usr/local/bin/gw-mac-check.sh

# Configurar y arrancar agente Wazuh HIDS
MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed "s/MANAGER_IP/${MANAGER_IP}/g; s/AGENT_NAME/$(hostname)/g" \
    /var/ossec/etc/ossec.conf > /tmp/ossec_rendered.conf && \
    mv /tmp/ossec_rendered.conf /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1514" 2>/dev/null; do sleep 2; done
sleep 10
# Arrancar todos los daemons: agentd (conexion/enrollment), logcollector
# (command monitors), modulesd (activo-pasivo checks), syscheckd (FIM)
/var/ossec/bin/wazuh-agentd -f &
sleep 5
/var/ossec/bin/wazuh-logcollector -f &
/var/ossec/bin/wazuh-modulesd &
/var/ossec/bin/wazuh-syscheckd &
sleep 2
echo "[Victim-${VICTIM_ID}] Agente Wazuh arrancado (agentd + logcollector + modulesd + syscheckd)."

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
