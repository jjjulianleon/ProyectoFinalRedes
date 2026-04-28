#!/bin/bash
# Blue Team entrypoint - Configura agente Wazuh HIDS y mantiene el contenedor activo

echo '[BlueTeam] Configurando agente Wazuh HIDS...'

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

MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed "s/MANAGER_IP/${MANAGER_IP}/g; s/AGENT_NAME/$(hostname)/g" \
    /var/ossec/etc/ossec.conf > /tmp/ossec_rendered.conf && \
    mv /tmp/ossec_rendered.conf /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1514" 2>/dev/null; do sleep 2; done
sleep 10
# Arrancar todos los daemons: agentd, logcollector, modulesd, syscheckd
/var/ossec/bin/wazuh-agentd -f &
sleep 5
/var/ossec/bin/wazuh-logcollector -f &
/var/ossec/bin/wazuh-modulesd &
/var/ossec/bin/wazuh-syscheckd &
sleep 2
echo '[BlueTeam] Agente Wazuh arrancado (agentd + logcollector + modulesd + syscheckd). Listo para defender.'

exec tail -f /dev/null
