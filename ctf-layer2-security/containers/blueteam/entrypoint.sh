#!/bin/bash
# Blue Team entrypoint - Configura agente Wazuh HIDS y mantiene el contenedor activo

echo '[BlueTeam] Configurando agente Wazuh HIDS...'
MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed -i "s/MANAGER_IP/${MANAGER_IP}/g" /var/ossec/etc/ossec.conf
sed -i "s/AGENT_NAME/$(hostname)/g" /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
/var/ossec/bin/wazuh-control start
echo '[BlueTeam] Agente Wazuh arrancado. Listo para defender.'

exec tail -f /dev/null
