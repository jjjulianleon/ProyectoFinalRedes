#!/bin/bash
# Blue Team entrypoint - Configura agente Wazuh HIDS y mantiene el contenedor activo

echo '[BlueTeam] Configurando agente Wazuh HIDS...'
sed -i "s/MANAGER_IP/${WAZUH_MANAGER_IP:-172.20.0.240}/g" /var/ossec/etc/ossec.conf
sed -i "s/AGENT_NAME/$(hostname)/g" /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-control start &>/dev/null &
echo '[BlueTeam] Agente Wazuh arrancado. Listo para defender.'

exec tail -f /dev/null
