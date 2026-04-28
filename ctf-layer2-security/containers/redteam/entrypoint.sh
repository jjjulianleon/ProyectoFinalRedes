#!/bin/bash
# Red Team entrypoint - Configura agente Wazuh HIDS y mantiene el contenedor activo

echo '[RedTeam] Configurando agente Wazuh HIDS...'
MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed "s/MANAGER_IP/${MANAGER_IP}/g; s/AGENT_NAME/$(hostname)/g" \
    /var/ossec/etc/ossec.conf > /tmp/ossec_rendered.conf && \
    mv /tmp/ossec_rendered.conf /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1514" 2>/dev/null; do sleep 2; done
sleep 10
/var/ossec/bin/wazuh-agentd -f &
sleep 3
echo '[RedTeam] Agente Wazuh arrancado. Listo para atacar.'

exec tail -f /dev/null
