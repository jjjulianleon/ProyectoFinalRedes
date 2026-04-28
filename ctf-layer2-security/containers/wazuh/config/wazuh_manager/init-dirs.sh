#!/usr/bin/with-contenv bash
# Create directories and files required by wazuh-analysisd on clean volume boots
YEAR=$(date +%Y)
MONTH=$(date +%b)

for dir in archives alerts firewall; do
    mkdir -p /var/ossec/logs/${dir}/${YEAR}/${MONTH}
    chown -R wazuh:wazuh /var/ossec/logs/${dir} 2>/dev/null || true
done

touch /var/ossec/logs/active-responses.log 2>/dev/null || true
chown wazuh:wazuh /var/ossec/logs/active-responses.log 2>/dev/null || true

# ar.conf must exist before analysisd starts
mkdir -p /var/ossec/etc/shared/default
touch /var/ossec/etc/shared/ar.conf
chown wazuh:wazuh /var/ossec/etc/shared/ar.conf
