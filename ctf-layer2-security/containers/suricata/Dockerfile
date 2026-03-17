# Suricata - Motor NIDS (Network Intrusion Detection System)
# Inspecciona trafico de red en modo promiscuo para detectar
# patrones de ARP Spoofing y MAC Flooding a nivel de Capa 2
FROM jasonish/suricata:7.0

# Copiar configuracion y reglas custom
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/ /var/lib/suricata/rules/

# Directorio para logs
RUN mkdir -p /var/log/suricata

# Suricata corre en modo AF_PACKET capturando trafico de la interfaz eth0
# que esta conectada a la red bridge del CTF
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "--af-packet=eth0", "-v"]
