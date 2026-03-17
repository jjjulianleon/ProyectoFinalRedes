#!/bin/bash
###############################################################################
# Configuración de integración Wazuh + Suricata
# Agrega Suricata como fuente de logs en Wazuh Manager
# Y copia las reglas custom de detección L2
###############################################################################

GREEN='\033[0;32m'
NC='\033[0m'

step() {
    echo -e "${GREEN}[>] $1${NC}"
}

echo ""
echo "============================================================"
echo "  Configuración Wazuh + Suricata Integration"
echo "============================================================"
echo ""

# ============================================================
# 1. Agregar Suricata como localfile en ossec.conf
# ============================================================
step "Configurando Wazuh Manager para leer logs de Suricata..."

# Verificar si ya está configurado
if docker exec wazuh-manager grep -q "suricata" /var/ossec/etc/ossec.conf 2>/dev/null; then
    echo "  [*] Ya configurado, saltando..."
else
    # Agregar bloque localfile antes del cierre de ossec_config
    docker exec wazuh-manager bash -c 'cat >> /var/ossec/etc/ossec.conf << "XMLEOF"

  <!-- Suricata NIDS - Lectura de alertas EVE JSON -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/suricata/eve.json</location>
  </localfile>

XMLEOF'
    echo "  [+] Localfile de Suricata agregado a ossec.conf"
fi

# ============================================================
# 2. Copiar reglas custom de Wazuh para alertas de Capa 2
# ============================================================
step "Copiando reglas custom de Wazuh..."

# Verificar si las reglas ya existen
if docker exec wazuh-manager test -f /var/ossec/etc/rules/layer2_rules.xml 2>/dev/null; then
    echo "  [*] Reglas ya existen, actualizando..."
fi

docker exec wazuh-manager bash -c 'cat > /var/ossec/etc/rules/layer2_rules.xml << "XMLEOF"
<!-- Reglas Wazuh Custom - Deteccion de Ataques de Capa 2 -->
<!-- Procesa alertas de Suricata (eve.json) y scripts Blue Team -->

<group name="layer2,suricata,">

  <!-- Alerta de Suricata: ARP Reply detectado -->
  <rule id="100010" level="5">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>ARP Reply detectado</match>
    <description>Suricata: ARP Reply detectado - posible ARP Spoofing</description>
    <group>arp_spoofing,</group>
  </rule>

  <!-- Alerta de Suricata: Alto volumen de ARP Replies -->
  <rule id="100011" level="10">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>Alto volumen de ARP Replies</match>
    <description>Suricata: ARP Spoofing en progreso - alto volumen de ARP Replies</description>
    <group>arp_spoofing,</group>
  </rule>

  <!-- Alerta de Suricata: Suplantacion de Gateway -->
  <rule id="100012" level="14">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>suplantando IP del Gateway</match>
    <description>Suricata: CRITICO - ARP Spoofing suplantando IP del Gateway</description>
    <group>arp_spoofing,</group>
  </rule>

  <!-- Alerta de Suricata: Posible MAC Flooding -->
  <rule id="100013" level="10">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>posible MAC Flooding</match>
    <description>Suricata: Volumen anomalo de paquetes - posible MAC Flooding</description>
    <group>mac_flooding,</group>
  </rule>

  <!-- Alerta de Suricata: Flag en trafico HTTP -->
  <rule id="100020" level="12">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>Flag detectada en trafico HTTP</match>
    <description>Suricata: Flag del CTF detectada transitando en texto plano</description>
    <group>data_leak,</group>
  </rule>

  <!-- Alerta de Suricata: Credenciales en texto plano -->
  <rule id="100021" level="12">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <match>Credenciales en texto plano</match>
    <description>Suricata: Credenciales/tokens detectados en trafico sin cifrar</description>
    <group>data_leak,</group>
  </rule>

</group>
XMLEOF'
echo "  [+] Reglas layer2_rules.xml creadas"

# ============================================================
# 3. Reiniciar Wazuh Manager para aplicar cambios
# ============================================================
step "Reiniciando Wazuh Manager..."
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart 2>/dev/null
sleep 5

# Verificar que inició correctamente
if docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "running"; then
    echo "  [+] Wazuh Manager corriendo correctamente"
else
    echo "  [!] Verificando estado..."
    docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null
fi

# ============================================================
# 4. Verificar integración
# ============================================================
step "Verificando integración..."

# Verificar que el archivo de logs de Suricata es accesible
if docker exec wazuh-manager test -f /var/ossec/logs/suricata/eve.json 2>/dev/null; then
    echo "  [+] Logs de Suricata accesibles desde Wazuh Manager"
else
    echo "  [-] Logs de Suricata no encontrados (se generarán al ejecutar el CTF)"
fi

# Verificar reglas cargadas
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest -t 2>/dev/null | grep -i "rule\|error" | head -5 || true

echo ""
echo "============================================================"
echo "  Integración Wazuh + Suricata configurada"
echo "============================================================"
echo ""
echo "  Las alertas de Suricata se procesan en Wazuh como:"
echo "    - Rule 100010-100012: Detección de ARP Spoofing"
echo "    - Rule 100013:        Detección de MAC Flooding"
echo "    - Rule 100020-100021: Datos sensibles en texto plano"
echo ""
echo "  Dashboard: https://localhost:5601 (admin/SecretPassword)"
echo ""
