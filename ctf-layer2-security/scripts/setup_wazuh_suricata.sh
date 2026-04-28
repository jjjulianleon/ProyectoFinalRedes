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
# 2. Verificar reglas custom de Wazuh
# ============================================================
step "Verificando reglas custom de Wazuh..."

# Las reglas estan montadas desde el host via bind mount read-only:
#   containers/wazuh/rules/layer2_rules.xml -> /var/ossec/etc/rules/layer2_rules.xml
# NO se intenta sobreescribir: el archivo en el contenedor es :ro.

if docker exec wazuh-manager test -f /var/ossec/etc/rules/layer2_rules.xml 2>/dev/null; then
    RULE_COUNT=$(docker exec wazuh-manager grep -c '<rule id=' /var/ossec/etc/rules/layer2_rules.xml 2>/dev/null || echo 0)
    echo "  [+] Reglas layer2_rules.xml presentes ($RULE_COUNT reglas custom cargadas)"
    echo "      Rangos activos: 100001-100020 (HIDS), 100050-100056 (NIDS Suricata)"
else
    echo "  [!] Reglas no encontradas en /var/ossec/etc/rules/layer2_rules.xml"
fi

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
echo "  Reglas activas en Wazuh:"
echo "    - Rule 100001-100006: HIDS - Command monitors (ARP table, MAC gateway)"
echo "    - Rule 100010-100012: HIDS - File Integrity Monitoring (/flags, /files)"
echo "    - Rule 100020:        HIDS - Deteccion de herramientas de ataque"
echo "    - Rule 100050-100056: NIDS - Alertas de Suricata (eve.json)"
echo ""
echo "  Dashboard: https://localhost:5601 (admin/SecretPassword)"
echo ""
