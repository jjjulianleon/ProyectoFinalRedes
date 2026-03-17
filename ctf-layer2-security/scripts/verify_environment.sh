#!/bin/bash
###############################################################################
# Verificación del Entorno CTF Layer 2 Security
# Comprueba que todos los contenedores, servicios y conectividad estén OK
###############################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PASS=0
FAIL=0

check() {
    local description="$1"
    local command="$2"

    if eval "$command" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[✓]${NC} $description"
        ((PASS++))
    else
        echo -e "  ${RED}[✗]${NC} $description"
        ((FAIL++))
    fi
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Verificación del Entorno CTF Layer 2 Security${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# ============================================================
# 1. Contenedores corriendo
# ============================================================
echo -e "${BOLD}[1/5] Contenedores Docker${NC}"
CONTAINERS="gateway victim1 victim2 victim3 redteam blueteam ctfd ctfd-db ctfd-cache wazuh-indexer wazuh-manager wazuh-dashboard suricata"
for c in $CONTAINERS; do
    check "$c corriendo" "docker inspect -f '{{.State.Running}}' $c 2>/dev/null | grep -q true"
done
echo ""

# ============================================================
# 2. Conectividad entre hosts
# ============================================================
echo -e "${BOLD}[2/5] Conectividad de Red${NC}"
check "redteam -> gateway (172.20.0.2)" "docker exec redteam ping -c 1 -W 2 172.20.0.2"
check "redteam -> victim1 (172.20.0.10)" "docker exec redteam ping -c 1 -W 2 172.20.0.10"
check "redteam -> victim2 (172.20.0.11)" "docker exec redteam ping -c 1 -W 2 172.20.0.11"
check "redteam -> victim3 (172.20.0.12)" "docker exec redteam ping -c 1 -W 2 172.20.0.12"
check "blueteam -> gateway (172.20.0.2)" "docker exec blueteam ping -c 1 -W 2 172.20.0.2"
echo ""

# ============================================================
# 3. Servicios HTTP de víctimas
# ============================================================
echo -e "${BOLD}[3/5] Servicios HTTP de Víctimas${NC}"
check "victim1 HTTP (flag en HTML)" "docker exec redteam curl -s http://172.20.0.10 | grep -q 'Portal Corporativo'"
check "victim2 HTTP (file server)" "docker exec redteam curl -s http://172.20.0.11 | grep -q 'Servidor de Archivos'"
check "victim3 HTTP (monitoring agent)" "docker exec redteam curl -s http://172.20.0.12 | grep -q 'Agente de Monitoreo'"
echo ""

# ============================================================
# 4. Plataformas de seguridad
# ============================================================
echo -e "${BOLD}[4/5] Plataformas${NC}"
check "CTFd accesible (puerto 8000)" "docker exec redteam curl -s -o /dev/null -w '%{http_code}' http://172.20.0.250:8000 | grep -qE '200|302'"
check "Wazuh Dashboard (puerto 5601)" "docker exec redteam curl -sk -o /dev/null -w '%{http_code}' https://172.20.0.242:5601 | grep -qE '200|302'"
check "Suricata corriendo" "docker exec suricata suricata --build-info > /dev/null 2>&1"
echo ""

# ============================================================
# 5. Scripts en contenedores
# ============================================================
echo -e "${BOLD}[5/5] Scripts Disponibles${NC}"
check "Red Team: arp_spoof.py" "docker exec redteam test -f /tools/arp_spoof.py"
check "Red Team: mac_flood.py" "docker exec redteam test -f /tools/mac_flood.py"
check "Red Team: capture_flags.py" "docker exec redteam test -f /tools/capture_flags.py"
check "Red Team: submit_flag.py" "docker exec redteam test -f /tools/submit_flag.py"
check "Blue Team: arp_monitor.py" "docker exec blueteam test -f /tools/arp_monitor.py"
check "Blue Team: mac_anomaly_detector.py" "docker exec blueteam test -f /tools/mac_anomaly_detector.py"
check "Blue Team: arp_restore.py" "docker exec blueteam test -f /tools/arp_restore.py"
echo ""

# ============================================================
# Resumen
# ============================================================
TOTAL=$((PASS + FAIL))
echo -e "${BOLD}============================================================${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}RESULTADO: $PASS/$TOTAL verificaciones exitosas${NC}"
    echo -e "  ${GREEN}El entorno está listo para la ejecución del CTF${NC}"
else
    echo -e "  ${YELLOW}${BOLD}RESULTADO: $PASS/$TOTAL verificaciones exitosas ($FAIL fallidas)${NC}"
    echo -e "  ${YELLOW}Revisa los items marcados con [✗] antes de continuar${NC}"
fi
echo -e "${BOLD}============================================================${NC}"
echo ""
