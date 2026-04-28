# Guía Rápida — CTF Layer 2 Security

## 1. Requisitos previos

```bash
# Verificar Docker
docker --version        # >= 24
docker compose version  # >= 2

# Ajuste de memoria para Wazuh Indexer (OpenSearch)
sudo sysctl -w vm.max_map_count=262144
```

---

## 2. Levantar el entorno

```bash
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security

docker compose up -d --build
```

Esperar ~2 minutos. Verificar que todo esté corriendo:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Deben aparecer **13 contenedores** con status `Up`.

---

## 3. Verificación rápida

```bash
# Agentes HIDS registrados (deben aparecer 5)
docker exec wazuh-manager /var/ossec/bin/manage_agents -l

# Alertas NIDS activas
docker exec suricata grep -c '"event_type":"alert"' /var/log/suricata/eve.json

# Flag accesible en victim1
docker exec redteam curl -s http://172.20.0.10 | grep -o 'FLAG{[^}]*}'
```

---

## 4. Ejecutar la demo completa (automático)

```bash
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security
sudo bash scripts/run_ctf_demo.sh
```

El script ejecuta en secuencia: captura de tráfico → monitoreo Blue Team → ARP Spoofing → captura de flags → MAC Flooding → restauración ARP → recolección de evidencia.

---

## 5. Demo manual paso a paso

### Red Team — atacar

```bash
docker exec -it redteam bash

# ARP Spoofing MITM entre victim1 y gateway
python3 /tools/arp_spoof.py -t 172.20.0.10 -g 172.20.0.2 --interval 1 --broadcast

# En otra terminal: capturar flags en tráfico
docker exec -it redteam bash
python3 /tools/capture_flags.py

# MAC Flooding
python3 /tools/mac_flood.py -c 2000 --delay 0.001

# Enviar flag capturada a CTFd
python3 /tools/submit_flag.py -f "FLAG{arp_spoof_mitm_captured}" -c 1 -u redteam -p redteam123
```

### Blue Team — defender

```bash
docker exec -it blueteam bash

# Detectar ARP Spoofing en tiempo real
python3 /tools/arp_monitor.py --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12 --probe-interval 3

# Detectar MAC Flooding
python3 /tools/mac_anomaly_detector.py --learning-time 10

# Restaurar tablas ARP envenenadas
python3 /tools/arp_restore.py --count 5
```

---

## 6. Dashboards

| Dashboard | URL | Credenciales |
|---|---|---|
| CTFd (plataforma CTF) | http://localhost:8000 | admin / admin123 |
| Wazuh (SIEM/alertas) | https://localhost:5601 | admin / SecretPassword |

### Wazuh — qué revisar

1. **Agents** → ver los 5 agentes en verde (`victim1/2/3`, `redteam`, `blueteam`)
2. **Threat Intelligence → Events** → filtrar por `rule.groups: suricata` → ver alertas en tiempo real
3. **Security Events** → buscar `ARP` o `FLAG` → ver detecciones de Suricata procesadas por Wazuh

### CTFd — qué revisar

1. Ir a **Challenges** → ver los 6 retos disponibles
2. Registrar equipo → resolver challenges → ver **Scoreboard** en tiempo real

---

## 7. Red y contenedores

| Contenedor | IP | Rol |
|---|---|---|
| gateway | 172.20.0.2 | Router de la red |
| victim1 | 172.20.0.10 | Flag en comentario HTML |
| victim2 | 172.20.0.11 | Flag en archivo de credenciales |
| victim3 | 172.20.0.12 | Flag en reportes periódicos HTTP |
| redteam | 172.20.0.100 | Atacante |
| blueteam | 172.20.0.200 | Defensor |
| wazuh-manager | 172.20.0.240 | SIEM central |
| suricata | (gateway) | NIDS |
| ctfd | 172.20.0.250 | Plataforma CTF |

---

## 8. Apagar el entorno

```bash
# Apagar sin borrar datos
docker compose down

# Apagar y borrar todo (volumes incluidos)
docker compose down -v
```
