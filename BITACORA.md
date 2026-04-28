# Bitácora del Proyecto - CTF Layer 2 Security

## Estado General
**Última actualización**: 2026-03-17
**Fase actual**: Fase 4 (Scripts Ofensivos)

---

## Fase 0: Prerequisitos
- [x] Docker instalado (v27.5.1)
- [x] Docker Compose instalado (v5.1.0)
- [x] Python 3 + Scapy disponibles
- [x] VM Kali con 8GB RAM asignados
- [x] Repositorio GitHub configurado (github.com/jjjulianleon/ProyectoFinalRedes)
- [x] Claude Code instalado

---

## Fase 1: Estructura del Proyecto + Docker Base
**Estado**: COMPLETADA

- [x] Estructura de directorios creada
- [x] Red bridge personalizada 172.20.0.0/24
- [x] Dockerfile gateway (Alpine, IP forwarding)
- [x] Dockerfile victims (Python slim)
- [x] Dockerfile redteam (Kali Rolling, Scapy, tcpdump)
- [x] Dockerfile blueteam (Kali Rolling, Scapy, tshark)
- [x] docker-compose.yml base con 6 contenedores
- [x] Conectividad verificada entre todos los contenedores
- [x] .gitignore configurado (excluye .env, PDFs, certs, capturas)

**IPs asignadas**:
| Contenedor | IP |
|---|---|
| Gateway | 172.20.0.2 |
| Victim 1 | 172.20.0.10 |
| Victim 2 | 172.20.0.11 |
| Victim 3 | 172.20.0.12 |
| Red Team | 172.20.0.100 |
| Blue Team | 172.20.0.200 |
| Suricata | 172.20.0.230 |
| Wazuh Manager | 172.20.0.240 |
| Wazuh Indexer | 172.20.0.241 |
| Wazuh Dashboard | 172.20.0.242 |
| CTFd | 172.20.0.250 |
| CTFd DB | 172.20.0.251 |
| CTFd Cache | 172.20.0.252 |

**Nota**: Gateway usa .2 porque Docker reserva .1 para la interfaz bridge del host.

---

## Fase 2: CTFd + Servicios Vulnerables + Flags
**Estado**: COMPLETADA

- [x] CTFd integrado al docker-compose (imagen ctfd/ctfd + MariaDB + Redis)
- [x] CTFd accesible en http://localhost:8000
- [x] Setup inicial de CTFd completado (Team Mode)
- [x] 6 challenges creados via API REST (setup_ctfd.py)
- [x] Victim 1: Servidor HTTP con flag en comentario HTML
- [x] Victim 2: File server con flag en /backup/db_credentials.txt
- [x] Victim 3: Agente de monitoreo que envía flag en texto plano al gateway cada 10s

**Challenges configurados**:
| # | Challenge | Categoría | Puntos |
|---|---|---|---|
| 1 | Hidden in Plain Sight | ARP Spoofing | 100 |
| 2 | Leaked Credentials | ARP Spoofing | 150 |
| 3 | Intercept the Report | Traffic Sniffing | 200 |
| 4 | Flood the Switch | MAC Flooding | 200 |
| 5 | Detect ARP Spoofing | Blue Team | 150 |
| 6 | Detect MAC Flooding | Blue Team | 150 |

---

## Fase 3: Wazuh + Suricata
**Estado**: COMPLETADA

### Wazuh
- [x] Certificados SSL generados (generador oficial wazuh/wazuh-certs-generator:0.0.2)
- [x] Wazuh Indexer desplegado y corriendo (1GB RAM, OpenSearch single-node)
- [x] opensearch.yml y internal_users.yml basados en config oficial 4.9.2
- [x] Wazuh Manager desplegado y corriendo (todos los módulos activos)
- [x] Filebeat conectado al indexer (SSL verification mode: none para lab)
- [x] Reglas custom de Capa 2 creadas (layer2_rules.xml)
- [x] Wazuh Dashboard funcional en https://localhost:5601 (admin/SecretPassword)

### Suricata
- [x] Dockerfile creado (jasonish/suricata:7.0)
- [x] suricata.yaml configurado (AF_PACKET, modo promiscuo, red 172.20.0.0/24)
- [x] Reglas custom de Capa 2 creadas (layer2.rules)
- [x] Contenedor corriendo y capturando tráfico

### Completado
- [x] Verificar detección de ARP Spoofing con reglas Suricata (1500+ alertas)
- [x] Verificar detección de MAC Flooding con reglas Suricata
- [x] Integrar alertas de Suricata con Wazuh (via volume suricata-logs)
- [x] Instalar agentes Wazuh HIDS en victim1/2/3, redteam, blueteam
- [x] Validar flujo completo de alertas end-to-end

---

## Fase 4: Scripts Ofensivos (Red Team)
**Estado**: COMPLETADA

- [x] arp_spoof.py - ARP Spoofing con Scapy (MITM) - verificado funcional
- [x] mac_flood.py - MAC Flooding con Scapy - verificado funcional
- [x] capture_flags.py - Sniffing y extracción de flags - verificado funcional
- [x] submit_flag.py - Envío automático a CTFd via API - fix aplicado (CookieJar + regex nonce)

---

## Fase 5: Scripts Defensivos (Blue Team)
**Estado**: COMPLETADA

- [x] arp_monitor.py - Monitor de ARP con Scapy - detecta spoofing en tiempo real
- [x] mac_anomaly_detector.py - Detector de MAC flooding - verificado funcional
- [x] arp_restore.py - Restaurador de tablas ARP - verificado funcional

---

## Fase 6: Ejecución del CTF
**Estado**: PENDIENTE

- [ ] Script de verificación del entorno
- [ ] Ejecutar ARP Spoofing -> capturar flags
- [ ] Ejecutar MAC Flooding -> observar comportamiento
- [ ] Blue Team detecta ataques (3 capas)
- [ ] Capturar tráfico con Wireshark/tshark
- [ ] Exportar logs de Wazuh y alertas de Suricata
- [ ] Generar reporte de resultados

---

## Fase 7: Documentación + Presentación
**Estado**: PENDIENTE

- [ ] Informe técnico final
- [ ] Capturas de Wireshark anotadas
- [ ] Análisis de logs Wazuh + alertas Suricata
- [ ] Recomendaciones de mitigación (DAI, Port Security, DHCP Snooping, 802.1X)
- [ ] Presentación con demo en vivo

---

## Problemas Encontrados y Soluciones

| Problema | Solución |
|---|---|
| Gateway IP conflicto con Docker bridge (.1) | Cambiado a 172.20.0.2 |
| docker-compose-plugin no disponible en Kali | Instalado manualmente via curl |
| Wazuh Indexer OOM con 512MB | Aumentado a 1GB (-Xms1g -Xmx1g) |
| cluster.initial_cluster_manager_nodes error | Eliminado (incompatible con single-node) |
| admin DN mismatch en opensearch | Corregido agregando L=Quito al DN |
| filebeat.yml permisos (uid!=0) | Entrypoint custom que copia con chown root |
| ossec.conf doble bloque global | Simplificado a un solo bloque |
| Suricata hostname + network_mode conflicto | Cambiado a red normal con IP estática |
| Kali pip3 externally-managed-environment | Ejecutado setup desde contenedor victim |
| Wazuh agents: Duplicate agent name al reiniciar | Se eliminan agentes viejos via API antes de rebuild; <force> va en el MANAGER (auth), NO en el agente |
| Agentes con keys obsoletas post-rebuild | Limpiar /var/ossec/etc/client.keys antes de reiniciar agentd |
| Victims sin NET_ADMIN/NET_RAW | Agregado cap_add a los 3 contenedores victim en docker-compose.yml |
| CTFd: no setup inicial al levantar | Automatizado via POST /setup + login + CSRF token en curl |

---

## Comandos Útiles

```bash
# Levantar todo el entorno
sudo sysctl -w vm.max_map_count=262144
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security
sudo docker compose up -d

# Ver estado de contenedores
sudo docker ps --format "table {{.Names}}\t{{.Status}}"

# Reconstruir y recrear
sudo docker compose down -v && sudo docker compose up -d --build

# Logs de un servicio
sudo docker logs <nombre_contenedor> 2>&1 | tail -20

# Accesos web
# CTFd: http://localhost:8000
# Wazuh Dashboard: https://localhost:5601 (admin / SecretPassword)

# Probar conectividad
sudo docker exec redteam ping -c 2 172.20.0.10
sudo docker exec redteam curl -s http://172.20.0.10
```
