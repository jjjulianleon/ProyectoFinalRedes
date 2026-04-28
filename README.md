# CTF Layer 2 Security Lab

Laboratorio de seguridad en red orientado a ataques y defensa de Capa 2 (ARP Spoofing y MAC Flooding), desarrollado como proyecto final para la materia **Redes de Computadoras** en la Universidad San Francisco de Quito (USFQ).

El entorno simula un escenario CTF (Capture The Flag) completamente contenedorizado con Docker, donde un equipo atacante (Red Team) ejecuta ataques reales de red contra víctimas, y un equipo defensor (Blue Team) los detecta y mitiga usando un SIEM (Wazuh) y un NIDS (Suricata).

---

## Arquitectura

Todos los contenedores comparten una red bridge personalizada `172.20.0.0/24`:

| Contenedor | IP | Rol |
|---|---|---|
| gateway | 172.20.0.2 | Router con IP forwarding |
| victim1 | 172.20.0.10 | Servidor HTTP — flag en comentario HTML |
| victim2 | 172.20.0.11 | Servidor de archivos — flag en `/backup/db_credentials.txt` |
| victim3 | 172.20.0.12 | Agente de monitoreo — envía flag en texto plano al gateway cada 10s |
| redteam | 172.20.0.100 | Atacante (caps NET_ADMIN + NET_RAW, IP forwarding activo) |
| blueteam | 172.20.0.200 | Defensor (caps NET_ADMIN + NET_RAW) |
| suricata | comparte red gateway | NIDS en modo promiscuo AF_PACKET |
| wazuh-manager | 172.20.0.240 | SIEM central |
| wazuh-indexer | 172.20.0.241 | Backend OpenSearch |
| wazuh-dashboard | 172.20.0.242 | Panel web del SIEM |
| ctfd | 172.20.0.250 | Scoreboard CTF |

**Suricata** corre con `network_mode: "service:gateway"`, compartiendo el namespace de red del gateway para ver todo el tráfico del bridge (equivalente a un puerto SPAN/mirror).

**Pipeline NIDS → SIEM**: Los logs de Suricata (`/var/log/suricata/eve.json`) se montan como volumen Docker compartido con `wazuh-manager`, que los indexa y genera alertas en tiempo real.

---

## Estructura del proyecto

```
ctf-layer2-security/
├── docker-compose.yml
├── containers/
│   ├── redteam/tools/
│   │   ├── arp_spoof.py          # MITM por ARP Spoofing (Scapy)
│   │   ├── mac_flood.py          # MAC Flooding (Scapy)
│   │   ├── capture_flags.py      # Sniffing de tráfico + extracción de flags
│   │   └── submit_flag.py        # Envío de flags a la API de CTFd
│   ├── blueteam/tools/
│   │   ├── arp_monitor.py        # Detección de cambios ARP + alertas
│   │   ├── mac_anomaly_detector.py  # Detección de MAC Flooding
│   │   └── arp_restore.py        # Restauración de tabla ARP
│   ├── victim/services/
│   │   ├── http_server_v1.py     # Flag en comentario HTML
│   │   ├── http_server_v2.py     # Flag en archivo de credenciales
│   │   └── http_server_v3.py     # Agente de monitoreo periódico
│   ├── suricata/
│   │   ├── suricata.yaml         # Config AF_PACKET, HOME_NET=172.20.0.0/24
│   │   └── rules/layer2.rules    # Reglas custom de detección L2
│   └── wazuh/
│       ├── rules/layer2_rules.xml  # Reglas Wazuh custom para alertas L2
│       └── config/               # Configs de manager, indexer y dashboard
└── scripts/
    ├── run_ctf_demo.sh           # Demo automatizada (ataque + defensa)
    ├── verify_environment.sh     # Verifica los 13 contenedores y conectividad
    └── setup_wazuh_suricata.sh   # Setup inicial de Wazuh + Suricata
```

---

## Ataques implementados

### ARP Spoofing (MITM)
El Red Team envenena la caché ARP de las víctimas para posicionarse como Man-in-the-Middle entre ellas y el gateway. Con IP forwarding activo, el tráfico pasa por el atacante de forma transparente, permitiendo capturar flags que viajan en texto plano.

**Detección**: Suricata detecta ARP Replies en broadcast y alto volumen de replies (>10 en 5s). Wazuh detecta cambios en `/proc/net/arp` vía syscheck.

### MAC Flooding
El Red Team inunda la tabla CAM del switch virtual con miles de tramas con MACs aleatorias, forzándolo a comportarse como hub y difundir todo el tráfico a todos los puertos.

**Detección**: Suricata detecta volumen anómalo de ARP Requests (>50 en 3s). El script `mac_anomaly_detector.py` del Blue Team también detecta el comportamiento desde el endpoint.

---

## Requisitos

- Docker >= 24 y Docker Compose >= 2
- Kali Linux (o cualquier distro con soporte NET_RAW/NET_ADMIN en Docker)
- Mínimo 4 GB RAM disponibles (Wazuh Indexer requiere 1 GB de heap)

---

## Inicio rápido

```bash
# 1. Ajuste necesario para Wazuh Indexer (OpenSearch)
sudo sysctl -w vm.max_map_count=262144

# 2. Clonar y levantar el entorno
cd ctf-layer2-security
sudo docker compose up -d

# 3. Verificar los 13 contenedores
sudo bash scripts/verify_environment.sh

# 4. Ejecutar la demo automatizada
sudo bash scripts/run_ctf_demo.sh
```

Las flags se inyectan vía variables de entorno en un archivo `.env` (no incluido en el repositorio). Ejemplo:

```env
FLAG1=FLAG{arp_spoof_victim1}
FLAG2=FLAG{mitm_credentials}
FLAG3=FLAG{plaintext_monitoring}
```

---

## Acceso web

| Servicio | URL | Credenciales |
|---|---|---|
| CTFd (scoreboard) | http://localhost:8000 | — |
| Wazuh Dashboard | https://localhost:5601 | `admin` / `SecretPassword` |

---

## Detección y respuesta

El Blue Team dispone de scripts de monitoreo activo y el stack Wazuh + Suricata para correlacionar eventos:

- **Suricata** detecta el ataque a nivel de red (tráfico ARP anómalo, flags en texto plano, credenciales HTTP)
- **Wazuh** correlaciona eventos del endpoint (cambios en tabla ARP, logs de sistema) y los de Suricata
- **`arp_restore.py`** restaura automáticamente las entradas ARP legítimas en las víctimas afectadas

---

## Tecnologías

- **Scapy** — crafting de paquetes para ataques y monitoreo
- **Suricata** — NIDS con reglas custom de Capa 2
- **Wazuh** — SIEM/HIDS con reglas correlacionadas
- **CTFd** — plataforma de scoreboard para el CTF
- **Docker / Docker Compose** — orquestación del entorno completo
