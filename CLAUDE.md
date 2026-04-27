# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CTF (Capture The Flag) cybersecurity lab simulating Layer 2 network attacks (ARP Spoofing, MAC Flooding) in a containerized environment. It is a university final project for a networking course, running on Kali Linux with Docker. The lab has two teams:
- **Red Team**: Attackers using Scapy-based scripts to compromise victim hosts
- **Blue Team**: Defenders using monitoring scripts and SIEM/NIDS tools (Wazuh + Suricata)

## Key Commands

All commands must be run from `ctf-layer2-security/` and require `sudo`:

```bash
# Prerequisite (required before starting containers on Kali)
sudo sysctl -w vm.max_map_count=262144

# Start the full environment
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security
sudo docker compose up -d

# Rebuild everything from scratch
sudo docker compose down -v && sudo docker compose up -d --build

# Verify all containers and connectivity are healthy
sudo bash scripts/verify_environment.sh

# Run the full CTF demo (automated attack + defense sequence)
sudo bash scripts/run_ctf_demo.sh

# Exec into a container
sudo docker exec -it redteam bash
sudo docker exec -it blueteam bash

# Check container logs
sudo docker logs <container_name> 2>&1 | tail -20

# Check status
sudo docker ps --format "table {{.Names}}\t{{.Status}}"
```

## Network Architecture

All containers share a custom bridge network `172.20.0.0/24`:

| Container | IP | Role |
|---|---|---|
| gateway | 172.20.0.2 | Router with IP forwarding |
| victim1 | 172.20.0.10 | HTTP server, flag in HTML comment |
| victim2 | 172.20.0.11 | File server, flag in `/backup/db_credentials.txt` |
| victim3 | 172.20.0.12 | Monitoring agent, sends flag in plaintext to gateway every 10s |
| redteam | 172.20.0.100 | Attacker (NET_ADMIN + NET_RAW caps, IP forwarding on) |
| blueteam | 172.20.0.200 | Defender (NET_ADMIN + NET_RAW caps) |
| suricata | shares gateway network | NIDS in promiscuous AF_PACKET mode |
| wazuh-manager | 172.20.0.240 | SIEM central server |
| wazuh-indexer | 172.20.0.241 | OpenSearch backend (1GB RAM) |
| wazuh-dashboard | 172.20.0.242 | Web UI |
| ctfd | 172.20.0.250 | CTF scoreboard (http://localhost:8000) |

**Note:** Gateway uses `.2` because Docker reserves `.1` for the host bridge interface.

## Code Structure

```
ctf-layer2-security/
├── docker-compose.yml          # Defines all 13 services
├── containers/
│   ├── redteam/tools/          # Attack scripts (Scapy-based)
│   │   ├── arp_spoof.py        # ARP Spoofing MITM
│   │   ├── mac_flood.py        # MAC Flooding
│   │   ├── capture_flags.py    # Traffic sniffing + flag extraction
│   │   └── submit_flag.py      # CTFd API submission
│   ├── blueteam/tools/         # Defense scripts (Scapy-based)
│   │   ├── arp_monitor.py      # ARP change detection + alerting
│   │   ├── mac_anomaly_detector.py  # MAC flooding detection
│   │   └── arp_restore.py      # ARP table restoration
│   ├── victim/services/        # HTTP servers, one per VICTIM_ID (1/2/3)
│   │   ├── http_server_v1.py   # Flag hidden in HTML comment
│   │   ├── http_server_v2.py   # Flag in /backup/db_credentials.txt
│   │   └── http_server_v3.py   # Monitoring agent, periodic plaintext reports
│   ├── suricata/
│   │   ├── suricata.yaml       # AF_PACKET config, HOME_NET=172.20.0.0/24
│   │   └── rules/layer2.rules  # Custom Layer 2 detection rules
│   └── wazuh/
│       ├── rules/layer2_rules.xml  # Custom Wazuh rules for L2 alerts
│       ├── config/             # wazuh_indexer/ and wazuh_dashboard/ configs
│       └── certs/              # TLS certs (generated, not in git)
└── scripts/
    ├── verify_environment.sh   # Checks all 13 containers + connectivity + scripts
    ├── run_ctf_demo.sh         # Full automated demo (attack + defense + evidence)
    └── setup_wazuh_suricata.sh # One-time setup helper
```

## Important Architectural Details

**Suricata** runs with `network_mode: "service:gateway"` — it shares the gateway's network namespace to see all traffic crossing the bridge, simulating a SPAN/mirror port. This means Suricata has no separate IP; it uses `eth0` of the gateway container.

**Wazuh integration**: Suricata logs at `/var/log/suricata/eve.json` are mounted as the Docker volume `suricata-logs`, which is also mounted read-only into `wazuh-manager` at `/var/ossec/logs/suricata`. This is the data pipeline from NIDS → SIEM.

**Victim flags** are injected at container startup via environment variables `FLAG1`, `FLAG2`, `FLAG3` (defined in a `.env` file, excluded from git). Victim selection is handled by the `VICTIM_ID` build arg and env var in `entrypoint.sh`.

**Wazuh certs** are pre-generated and stored in `containers/wazuh/certs/` (excluded from git). To regenerate, use `containers/wazuh/generate-certs.sh` with the `generate-certs-compose.yml`.

## Web Access

- **CTFd** (scoreboard): http://localhost:8000
- **Wazuh Dashboard**: https://localhost:5601 — credentials: `admin` / `SecretPassword`

## Known Issues & Solutions

- Wazuh Indexer needs `vm.max_map_count=262144` on the host (set it before `docker compose up`)
- Wazuh Indexer requires 1GB heap (`-Xms1g -Xmx1g`); lower values cause OOM
- Suricata cannot use `hostname:` when sharing another container's network namespace
