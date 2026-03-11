#!/usr/bin/env python3
"""
Script de configuracion automatica de CTFd
Crea los challenges y flags usando la API REST de CTFd.

Uso: python3 setup_ctfd.py

La API REST de CTFd funciona asi:
- POST /api/v1/challenges -> crea un challenge (reto)
- POST /api/v1/flags -> asocia una flag a un challenge
- Se necesita un token de acceso (Access Token) para autenticarse
- El token se genera desde la interfaz web: Admin > Config > Access Tokens

IMPORTANTE: Primero debes hacer el setup inicial de CTFd via web (localhost:8000)
y crear un Access Token antes de ejecutar este script.
"""

import requests
import sys
import json

CTFD_URL = "http://172.20.0.250:8000"

# Challenges del CTF
CHALLENGES = [
    {
        "name": "Hidden in Plain Sight",
        "description": (
            "La empresa tiene un portal corporativo interno en Victim 1 (172.20.0.10). "
            "Se rumorea que un desarrollador dejo informacion sensible en el codigo fuente "
            "de la pagina. Intercepta el trafico HTTP para descubrirla.\n\n"
            "**Pista**: Realiza un ataque MITM entre Victim 1 y el gateway para ver "
            "el trafico HTTP en texto plano."
        ),
        "value": 100,
        "category": "ARP Spoofing",
        "type": "standard",
        "flag": "FLAG{arp_spoof_mitm_captured}",
    },
    {
        "name": "Leaked Credentials",
        "description": (
            "Victim 2 (172.20.0.11) ejecuta un servidor de archivos interno. "
            "Alguien dejo un backup de credenciales accesible. Intercepta el trafico "
            "para descubrir las credenciales filtradas.\n\n"
            "**Pista**: Navega por los archivos disponibles en el file server despues "
            "de establecer el MITM."
        ),
        "value": 150,
        "category": "ARP Spoofing",
        "type": "standard",
        "flag": "FLAG{mac_flood_broadcast_leak}",
    },
    {
        "name": "Intercept the Report",
        "description": (
            "Victim 3 (172.20.0.12) es un agente de monitoreo que envia reportes "
            "periodicos al gateway en texto plano. Uno de esos reportes contiene "
            "un token de autenticacion sensible.\n\n"
            "**Pista**: Captura el trafico entre Victim 3 y el gateway. El reporte "
            "se envia cada 10 segundos."
        ),
        "value": 200,
        "category": "Traffic Sniffing",
        "type": "standard",
        "flag": "FLAG{plaintext_credentials_exposed}",
    },
    {
        "name": "Flood the Switch",
        "description": (
            "Demuestra un ataque de MAC Flooding contra el bridge de la red. "
            "Inunda la tabla CAM con direcciones MAC aleatorias y observa como "
            "el bridge comienza a reenviar trafico por todos los puertos.\n\n"
            "**Pista**: Usa el script mac_flood.py y captura trafico que normalmente "
            "no verias. Documenta la evidencia."
        ),
        "value": 200,
        "category": "MAC Flooding",
        "type": "standard",
        "flag": "FLAG{cam_table_overflow_success}",
    },
    {
        "name": "Blue Team - Detect ARP Spoofing",
        "description": (
            "Como Blue Team, detecta un ataque de ARP Spoofing en progreso. "
            "Identifica la IP y MAC del atacante usando las herramientas defensivas.\n\n"
            "**Formato de flag**: FLAG{detected_arp_spoof_[IP_atacante]}\n"
            "Ejemplo: FLAG{detected_arp_spoof_172.20.0.100}"
        ),
        "value": 150,
        "category": "Blue Team",
        "type": "standard",
        "flag": "FLAG{detected_arp_spoof_172.20.0.100}",
    },
    {
        "name": "Blue Team - Detect MAC Flooding",
        "description": (
            "Como Blue Team, detecta un ataque de MAC Flooding en progreso. "
            "Determina cuantas MACs anomalas se generaron y desde que host.\n\n"
            "**Formato de flag**: FLAG{mac_flood_detected_from_[IP]}\n"
            "Ejemplo: FLAG{mac_flood_detected_from_172.20.0.100}"
        ),
        "value": 150,
        "category": "Blue Team",
        "type": "standard",
        "flag": "FLAG{mac_flood_detected_from_172.20.0.100}",
    },
]


def setup_challenges(token):
    """Crea los challenges y flags en CTFd usando la API REST"""
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }

    for ch in CHALLENGES:
        # Crear el challenge
        challenge_data = {
            "name": ch["name"],
            "description": ch["description"],
            "value": ch["value"],
            "category": ch["category"],
            "type": ch["type"],
            "state": "visible",
        }

        resp = requests.post(
            f"{CTFD_URL}/api/v1/challenges",
            headers=headers,
            json=challenge_data,
        )

        if resp.status_code == 200:
            challenge_id = resp.json()["data"]["id"]
            print(f"[OK] Challenge creado: {ch['name']} (ID: {challenge_id})")

            # Crear la flag asociada al challenge
            flag_data = {
                "challenge_id": challenge_id,
                "content": ch["flag"],
                "type": "static",
            }

            flag_resp = requests.post(
                f"{CTFD_URL}/api/v1/flags",
                headers=headers,
                json=flag_data,
            )

            if flag_resp.status_code == 200:
                print(f"    Flag configurada: {ch['flag']}")
            else:
                print(f"    [ERROR] Flag: {flag_resp.text}")
        else:
            print(f"[ERROR] Challenge '{ch['name']}': {resp.text}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 setup_ctfd.py <ACCESS_TOKEN>")
        print()
        print("Para obtener el Access Token:")
        print("1. Abre CTFd en http://localhost:8000")
        print("2. Completa el setup inicial (nombre del CTF, admin user)")
        print("3. Ve a Admin Panel > Config > Access Tokens")
        print("4. Genera un nuevo token y pasalo como argumento")
        sys.exit(1)

    token = sys.argv[1]
    print(f"[*] Configurando CTFd en {CTFD_URL}...")
    setup_challenges(token)
    print("[*] Setup completado!")
