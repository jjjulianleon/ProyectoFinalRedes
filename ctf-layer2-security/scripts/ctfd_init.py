#!/usr/bin/env python3
"""
Inicializacion automatica completa de CTFd desde cero.
Realiza el setup inicial, crea challenges y configura usuario blueteam.

Uso: python3 ctfd_init.py
"""
import http.cookiejar
import json
import re
import sys
from urllib import error, parse, request

BASE = "http://172.20.0.250:8000"
ADMIN_NAME = "admin"
ADMIN_EMAIL = "admin@ctf.local"
ADMIN_PASSWORD = "admin123"
CTF_NAME = "CTF Layer 2 Security"

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
        "flag": "FLAG{mac_flood_detected_from_172.20.0.100}",
    },
]


def needs_setup():
    """Verifica si CTFd aun no ha sido inicializado."""
    try:
        r = request.urlopen(BASE + "/api/v1/challenges", timeout=5)
        return False
    except error.HTTPError as e:
        if e.code in (302, 403):
            return True
        return False
    except Exception:
        return True


def do_initial_setup():
    """Realiza el setup inicial de CTFd via el formulario /setup."""
    jar = http.cookiejar.CookieJar()
    opener = request.build_opener(request.HTTPCookieProcessor(jar))

    # Obtener nonce del formulario de setup
    r = opener.open(BASE + "/setup")
    html = r.read().decode()
    match = re.search(r'name="nonce"[^>]+value="([^"]+)"', html)
    if not match:
        print("[!] No se encontro el nonce en /setup — CTFd ya puede estar configurado")
        return False

    nonce = match.group(1)
    data = parse.urlencode({
        "ctf_name": CTF_NAME,
        "ctf_description": "CTF de seguridad de Capa 2 - ARP Spoofing y MAC Flooding",
        "name": ADMIN_NAME,
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
        "nonce": nonce,
    }).encode()

    req = request.Request(
        BASE + "/setup",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    opener.open(req)
    print(f"  [+] CTFd inicializado: '{CTF_NAME}' | admin: {ADMIN_NAME} / {ADMIN_PASSWORD}")
    return True


def admin_session():
    """Abre sesion como admin y retorna opener + headers CSRF."""
    jar = http.cookiejar.CookieJar()
    opener = request.build_opener(request.HTTPCookieProcessor(jar))
    r = opener.open(BASE + "/login")
    nonce = re.search(r'name="nonce"[^>]+value="([^"]+)"', r.read().decode()).group(1)
    data = parse.urlencode({
        "name": ADMIN_NAME,
        "password": ADMIN_PASSWORD,
        "nonce": nonce,
    }).encode()
    r = opener.open(request.Request(
        BASE + "/login", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ))
    html = r.read().decode()
    nonce2 = re.search(r"'csrfNonce':\s*\"([^\"]+)\"", html).group(1)
    headers = {"CSRF-Token": nonce2, "Content-Type": "application/json"}
    return opener, headers


def create_challenges(opener, headers):
    """Crea los challenges y sus flags en CTFd."""
    # Verificar si ya existen challenges
    r = opener.open(request.Request(BASE + "/api/v1/challenges", headers=headers))
    existing = json.loads(r.read().decode()).get("data", [])
    if existing:
        print(f"  [*] Ya existen {len(existing)} challenges, saltando creacion")
        return

    for ch in CHALLENGES:
        body = json.dumps({
            "name": ch["name"],
            "description": ch["description"],
            "value": ch["value"],
            "category": ch["category"],
            "type": "standard",
            "state": "visible",
        }).encode()
        req = request.Request(BASE + "/api/v1/challenges", data=body,
                              headers=headers, method="POST")
        resp = opener.open(req)
        challenge_id = json.loads(resp.read().decode())["data"]["id"]

        flag_body = json.dumps({
            "challenge_id": challenge_id,
            "content": ch["flag"],
            "type": "static",
        }).encode()
        opener.open(request.Request(BASE + "/api/v1/flags", data=flag_body,
                                    headers=headers, method="POST"))
        print(f"  [+] {ch['name']} ({ch['value']} pts) | {ch['flag']}")


def create_user(opener, headers, name, email, password, existing_names):
    """Crea un usuario si no existe."""
    if name not in existing_names:
        body = json.dumps({
            "name": name,
            "email": email,
            "password": password,
            "type": "user",
        }).encode()
        try:
            opener.open(request.Request(BASE + "/api/v1/users", data=body,
                                        headers=headers, method="POST"))
            print(f"  [+] Usuario {name} creado (pass: {password})")
        except error.HTTPError as e:
            print(f"  [!] Error creando {name}: {e.read().decode()[:80]}")
    else:
        print(f"  [+] Usuario {name} ya existe")


def create_blueteam(opener, headers):
    """Crea usuarios blueteam y redteam si no existen."""
    r = opener.open(request.Request(BASE + "/api/v1/users?per_page=100", headers=headers))
    existing = [u["name"] for u in json.loads(r.read().decode()).get("data", [])]
    create_user(opener, headers, "blueteam", "blueteam@ctf.local", "blueteam123", existing)
    create_user(opener, headers, "redteam",  "redteam@ctf.local",  "redteam123",  existing)


def main():
    print(f"[*] Conectando a CTFd en {BASE}...")

    # Setup inicial si es necesario
    r = request.urlopen(BASE + "/", timeout=10)
    final_url = r.geturl()
    if "/setup" in final_url:
        print("[*] CTFd sin configurar, realizando setup inicial...")
        do_initial_setup()
    else:
        print("[*] CTFd ya configurado, saltando setup inicial")

    # Sesion admin
    try:
        opener, headers = admin_session()
    except Exception as e:
        print(f"[!] Error al iniciar sesion: {e}")
        sys.exit(1)

    # Challenges
    print("[*] Configurando challenges...")
    create_challenges(opener, headers)

    # Usuario blueteam
    print("[*] Configurando usuario blueteam...")
    create_blueteam(opener, headers)

    print("[*] CTFd listo.")


if __name__ == "__main__":
    main()
