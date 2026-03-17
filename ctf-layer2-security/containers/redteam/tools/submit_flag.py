#!/usr/bin/env python3
"""
=============================================================================
Submit Flag - Envio automatico de flags a CTFd via API REST
=============================================================================
Este script permite enviar flags capturadas a la plataforma CTFd
para obtener puntos en la competencia.

COMO FUNCIONA:
  1. Se conecta a la API REST de CTFd (http://172.20.0.250:8000)
  2. Autentica con credenciales de un equipo registrado
  3. Envia la flag al challenge correspondiente
  4. Muestra el resultado (correcta/incorrecta/ya enviada)

EJEMPLO DE USO:
  # Enviar una flag especifica
  python3 submit_flag.py -f "FLAG{arp_spoof_mitm_captured}" -c 1

  # Enviar con usuario y password
  python3 submit_flag.py -f "FLAG{...}" -c 1 -u teamred -p password123

  # Enviar usando token de sesion
  python3 submit_flag.py -f "FLAG{...}" -c 2 --token <session_token>

  # Listar challenges disponibles
  python3 submit_flag.py --list

REQUISITOS:
  - CTFd corriendo y accesible (http://172.20.0.250:8000)
  - Equipo registrado en CTFd
  - Conectividad con el servidor CTFd
=============================================================================
"""

import argparse
import json
import sys

# Usar urllib para evitar dependencia externa (requests no esta en redteam)
from urllib import request, error, parse


CTFD_URL = "http://172.20.0.250:8000"


class CTFdClient:
    """Cliente para interactuar con la API REST de CTFd."""

    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.session = None
        self.nonce = None
        self.token = token

    def _api_request(self, method, endpoint, data=None):
        """
        Realiza una peticion a la API de CTFd.

        CTFd ofrece dos modos de autenticacion:
        1. Token de API (Header: Authorization: Token <token>)
        2. Cookie de sesion (tras login con usuario/password)
        """
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}

        if self.token:
            headers["Authorization"] = f"Token {self.token}"

        body = json.dumps(data).encode("utf-8") if data else None
        req = request.Request(url, data=body, headers=headers, method=method)

        if self.session:
            req.add_header("Cookie", self.session)

        try:
            with request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except error.HTTPError as e:
            body = e.read().decode()
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                print(f"[!] Error HTTP {e.code}: {body[:200]}")
                return None

    def login(self, username, password):
        """
        Inicia sesion en CTFd y obtiene cookie de sesion + nonce CSRF.

        CTFd usa sesiones basadas en cookies para usuarios normales.
        Para automatizacion, es preferible usar tokens de API.
        """
        # Obtener nonce del formulario de login
        try:
            login_url = f"{self.base_url}/login"
            req = request.Request(login_url)
            with request.urlopen(req) as resp:
                html = resp.read().decode()
                # Extraer nonce CSRF
                import re
                nonce_match = re.search(r'name="nonce"\s+value="([^"]+)"', html)
                if nonce_match:
                    self.nonce = nonce_match.group(1)
                # Guardar cookie de sesion
                cookies = resp.headers.get_all("Set-Cookie")
                if cookies:
                    self.session = "; ".join(
                        c.split(";")[0] for c in cookies
                    )
        except Exception as e:
            print(f"[!] Error obteniendo pagina de login: {e}")
            return False

        # Enviar credenciales
        login_data = parse.urlencode({
            "name": username,
            "password": password,
            "nonce": self.nonce or ""
        }).encode()

        try:
            req = request.Request(
                f"{self.base_url}/login",
                data=login_data,
                method="POST"
            )
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            if self.session:
                req.add_header("Cookie", self.session)

            with request.urlopen(req) as resp:
                cookies = resp.headers.get_all("Set-Cookie")
                if cookies:
                    self.session = "; ".join(
                        c.split(";")[0] for c in cookies
                    )
                print(f"[+] Login exitoso como '{username}'")
                return True
        except error.HTTPError as e:
            if e.code == 302 or e.code == 301:
                cookies = e.headers.get_all("Set-Cookie")
                if cookies:
                    self.session = "; ".join(
                        c.split(";")[0] for c in cookies
                    )
                print(f"[+] Login exitoso como '{username}'")
                return True
            print(f"[!] Login fallido: HTTP {e.code}")
            return False

    def list_challenges(self):
        """
        Lista todos los challenges disponibles en CTFd.
        GET /api/v1/challenges
        """
        result = self._api_request("GET", "/api/v1/challenges")
        if not result or not result.get("success"):
            print("[!] No se pudieron obtener los challenges")
            return []
        return result.get("data", [])

    def submit_flag(self, challenge_id, flag):
        """
        Envia una flag a CTFd para un challenge especifico.
        POST /api/v1/challenges/attempt

        Body: {"challenge_id": <id>, "submission": "<flag>"}

        Respuestas posibles:
        - correct: Flag correcta, puntos otorgados
        - incorrect: Flag incorrecta
        - already_solved: Ya fue resuelta por este equipo
        """
        data = {
            "challenge_id": challenge_id,
            "submission": flag
        }
        result = self._api_request("POST", "/api/v1/challenges/attempt", data)
        return result


def main():
    parser = argparse.ArgumentParser(
        description="Envio automatico de flags a CTFd",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Challenges del CTF:
  1. Hidden in Plain Sight    (ARP Spoofing, 100pts)
  2. Leaked Credentials       (ARP Spoofing, 150pts)
  3. Intercept the Report     (Traffic Sniffing, 200pts)
  4. Flood the Switch         (MAC Flooding, 200pts)
  5. Detect ARP Spoofing      (Blue Team, 150pts)
  6. Detect MAC Flooding      (Blue Team, 150pts)

Ejemplos:
  # Listar challenges
  python3 submit_flag.py --list --token <api_token>

  # Enviar flag del challenge 1
  python3 submit_flag.py -f "FLAG{arp_spoof_mitm_captured}" -c 1 --token <api_token>

  # Enviar con credenciales de equipo
  python3 submit_flag.py -f "FLAG{...}" -c 2 -u teamred -p pass123
        """
    )
    parser.add_argument("-f", "--flag", default=None,
                        help="Flag a enviar")
    parser.add_argument("-c", "--challenge-id", type=int, default=None,
                        help="ID del challenge")
    parser.add_argument("--url", default=CTFD_URL,
                        help=f"URL de CTFd (default: {CTFD_URL})")
    parser.add_argument("--token", default=None,
                        help="Token de API de CTFd")
    parser.add_argument("-u", "--username", default=None,
                        help="Nombre de usuario/equipo en CTFd")
    parser.add_argument("-p", "--password", default=None,
                        help="Password del equipo en CTFd")
    parser.add_argument("--list", action="store_true",
                        help="Listar challenges disponibles")
    args = parser.parse_args()

    # Crear cliente CTFd
    client = CTFdClient(args.url, token=args.token)

    # Autenticar si se proporcionaron credenciales
    if args.username and args.password:
        if not client.login(args.username, args.password):
            sys.exit(1)
    elif not args.token:
        print("[!] Se requiere --token o credenciales (-u/-p)")
        print("[!] Usa 'python3 submit_flag.py --help' para ver opciones")
        sys.exit(1)

    # Listar challenges
    if args.list:
        print("\n" + "=" * 60)
        print("  Challenges Disponibles")
        print("=" * 60)
        challenges = client.list_challenges()
        for ch in challenges:
            solved = "RESUELTO" if ch.get("solved_by_me") else "pendiente"
            print(f"  [{ch['id']}] {ch['name']}")
            print(f"      Categoria: {ch.get('category', 'N/A')}")
            print(f"      Puntos:    {ch.get('value', 'N/A')}")
            print(f"      Estado:    {solved}")
            print()
        print("=" * 60)
        return

    # Enviar flag
    if not args.flag or args.challenge_id is None:
        print("[!] Se requiere -f <flag> y -c <challenge_id>")
        print("[!] Usa --list para ver los challenges disponibles")
        sys.exit(1)

    print(f"\n[*] Enviando flag al challenge {args.challenge_id}...")
    print(f"[*] Flag: {args.flag}")

    result = client.submit_flag(args.challenge_id, args.flag)

    if result is None:
        print("[!] Error al enviar la flag")
        sys.exit(1)

    status = result.get("data", {}).get("status", "unknown")
    message = result.get("data", {}).get("message", "Sin mensaje")

    if status == "correct":
        print(f"\n[+] CORRECTA! {message}")
        print(f"[+] Puntos otorgados para challenge {args.challenge_id}")
    elif status == "already_solved":
        print(f"\n[*] Ya resuelta: {message}")
    elif status == "incorrect":
        print(f"\n[-] INCORRECTA: {message}")
    else:
        print(f"\n[?] Respuesta: {status} - {message}")


if __name__ == "__main__":
    main()
