#!/usr/bin/env python3
"""Reset CTFd para demo: elimina submissions y crea usuario blueteam si no existe."""
import http.cookiejar
import json
import re
import sys
from urllib import error, parse, request

BASE = "http://172.20.0.250:8000"


def admin_session():
    jar = http.cookiejar.CookieJar()
    opener = request.build_opener(request.HTTPCookieProcessor(jar))
    r = opener.open(BASE + "/login")
    nonce = re.search(r'name="nonce"[^>]+value="([^"]+)"', r.read().decode()).group(1)
    data = parse.urlencode({"name": "admin", "password": "admin123", "nonce": nonce}).encode()
    r = opener.open(request.Request(BASE + "/login", data=data, method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"}))
    html = r.read().decode()
    nonce2 = re.search(r"'csrfNonce':\s*\"([^\"]+)\"", html).group(1)
    headers = {"CSRF-Token": nonce2, "Content-Type": "application/json"}
    return opener, headers


def main():
    try:
        opener, headers = admin_session()
    except Exception as e:
        print(f"[!] No se pudo conectar al CTFd: {e}")
        sys.exit(1)

    # Eliminar todas las submissions
    r = opener.open(request.Request(BASE + "/api/v1/submissions?per_page=100", headers=headers))
    subs = json.loads(r.read().decode()).get("data", [])
    for s in subs:
        req = request.Request(f"{BASE}/api/v1/submissions/{s['id']}", headers=headers, method="DELETE")
        opener.open(req)
    print(f"  [+] {len(subs)} submissions eliminadas — scoreboard en cero")

    # Crear usuarios blueteam y redteam si no existen
    r = opener.open(request.Request(BASE + "/api/v1/users?per_page=100", headers=headers))
    existing = [u["name"] for u in json.loads(r.read().decode()).get("data", [])]
    for name, email, pwd in [
        ("blueteam", "blueteam@ctf.local", "blueteam123"),
        ("redteam",  "redteam@ctf.local",  "redteam123"),
    ]:
        if name not in existing:
            body = json.dumps({"name": name, "email": email,
                               "password": pwd, "type": "user"}).encode()
            try:
                opener.open(request.Request(BASE + "/api/v1/users", data=body,
                                            headers=headers, method="POST"))
                print(f"  [+] Usuario {name} creado")
            except error.HTTPError as e:
                print(f"  [!] Error creando {name}: {e.read().decode()[:100]}")
        else:
            print(f"  [+] Usuario {name} ya existe")


if __name__ == "__main__":
    main()
