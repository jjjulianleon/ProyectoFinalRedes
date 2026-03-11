#!/usr/bin/env python3
"""
Victim 3 - Servicio que transmite la flag periodicamente en texto plano
Este host envia datos al gateway cada 10 segundos via HTTP POST sin cifrar.
El Red Team debe hacer ARP Spoofing (MITM) entre victim3 y el gateway
para capturar estos paquetes y extraer la flag del payload.
"""

import os
import time
import threading
import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler

FLAG = os.environ.get("FLAG", "FLAG{default_flag_3}")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "172.20.0.2")
PORT = 80


class StatusHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = """<!DOCTYPE html>
<html>
<head><title>Victim 3 - Monitoring Agent</title></head>
<body>
    <h1>Agente de Monitoreo</h1>
    <p>Estado: ACTIVO</p>
    <p>Enviando reportes periodicos al gateway...</p>
    <p>Intervalo: cada 10 segundos</p>
    <footer>Monitoring Agent v1.0</footer>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            super().do_GET()

    def log_message(self, format, *args):
        print(f"[Victim3-Status] {self.client_address[0]} - {format % args}")


def send_periodic_report():
    """
    Envia reportes periodicos al gateway en texto plano via HTTP.
    El payload incluye la flag como parte de un "reporte de seguridad".
    Un atacante con MITM puede capturar estos paquetes.
    """
    while True:
        time.sleep(10)
        payload = (
            f"SECURITY_REPORT|timestamp={int(time.time())}"
            f"|host=victim3|status=ok"
            f"|auth_token={FLAG}"
            f"|metrics=cpu:23,mem:45,disk:67"
        )
        try:
            # Envia el reporte al gateway en texto plano (HTTP, no HTTPS)
            requests.post(
                f"http://{GATEWAY_IP}:80/report",
                data=payload,
                timeout=2
            )
            print(f"[Victim3] Reporte enviado al gateway")
        except Exception:
            # El gateway no tiene servidor HTTP escuchando, pero el paquete
            # se envia igual por la red — y eso es lo que importa para el MITM
            print(f"[Victim3] Reporte enviado (gateway no responde, pero paquete transmitido)")


if __name__ == "__main__":
    # Hilo que envia reportes periodicos al gateway
    reporter = threading.Thread(target=send_periodic_report, daemon=True)
    reporter.start()

    # Servidor HTTP para mostrar estado
    server = HTTPServer(("0.0.0.0", PORT), StatusHandler)
    print(f"[Victim3] Agente de monitoreo en puerto {PORT}")
    print(f"[Victim3] Enviando reportes con flag al gateway cada 10s")
    server.serve_forever()
