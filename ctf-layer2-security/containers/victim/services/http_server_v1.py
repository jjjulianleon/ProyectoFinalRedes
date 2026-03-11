#!/usr/bin/env python3
"""
Victim 1 - Servidor HTTP con flag oculta en comentario HTML
La flag esta escondida en un comentario HTML de la pagina principal.
El Red Team debe interceptar el trafico HTTP (via ARP Spoofing MITM)
para ver el contenido de la pagina y encontrar la flag.
"""

import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

FLAG = os.environ.get("FLAG", "FLAG{default_flag_1}")
PORT = 80


class VictimHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            # Pagina principal con flag oculta en comentario HTML
            html = f"""<!DOCTYPE html>
<html>
<head><title>Victim 1 - Corporate Portal</title></head>
<body>
    <h1>Portal Corporativo Interno</h1>
    <p>Bienvenido al sistema interno de la empresa.</p>
    <p>Acceso restringido a personal autorizado.</p>
    <!-- TODO: Remover antes de produccion - credenciales de prueba -->
    <!-- Flag de auditoria: {FLAG} -->
    <footer>IT Department - 2026</footer>
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
        print(f"[Victim1-HTTP] {self.client_address[0]} - {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), VictimHandler)
    print(f"[Victim1] Servidor HTTP en puerto {PORT}")
    print(f"[Victim1] Flag oculta en comentario HTML de la pagina principal")
    server.serve_forever()
