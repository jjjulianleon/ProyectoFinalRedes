#!/bin/bash
# Gateway entrypoint
# Verifica que IP forwarding esta habilitado y mantiene el contenedor corriendo

echo "[Gateway] Iniciando gateway/router..."
echo "[Gateway] IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "[Gateway] Interfaces de red:"
ip addr show
echo "[Gateway] Gateway listo."

# Servidor HTTP simple en puerto 80
# Acepta las peticiones POST de victim3 (reportes de monitoreo)
# Esto permite que el trafico HTTP fluya por la red y sea capturable via MITM
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass
HTTPServer(('0.0.0.0', 80), H).serve_forever()
" &

# Mantener el contenedor corriendo
tail -f /dev/null
