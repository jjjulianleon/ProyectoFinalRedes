#!/bin/bash
# Victim entrypoint - Lanza el servicio HTTP correspondiente segun VICTIM_ID

echo "[Victim-${VICTIM_ID}] Iniciando host victima..."
echo "[Victim-${VICTIM_ID}] IP: $(hostname -I)"

case "${VICTIM_ID}" in
    1)
        echo "[Victim-1] Lanzando servidor HTTP con flag en comentario HTML"
        python3 /app/services/http_server_v1.py
        ;;
    2)
        echo "[Victim-2] Lanzando file server con flag en archivo"
        python3 /app/services/http_server_v2.py
        ;;
    3)
        echo "[Victim-3] Lanzando agente de monitoreo con flag en reportes"
        python3 /app/services/http_server_v3.py
        ;;
    *)
        echo "[Victim-${VICTIM_ID}] ID no reconocido, lanzando servidor basico"
        python3 -m http.server 80 --directory /app
        ;;
esac
