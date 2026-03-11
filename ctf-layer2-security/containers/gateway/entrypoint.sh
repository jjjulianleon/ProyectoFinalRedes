#!/bin/bash
# Gateway entrypoint
# Verifica que IP forwarding esta habilitado y mantiene el contenedor corriendo

echo "[Gateway] Iniciando gateway/router..."
echo "[Gateway] IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "[Gateway] Interfaces de red:"
ip addr show
echo "[Gateway] Gateway listo."

# Mantener el contenedor corriendo
tail -f /dev/null
