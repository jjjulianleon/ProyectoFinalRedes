#!/bin/bash
# ============================================================================
# Generador de certificados SSL para Wazuh
# Genera CA root + certificados para indexer, manager y dashboard
# Solo necesita ejecutarse UNA vez antes del primer docker compose up
# ============================================================================

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

# Si ya existen los certs, no regenerar
if [ -f "$CERTS_DIR/root-ca.pem" ]; then
    echo "[*] Certificados ya existen en $CERTS_DIR. Saltando generacion."
    exit 0
fi

echo "[*] Generando certificados SSL para Wazuh..."

# 1. Root CA (Autoridad Certificadora raiz)
echo "[1/4] Generando Root CA..."
openssl genrsa -out "$CERTS_DIR/root-ca-key.pem" 2048 2>/dev/null
openssl req -new -x509 -sha256 -key "$CERTS_DIR/root-ca-key.pem" \
    -out "$CERTS_DIR/root-ca.pem" -days 3650 \
    -subj "/C=EC/ST=Pichincha/L=Quito/O=CTF-Lab/CN=CTF-Root-CA" 2>/dev/null

# 2. Certificado para Wazuh Indexer (admin + nodo)
echo "[2/4] Generando certificado del Indexer..."
openssl genrsa -out "$CERTS_DIR/indexer-key.pem" 2048 2>/dev/null
openssl req -new -key "$CERTS_DIR/indexer-key.pem" \
    -out "$CERTS_DIR/indexer.csr" \
    -subj "/C=EC/ST=Pichincha/L=Quito/O=CTF-Lab/CN=wazuh-indexer" 2>/dev/null

cat > "$CERTS_DIR/indexer-ext.conf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-indexer
DNS.2 = localhost
IP.1 = 172.20.0.241
IP.2 = 127.0.0.1
EXTEOF

openssl x509 -req -in "$CERTS_DIR/indexer.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/indexer.pem" -days 3650 \
    -extensions v3_req -extfile "$CERTS_DIR/indexer-ext.conf" 2>/dev/null

# Admin cert (para administrar el indexer)
openssl genrsa -out "$CERTS_DIR/admin-key.pem" 2048 2>/dev/null
openssl req -new -key "$CERTS_DIR/admin-key.pem" \
    -out "$CERTS_DIR/admin.csr" \
    -subj "/C=EC/ST=Pichincha/L=Quito/O=CTF-Lab/CN=admin" 2>/dev/null
openssl x509 -req -in "$CERTS_DIR/admin.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/admin.pem" -days 3650 2>/dev/null

# 3. Certificado para Wazuh Manager (filebeat -> indexer)
echo "[3/4] Generando certificado del Manager..."
openssl genrsa -out "$CERTS_DIR/manager-key.pem" 2048 2>/dev/null
openssl req -new -key "$CERTS_DIR/manager-key.pem" \
    -out "$CERTS_DIR/manager.csr" \
    -subj "/C=EC/ST=Pichincha/L=Quito/O=CTF-Lab/CN=wazuh-manager" 2>/dev/null

cat > "$CERTS_DIR/manager-ext.conf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-manager
DNS.2 = localhost
IP.1 = 172.20.0.240
IP.2 = 127.0.0.1
EXTEOF

openssl x509 -req -in "$CERTS_DIR/manager.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/manager.pem" -days 3650 \
    -extensions v3_req -extfile "$CERTS_DIR/manager-ext.conf" 2>/dev/null

# 4. Certificado para Wazuh Dashboard
echo "[4/4] Generando certificado del Dashboard..."
openssl genrsa -out "$CERTS_DIR/dashboard-key.pem" 2048 2>/dev/null
openssl req -new -key "$CERTS_DIR/dashboard-key.pem" \
    -out "$CERTS_DIR/dashboard.csr" \
    -subj "/C=EC/ST=Pichincha/L=Quito/O=CTF-Lab/CN=wazuh-dashboard" 2>/dev/null

cat > "$CERTS_DIR/dashboard-ext.conf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-dashboard
DNS.2 = localhost
IP.1 = 172.20.0.242
IP.2 = 127.0.0.1
EXTEOF

openssl x509 -req -in "$CERTS_DIR/dashboard.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/dashboard.pem" -days 3650 \
    -extensions v3_req -extfile "$CERTS_DIR/dashboard-ext.conf" 2>/dev/null

# Limpiar CSRs y configs temporales
rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.conf "$CERTS_DIR"/*.srl

echo "[*] Certificados generados exitosamente en $CERTS_DIR/"
ls -la "$CERTS_DIR"/*.pem
