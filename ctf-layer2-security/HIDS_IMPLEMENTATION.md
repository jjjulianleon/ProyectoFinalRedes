# Plan de Implementación HIDS — Agentes Wazuh en CTF Lab

> **Contexto para Claude**: Este archivo documenta el plan completo para integrar agentes Wazuh HIDS en los contenedores del CTF Layer 2 Security Lab. El laboratorio corre en Kali Linux con Docker. El objetivo es que victim1/2/3, blueteam y redteam reporten eventos al wazuh-manager (172.20.0.240) vía enrollment en puerto 1515.

---

## Estado actual por fase

| Fase | Descripción | Estado |
|------|-------------|--------|
| A | Agregar `<localfile>` Suricata en ossec.conf del manager | ✅ Completada |
| B | Instalar agentes Wazuh en 5 contenedores | 🔴 En depuración |
| C | Reescribir reglas `layer2_rules.xml` | ⏳ Pendiente |
| D | Actualizar scripts de soporte | ⏳ Pendiente |

---

## Fase A — `<localfile>` Suricata en manager ✅

**Archivo**: `containers/wazuh/config/wazuh_manager/ossec.conf`

Se agregó el bloque al final de `<ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/suricata/eve.json</location>
</localfile>
```

> **Nota**: El manager usa la imagen oficial `wazuh/wazuh-manager:4.9.2` sin volume mount para ossec.conf. La config se inyecta en runtime via `scripts/setup_wazuh_suricata.sh`. Este archivo en `containers/wazuh/config/` sirve como referencia pero NO se monta automáticamente.

---

## Fase B — Instalar Agentes Wazuh en 5 Contenedores 🔴

### Lo que se implementó

#### B1. Templates `agent-ossec.conf` (uno por contenedor)

Archivos creados:
- `containers/victim/agent-ossec.conf`
- `containers/blueteam/agent-ossec.conf`
- `containers/redteam/agent-ossec.conf`

Estructura común:
```xml
<ossec_config>
  <client>
    <server>
      <address>MANAGER_IP</address>  <!-- sed reemplaza en entrypoint -->
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>AGENT_NAME</agent_name>  <!-- sed reemplaza con hostname -->
    </enrollment>
  </client>
  <syscheck>
    <directories realtime="yes" report_changes="yes">/flags</directories>
    <directories realtime="yes" report_changes="yes">/files</directories>
    ...
  </syscheck>
  <localfile> <!-- arp-table-check cada 15s --> </localfile>
  <localfile> <!-- arp-entry-count cada 15s --> </localfile>
  <localfile> <!-- gateway-mac-check cada 10s --> </localfile>
</ossec_config>
```

#### B2–B5. Dockerfiles modificados

Todos los Dockerfiles (victim, blueteam, redteam) instalan el agente así:

```dockerfile
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && curl -sL https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb \
      -o /tmp/wazuh-agent.deb \
    && dpkg -i /tmp/wazuh-agent.deb \
    && rm /tmp/wazuh-agent.deb /usr/sbin/policy-rc.d

COPY agent-ossec.conf /var/ossec/etc/ossec.conf
```

#### B3. Entrypoints modificados

Patrón actual en los 3 entrypoints:

```bash
MANAGER_IP="${WAZUH_MANAGER_IP:-172.20.0.240}"
sed -i "s/MANAGER_IP/${MANAGER_IP}/g" /var/ossec/etc/ossec.conf
sed -i "s/AGENT_NAME/$(hostname)/g" /var/ossec/etc/ossec.conf
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
/var/ossec/bin/wazuh-control start
```

#### B6. docker-compose.yml

Se agregó a victim1/2/3, blueteam y redteam:
```yaml
environment:
  - WAZUH_MANAGER_IP=172.20.0.240
depends_on:
  - wazuh-manager
```

---

## Bugs activos en Fase B

### Bug 1 — `<force>` no es elemento válido en el agente

**Síntoma**:
```
wazuh-agentd: ERROR: (1230): Invalid element in the configuration: 'force'.
wazuh-agentd: ERROR: (1202): Configuration error at 'etc/ossec.conf'.
wazuh-agentd: ERROR: (1215): No client configured. Exiting.
```

**Causa**: Se intentó agregar `<force>` dentro de `<enrollment>` en el agente, pero ese elemento solo es válido en el **manager** (sección `<auth>`), no en el agente.

**Estado**: El bloque `<force>` fue removido de los `agent-ossec.conf`. Los archivos actuales están limpios sin ese bloque.

**Solución pendiente**: Agregar `<force>` en la sección `<auth>` del ossec.conf del **manager** (ver Bug 2).

---

### Bug 2 — Duplicate agent name tras rebuild

**Síntoma**:
```
wazuh-agentd: ERROR: Duplicate agent name: victim1 (from manager)
wazuh-agentd: ERROR: Unable to add agent (from manager)
```

**Causa**: Tras `docker compose down -v && up --build`, los contenedores se recrean con nuevas claves pero el manager conserva los registros anteriores. El enrollment falla porque ya existe un agente con ese nombre.

**Estado del manager en este momento**:
```
ID: 001  Name: redteam   Active
ID: 002  Name: victim1   Pending    ← stuck en enrollment loop
ID: 003  Name: blueteam  Never connected
```
victim2 y victim3 tampoco están registrados.

**Fix aplicado al manager en runtime** (sesión actual):
```bash
# Inyectado en /var/ossec/etc/ossec.conf del manager corriendo:
<auth>
  ...
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">0</disconnected_time>
    <after_registration_time>0</after_registration_time>
  </force>
</auth>
```

> ⚠️ **Este fix no es persistente.** Al hacer `docker compose down && up`, el manager vuelve a la imagen original sin ese bloque. Hay que incorporarlo al flujo de setup.

**Fix permanente pendiente**: Actualizar `scripts/setup_wazuh_suricata.sh` para que inyecte el bloque `<force>` en el `<auth>` del manager antes de hacer `wazuh-control restart`. Usar `sed` similar a:
```bash
sudo docker exec wazuh-manager sed -i \
  's|<ssl_auto_negotiate>no</ssl_auto_negotiate>|<ssl_auto_negotiate>no</ssl_auto_negotiate>\n    <force>\n      <enabled>yes</enabled>\n      <key_mismatch>yes</key_mismatch>\n      <disconnected_time enabled="yes">0</disconnected_time>\n      <after_registration_time>0</after_registration_time>\n    </force>|' \
  /var/ossec/etc/ossec.conf
```

---

### Bug 3 — Race condition: solo `wazuh-execd` arranca en el inicio

**Síntoma**: Después del primer `docker compose up`, victim2/3/blueteam muestran:
```
wazuh-modulesd not running...
wazuh-logcollector not running...
wazuh-syscheckd not running...
wazuh-agentd not running...
wazuh-execd is running...    ← solo este
```

**Causa**: El `wazuh-control start` corre inmediatamente en el entrypoint. `wazuh-execd` arranca bien pero `wazuh-agentd` falla al intentar conectar a puerto 1515 (manager todavía inicializando). Cuando agentd falla, `wazuh-control` no arranca los daemons restantes.

**Fix aplicado**: Se agregó el wait loop en los 3 entrypoints:
```bash
until bash -c "echo >/dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; do sleep 2; done
```

**Verificación pendiente**: Este fix resuelve el timing, pero requiere un rebuild completo para activarse (`docker compose down -v && up --build`).

---

### Bug 4 — `agent-ossec.conf` en el contenedor no refleja los cambios del repo

**Causa**: Los contenedores ya están corriendo con el config anterior (sin wait loop, con `<force>` erróneo). Para que los cambios de Dockerfile y entrypoints tomen efecto se necesita rebuild.

**Estado**: Los archivos en el repo están correctos. Pendiente ejecutar rebuild completo.

---

## Procedimiento correcto para aplicar Fase B completa

```bash
# 1. Aplicar sysctl requerido por Wazuh Indexer
sudo sysctl -w vm.max_map_count=262144

# 2. Rebuild completo
cd ~/Desktop/ProyectoFinalRedes/ctf-layer2-security
sudo docker compose down -v && sudo docker compose up -d --build

# 3. Esperar que el manager esté listo (~30s) y ejecutar setup
sudo bash scripts/setup_wazuh_suricata.sh
# Este script debe inyectar <force> en <auth> del manager ANTES del restart

# 4. Esperar ~30s para enrollment de agentes

# 5. Verificar 5 agentes activos
sudo docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

**Resultado esperado**:
```
ID: 001  Name: redteam    Active
ID: 002  Name: victim1    Active
ID: 003  Name: victim2    Active
ID: 004  Name: victim3    Active
ID: 005  Name: blueteam   Active
```

---

## Próximos pasos para terminar Fase B

1. **Actualizar `scripts/setup_wazuh_suricata.sh`** — agregar inyección de `<force>` en `<auth>` del manager (antes del `wazuh-control restart` existente). Verificar con `grep -q 'force'` para no duplicar.

2. **Rebuild y verificación** — ejecutar el procedimiento de arriba y confirmar 5 agentes activos.

3. **Continuar con Fase C** — reescribir `containers/wazuh/rules/layer2_rules.xml` con rangos separados HIDS (100001-100029) y NIDS (100050-100059).

---

## Fases C y D (pendientes)

### Fase C — Reescribir `layer2_rules.xml`

**Problema actual**: Las reglas existentes (IDs 100010–100021 en `setup_wazuh_suricata.sh`) colisionan con el rango HIDS planeado (100010–100019). Rango propuesto:

| Rango | Tipo | Descripción |
|-------|------|-------------|
| 100001–100009 | HIDS | Monitoreo tabla ARP (command monitors) |
| 100010–100019 | HIDS | File Integrity Monitoring (syscheck) |
| 100020–100029 | HIDS | Detección de herramientas de ataque |
| 100050–100059 | NIDS | Alertas Suricata (eve.json) |

Reglas HIDS clave:
- `100001`: output de `arp-table-check` → captura snapshot ARP
- `100002`: correlación sobre 100001, freq≥5 en 30s → ARP Spoofing detectado
- `100003`: output de `arp-entry-count` con regex `>19` → posible MAC Flooding
- `100005`: output de `gateway-mac-check` con cambio de MAC → ARP Spoofing activo
- `100010`: syscheck en `/flags/` → acceso a flags
- `100011`: syscheck en `/files/` → acceso a archivos sensibles

### Fase D — Scripts de soporte

**D1. `verify_environment.sh`**: agregar sección `[6/6] Agentes Wazuh HIDS` que verifique que los 5 agentes están registrados y activos.

**D2. `setup_wazuh_suricata.sh`**: actualizar IDs de reglas NIDS al rango 100050–100059 e inyectar reglas HIDS.

---

## Arquitectura de red (referencia rápida)

```
172.20.0.2   gateway      (IP forwarding, Suricata comparte su namespace)
172.20.0.10  victim1      → agente Wazuh HIDS
172.20.0.11  victim2      → agente Wazuh HIDS
172.20.0.12  victim3      → agente Wazuh HIDS
172.20.0.100 redteam      → agente Wazuh HIDS
172.20.0.200 blueteam     → agente Wazuh HIDS
172.20.0.240 wazuh-manager ← recibe todos los agentes (puerto 1514/1515)
```

Pipeline de datos:
```
Agentes HIDS → wazuh-manager:1514 (eventos)
Suricata eve.json → volume suricata-logs → wazuh-manager lee /var/ossec/logs/suricata/
wazuh-manager → wazuh-indexer:9200 → wazuh-dashboard:5601
```
