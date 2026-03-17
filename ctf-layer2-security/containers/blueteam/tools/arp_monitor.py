#!/usr/bin/env python3
"""
=============================================================================
ARP Monitor - Detector de ARP Spoofing en tiempo real
=============================================================================
Este script monitorea el trafico ARP de la red para detectar ataques
de ARP Spoofing (ARP Cache Poisoning).

COMO DETECTA EL ATAQUE:
  1. Construye una tabla de asociaciones IP <-> MAC legitimas
  2. Monitorea todos los paquetes ARP en la red
  3. Si una IP cambia de MAC, genera una ALERTA (posible ARP Spoofing)
  4. Detecta multiples ARP Reply sin Request previo (gratuitous ARP sospechoso)
  5. Detecta si dos IPs diferentes reclaman la misma MAC

INDICADORES DE ARP SPOOFING:
  - Una IP conocida cambia de MAC repentinamente
  - Rafaga de ARP Replies no solicitados
  - Multiples IPs apuntando a la misma MAC (MITM)
  - ARP Reply con MAC origen diferente a la MAC en el header Ethernet

EJEMPLO DE USO:
  # Monitoreo basico
  python3 arp_monitor.py

  # Monitoreo con IPs conocidas pre-cargadas
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12

  # Guardar alertas en archivo
  python3 arp_monitor.py -o /logs/arp_alerts.log

REQUISITOS:
  - Privilegios root (NET_RAW)
  - Scapy instalado
=============================================================================
"""

import argparse
import sys
import time
import signal
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, ARP, Ether, srp, conf


class ARPMonitor:
    """Monitor de trafico ARP para deteccion de ARP Spoofing."""

    def __init__(self, iface="eth0", known_hosts=None, output_file=None):
        self.iface = iface
        self.output_file = output_file

        # Tabla de asociaciones IP -> MAC conocidas
        # Se llena dinamicamente o con hosts pre-configurados
        self.arp_table = {}

        # Contadores para deteccion de anomalias
        self.reply_count = defaultdict(int)     # Replies por IP origen
        self.reply_timestamps = defaultdict(list)  # Timestamps de replies
        self.alerts = []                        # Historial de alertas
        self.pkt_count = 0

        # Umbral: mas de N replies en M segundos = sospechoso
        self.reply_threshold = 5
        self.time_window = 10  # segundos

        # Pre-cargar hosts conocidos si se proporcionan
        if known_hosts:
            self._resolve_known_hosts(known_hosts)

    def _resolve_known_hosts(self, ip_list):
        """
        Resuelve las MACs reales de hosts conocidos via ARP Request.
        Esto establece la linea base legitima de la red.
        """
        print(f"[*] Resolviendo MACs de {len(ip_list)} hosts conocidos...")
        for ip in ip_list:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
            result = srp(pkt, iface=self.iface, timeout=2, verbose=False)[0]
            if result:
                mac = result[0][1].hwsrc
                self.arp_table[ip] = mac
                print(f"  [+] {ip} -> {mac}")
            else:
                print(f"  [-] {ip} -> No responde")
        print()

    def _alert(self, level, message, details=None):
        """Genera y muestra una alerta de seguridad."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{level}] {message}"
        if details:
            alert_msg += f"\n    Detalles: {details}"

        # Colores para la terminal
        colors = {
            "CRITICO": "\033[91m",   # Rojo
            "ALERTA": "\033[93m",    # Amarillo
            "INFO": "\033[94m",      # Azul
        }
        reset = "\033[0m"
        color = colors.get(level, "")

        print(f"\n{color}{'!'*60}")
        print(f"  {alert_msg}")
        print(f"{'!'*60}{reset}\n")

        self.alerts.append(alert_msg)

        if self.output_file:
            try:
                with open(self.output_file, "a") as f:
                    f.write(alert_msg + "\n")
            except Exception:
                pass

    def process_packet(self, pkt):
        """
        Analiza cada paquete ARP capturado.

        Campos ARP relevantes:
        =====================================================================
        pkt[ARP].op      -> Operacion: 1=Request(who-has), 2=Reply(is-at)
        pkt[ARP].hwsrc   -> MAC origen (quien envia el ARP)
        pkt[ARP].psrc    -> IP origen (IP que el emisor dice tener)
        pkt[ARP].hwdst   -> MAC destino
        pkt[ARP].pdst    -> IP destino (IP por la que se pregunta)
        pkt[Ether].src   -> MAC origen en header Ethernet (capa 2)
        pkt[Ether].dst   -> MAC destino en header Ethernet
        =====================================================================
        """
        if not pkt.haslayer(ARP):
            return

        self.pkt_count += 1
        arp = pkt[ARP]

        # Solo analizar ARP Replies (op=2, is-at)
        # Los Replies son los que pueden envenenar tablas ARP
        if arp.op == 2:  # is-at (ARP Reply)
            src_ip = arp.psrc     # IP que dice tener
            src_mac = arp.hwsrc   # MAC que dice ser
            eth_src = pkt[Ether].src  # MAC real del header Ethernet

            # ============================================================
            # Deteccion 1: MAC inconsistente entre ARP y Ethernet
            # ============================================================
            # Si la MAC en el campo ARP no coincide con la del header
            # Ethernet, alguien esta manipulando los paquetes
            if src_mac != eth_src:
                self._alert(
                    "CRITICO",
                    f"MAC inconsistente en ARP Reply!",
                    f"IP={src_ip}, ARP.hwsrc={src_mac}, Ether.src={eth_src}"
                )

            # ============================================================
            # Deteccion 2: IP cambio de MAC (ARP Cache Poisoning)
            # ============================================================
            # Si ya conocemos la MAC de esta IP y ahora es diferente,
            # alguien esta intentando suplantar esa IP
            if src_ip in self.arp_table:
                known_mac = self.arp_table[src_ip]
                if src_mac != known_mac:
                    self._alert(
                        "CRITICO",
                        f"ARP SPOOFING DETECTADO! IP {src_ip} cambio de MAC",
                        f"MAC legitima={known_mac}, MAC atacante={src_mac}"
                    )
                    return  # No actualizar la tabla con MAC falsa
            else:
                # Primera vez que vemos esta IP, registrar como legitima
                self.arp_table[src_ip] = src_mac
                print(f"[+] Nueva entrada ARP: {src_ip} -> {src_mac}")

            # ============================================================
            # Deteccion 3: Rafaga de ARP Replies (comportamiento de ataque)
            # ============================================================
            # Un atacante de ARP Spoofing envia replies constantemente
            # para mantener las tablas ARP envenenadas
            now = time.time()
            self.reply_timestamps[src_ip].append(now)

            # Limpiar timestamps antiguos (fuera de la ventana)
            self.reply_timestamps[src_ip] = [
                t for t in self.reply_timestamps[src_ip]
                if now - t < self.time_window
            ]

            count = len(self.reply_timestamps[src_ip])
            if count >= self.reply_threshold:
                self._alert(
                    "ALERTA",
                    f"Rafaga de ARP Replies desde {src_ip}",
                    f"{count} replies en {self.time_window}s (umbral={self.reply_threshold})"
                )

            # ============================================================
            # Deteccion 4: Multiples IPs con la misma MAC (MITM)
            # ============================================================
            # Si el atacante suplanta multiples hosts, varias IPs
            # apuntaran a su MAC
            ips_with_same_mac = [
                ip for ip, mac in self.arp_table.items()
                if mac == src_mac and ip != src_ip
            ]
            if ips_with_same_mac:
                self._alert(
                    "CRITICO",
                    f"Multiples IPs con la misma MAC (posible MITM)",
                    f"MAC={src_mac}, IPs={[src_ip] + ips_with_same_mac}"
                )

        # Mostrar estado periodico
        if self.pkt_count % 20 == 0:
            print(f"\r[*] Paquetes ARP procesados: {self.pkt_count} | "
                  f"Alertas: {len(self.alerts)} | "
                  f"Hosts conocidos: {len(self.arp_table)}", end="", flush=True)

    def print_summary(self):
        """Muestra resumen del monitoreo."""
        print(f"\n\n{'='*60}")
        print(f"  Resumen de Monitoreo ARP")
        print(f"{'='*60}")
        print(f"  Paquetes ARP procesados: {self.pkt_count}")
        print(f"  Hosts detectados:        {len(self.arp_table)}")
        print(f"  Alertas generadas:       {len(self.alerts)}")

        if self.arp_table:
            print(f"\n  Tabla ARP conocida:")
            for ip, mac in sorted(self.arp_table.items()):
                print(f"    {ip:>15} -> {mac}")

        if self.alerts:
            print(f"\n  Alertas:")
            for alert in self.alerts:
                print(f"    {alert}")

        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor ARP para deteccion de ARP Spoofing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Monitoreo basico
  python3 arp_monitor.py

  # Con hosts conocidos del lab
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12

  # Guardar alertas
  python3 arp_monitor.py -o /logs/arp_alerts.log --known 172.20.0.2 172.20.0.10
        """
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--known", nargs="+", default=None,
                        help="IPs conocidas para establecer linea base")
    parser.add_argument("-o", "--output", default=None,
                        help="Archivo para guardar alertas")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Tiempo de monitoreo en segundos (0 = indefinido)")
    args = parser.parse_args()

    print("=" * 60)
    print("  ARP Monitor - Deteccion de ARP Spoofing")
    print("=" * 60)
    print(f"  Interface:  {args.interface}")
    print(f"  Hosts:      {args.known or 'Deteccion automatica'}")
    print(f"  Output:     {args.output or 'Solo consola'}")
    print("=" * 60)

    monitor = ARPMonitor(
        iface=args.interface,
        known_hosts=args.known,
        output_file=args.output
    )

    print(f"\n[*] Monitoreando trafico ARP... (Ctrl+C para detener)\n")

    try:
        sniff(
            iface=args.interface,
            filter="arp",
            prn=monitor.process_packet,
            store=False,
            timeout=args.timeout if args.timeout > 0 else None
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Error: Se requieren privilegios root")
        sys.exit(1)

    monitor.print_summary()


if __name__ == "__main__":
    main()
