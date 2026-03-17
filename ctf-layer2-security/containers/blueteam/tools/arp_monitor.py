#!/usr/bin/env python3
"""
=============================================================================
ARP Monitor - Detector de ARP Spoofing en tiempo real
=============================================================================
Este script monitorea el trafico ARP de la red para detectar ataques
de ARP Spoofing (ARP Cache Poisoning).

MODOS DE DETECCION:

  Modo Pasivo (--passive):
    Escucha ARP Replies en la red y detecta cambios de MAC.
    Funciona mejor cuando el monitor esta en el mismo segmento que las
    victimas y puede ver el trafico ARP unicast (modo promiscuo o hub).

  Modo Activo (default):
    Envia ARP Requests periodicos a los hosts conocidos y compara las
    respuestas con la baseline. Funciona en cualquier topologia porque
    genera su propio trafico de verificacion.
    Tecnica: "ARP Polling" - si un host responde con una MAC diferente
    a la registrada en la baseline, hay spoofing.

COMO DETECTA EL ATAQUE (Modo Activo):
  1. Resuelve las MACs reales de todos los hosts conocidos (baseline)
  2. Cada N segundos, envia ARP Request a cada host conocido
  3. Compara la MAC de respuesta con la baseline
  4. Si la MAC cambio, genera ALERTA (alguien esta suplantando ese host)
  5. Tambien detecta si multiples IPs responden con la misma MAC (MITM)

EJEMPLO DE USO:
  # Monitoreo activo (recomendado para Docker/switch)
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12

  # Monitoreo pasivo (para redes con hub o modo promiscuo)
  python3 arp_monitor.py --passive --known 172.20.0.2 172.20.0.10

  # Intervalo de probing personalizado
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 --probe-interval 3

  # Guardar alertas en archivo
  python3 arp_monitor.py -o /logs/arp_alerts.log --known 172.20.0.2 172.20.0.10

REQUISITOS:
  - Privilegios root (NET_RAW)
  - Scapy instalado
=============================================================================
"""

import argparse
import sys
import time
import signal
import threading
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, ARP, Ether, srp, conf


class ARPMonitor:
    """Monitor de trafico ARP para deteccion de ARP Spoofing."""

    def __init__(self, iface="eth0", known_hosts=None, output_file=None,
                 probe_interval=5):
        self.iface = iface
        self.output_file = output_file
        self.probe_interval = probe_interval

        # Tabla de asociaciones IP -> MAC conocidas (baseline)
        self.arp_table = {}

        # Lista de IPs a monitorear activamente
        self.known_ips = known_hosts or []

        # Contadores para deteccion de anomalias
        self.reply_timestamps = defaultdict(list)
        self.alerts = []
        self.pkt_count = 0
        self.probe_count = 0

        # Umbral: mas de N replies en M segundos = sospechoso
        self.reply_threshold = 5
        self.time_window = 10  # segundos

        # Control de ejecucion
        self.running = True

        # Pre-cargar hosts conocidos si se proporcionan
        if known_hosts:
            self._resolve_known_hosts(known_hosts)

    def _resolve_known_hosts(self, ip_list):
        """
        Resuelve las MACs reales de hosts conocidos via ARP Request.
        Esto establece la linea base legitima de la red.

        Se envia un ARP Request broadcast por cada IP:
          Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
        Solo el host real con esa IP responde con su MAC verdadera.
        """
        print(f"[*] Estableciendo baseline: resolviendo MACs de {len(ip_list)} hosts...")
        for ip in ip_list:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
            result = srp(pkt, iface=self.iface, timeout=2, verbose=False)[0]
            if result:
                mac = result[0][1].hwsrc
                self.arp_table[ip] = mac
                print(f"  [+] {ip} -> {mac} (baseline)")
            else:
                print(f"  [-] {ip} -> No responde")
        print()

    def _alert(self, level, message, details=None):
        """Genera y muestra una alerta de seguridad."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{level}] {message}"
        if details:
            alert_msg += f"\n    Detalles: {details}"

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

    # ==================================================================
    # MODO ACTIVO: ARP Polling
    # ==================================================================
    def active_probe(self):
        """
        Sondeo activo: envia ARP Requests a todos los hosts conocidos
        y compara la MAC de respuesta con la baseline.

        Tecnica: ARP Polling
        =====================================================================
        Para cada IP conocida:
          1. Envia: Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
          2. Recibe: ARP Reply con la MAC actual del host
          3. Compara con self.arp_table[ip] (la MAC de la baseline)
          4. Si difiere -> ALERTA: alguien esta respondiendo con otra MAC

        Por que funciona:
          - En una red con switch (o Docker bridge), el sniffer pasivo
            no ve los ARP Replies unicast entre otros hosts
          - Pero el sondeo activo GENERA trafico propio y recibe respuestas
            directamente, sin importar la topologia
          - Si hay un atacante haciendo ARP Spoofing, al preguntar por la
            IP del gateway podemos recibir DOS respuestas: la real y la
            del atacante (si el atacante responde a todos los requests)
          - O la respuesta puede venir con la MAC del atacante si este
            ha envenenado el gateway para que responda a traves de el
        =====================================================================
        """
        self.probe_count += 1

        for ip in self.known_ips:
            if not self.running:
                break

            # Enviar ARP Request
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
            result = srp(pkt, iface=self.iface, timeout=1, verbose=False)[0]

            if not result:
                continue

            # Verificar TODAS las respuestas (podrian llegar multiples)
            responding_macs = set()
            for sent, received in result:
                responding_macs.add(received.hwsrc)

            current_mac = list(responding_macs)[0]

            # Deteccion: Multiples respuestas a un solo ARP Request
            # Indica que hay dos hosts reclamando la misma IP
            if len(responding_macs) > 1:
                self._alert(
                    "CRITICO",
                    f"Multiples respuestas ARP para {ip}!",
                    f"MACs respondiendo: {responding_macs} "
                    f"(alguien esta suplantando esta IP)"
                )

            # Deteccion: MAC diferente a la baseline
            if ip in self.arp_table:
                baseline_mac = self.arp_table[ip]
                if current_mac != baseline_mac:
                    self._alert(
                        "CRITICO",
                        f"ARP SPOOFING DETECTADO! {ip} cambio de MAC",
                        f"MAC baseline={baseline_mac}, MAC actual={current_mac}\n"
                        f"    Alguien esta suplantando la IP {ip}"
                    )

        # Deteccion: Multiples IPs con la misma MAC (MITM clasico)
        mac_to_ips = defaultdict(list)
        for ip in self.known_ips:
            if ip in self.arp_table:
                # Resolver MAC actual (no baseline) para esta verificacion
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
                result = srp(pkt, iface=self.iface, timeout=1, verbose=False)[0]
                if result:
                    mac = result[0][1].hwsrc
                    mac_to_ips[mac].append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                self._alert(
                    "CRITICO",
                    f"Multiples IPs con la misma MAC (MITM detectado)",
                    f"MAC={mac}, IPs={ips}"
                )

    def run_active_probing(self):
        """Ejecuta el sondeo activo en un bucle periodico."""
        print(f"[*] Sondeo activo cada {self.probe_interval}s...")
        while self.running:
            self.active_probe()
            # Mostrar estado
            print(f"\r[*] Probe #{self.probe_count} | "
                  f"Alertas: {len(self.alerts)} | "
                  f"Hosts: {len(self.arp_table)}", end="", flush=True)
            time.sleep(self.probe_interval)

    # ==================================================================
    # MODO PASIVO: Sniffing de ARP
    # ==================================================================
    def process_packet(self, pkt):
        """
        Analiza cada paquete ARP capturado (modo pasivo).

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
        if arp.op == 2:
            src_ip = arp.psrc
            src_mac = arp.hwsrc
            eth_src = pkt[Ether].src

            # Deteccion 1: MAC inconsistente entre ARP y Ethernet
            if src_mac != eth_src:
                self._alert(
                    "CRITICO",
                    f"MAC inconsistente en ARP Reply!",
                    f"IP={src_ip}, ARP.hwsrc={src_mac}, Ether.src={eth_src}"
                )

            # Deteccion 2: IP cambio de MAC
            if src_ip in self.arp_table:
                known_mac = self.arp_table[src_ip]
                if src_mac != known_mac:
                    self._alert(
                        "CRITICO",
                        f"ARP SPOOFING DETECTADO! IP {src_ip} cambio de MAC",
                        f"MAC legitima={known_mac}, MAC atacante={src_mac}"
                    )
                    return
            else:
                self.arp_table[src_ip] = src_mac
                print(f"[+] Nueva entrada ARP: {src_ip} -> {src_mac}")

            # Deteccion 3: Rafaga de ARP Replies
            now = time.time()
            self.reply_timestamps[src_ip].append(now)
            self.reply_timestamps[src_ip] = [
                t for t in self.reply_timestamps[src_ip]
                if now - t < self.time_window
            ]
            count = len(self.reply_timestamps[src_ip])
            if count >= self.reply_threshold:
                self._alert(
                    "ALERTA",
                    f"Rafaga de ARP Replies desde {src_ip}",
                    f"{count} replies en {self.time_window}s"
                )

            # Deteccion 4: Multiples IPs con la misma MAC
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

        if self.pkt_count % 20 == 0:
            print(f"\r[*] Paquetes ARP: {self.pkt_count} | "
                  f"Alertas: {len(self.alerts)} | "
                  f"Hosts: {len(self.arp_table)}", end="", flush=True)

    def print_summary(self):
        """Muestra resumen del monitoreo."""
        print(f"\n\n{'='*60}")
        print(f"  Resumen de Monitoreo ARP")
        print(f"{'='*60}")
        print(f"  Paquetes ARP procesados: {self.pkt_count}")
        print(f"  Sondeos activos:         {self.probe_count}")
        print(f"  Hosts en baseline:       {len(self.arp_table)}")
        print(f"  Alertas generadas:       {len(self.alerts)}")

        if self.arp_table:
            print(f"\n  Tabla ARP baseline:")
            for ip, mac in sorted(self.arp_table.items()):
                print(f"    {ip:>15} -> {mac}")

        if self.alerts:
            print(f"\n  Alertas:")
            for alert in self.alerts:
                print(f"    {alert}")
        else:
            print(f"\n  No se detectaron anomalias ARP.")

        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor ARP para deteccion de ARP Spoofing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Monitoreo activo (recomendado)
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 172.20.0.11 172.20.0.12

  # Monitoreo pasivo
  python3 arp_monitor.py --passive --known 172.20.0.2 172.20.0.10

  # Intervalo de sondeo personalizado
  python3 arp_monitor.py --known 172.20.0.2 172.20.0.10 --probe-interval 3

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
    parser.add_argument("--passive", action="store_true",
                        help="Modo pasivo: solo escuchar (sin sondeo activo)")
    parser.add_argument("--probe-interval", type=int, default=5,
                        help="Intervalo de sondeo activo en segundos (default: 5)")
    args = parser.parse_args()

    mode = "Pasivo (sniffing)" if args.passive else "Activo (ARP polling)"

    print("=" * 60)
    print("  ARP Monitor - Deteccion de ARP Spoofing")
    print("=" * 60)
    print(f"  Interface:  {args.interface}")
    print(f"  Modo:       {mode}")
    print(f"  Hosts:      {args.known or 'Deteccion automatica'}")
    print(f"  Output:     {args.output or 'Solo consola'}")
    if not args.passive:
        print(f"  Probe int:  {args.probe_interval}s")
    print("=" * 60)

    monitor = ARPMonitor(
        iface=args.interface,
        known_hosts=args.known,
        output_file=args.output,
        probe_interval=args.probe_interval
    )

    # Manejar señales para salida limpia
    def signal_handler(sig, frame):
        monitor.running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.passive:
        # Modo pasivo: solo sniffing
        print(f"\n[*] Modo pasivo: escuchando trafico ARP... (Ctrl+C para detener)\n")
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
    else:
        # Modo activo: sondeo periodico + sniffing en background
        print(f"\n[*] Modo activo: sondeando hosts cada {args.probe_interval}s... "
              f"(Ctrl+C para detener)\n")

        # Sniffing pasivo en hilo de background (captura lo que pueda)
        sniffer_thread = threading.Thread(
            target=lambda: sniff(
                iface=args.interface,
                filter="arp",
                prn=monitor.process_packet,
                store=False,
                stop_filter=lambda x: not monitor.running,
                timeout=args.timeout if args.timeout > 0 else None
            ),
            daemon=True
        )
        sniffer_thread.start()

        # Sondeo activo en hilo principal
        try:
            start = time.time()
            while monitor.running:
                if args.timeout > 0 and (time.time() - start) >= args.timeout:
                    break
                monitor.active_probe()
                print(f"\r[*] Probe #{monitor.probe_count} | "
                      f"Alertas: {len(monitor.alerts)} | "
                      f"Hosts: {len(monitor.arp_table)}", end="", flush=True)
                time.sleep(args.probe_interval)
        except KeyboardInterrupt:
            monitor.running = False

    monitor.print_summary()


if __name__ == "__main__":
    main()
