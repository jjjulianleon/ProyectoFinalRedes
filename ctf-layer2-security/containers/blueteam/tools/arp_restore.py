#!/usr/bin/env python3
"""
=============================================================================
ARP Restore - Restaurador de tablas ARP
=============================================================================
Este script repara las tablas ARP de los hosts de la red despues de un
ataque de ARP Spoofing, restaurando las asociaciones IP <-> MAC correctas.

COMO FUNCIONA:
  1. Resuelve las MACs reales de todos los hosts via ARP Request
  2. Envia ARP Replies correctos a cada host para corregir sus tablas
  3. Puede ejecutarse una vez o en modo continuo para proteger la red
  4. Opcionalmente configura entradas ARP estaticas (inmunes a spoofing)

METODOS DE RESTAURACION:
  - Gratuitous ARP: Envia ARP Reply broadcast con la MAC correcta
  - Directed ARP: Envia ARP Reply unicast a cada host afectado
  - Static ARP: Configura entradas estaticas en la tabla ARP local

EJEMPLO DE USO:
  # Restaurar tablas ARP de todos los hosts del lab
  python3 arp_restore.py

  # Restaurar y proteger continuamente (cada 5 segundos)
  python3 arp_restore.py --continuous --interval 5

  # Restaurar hosts especificos
  python3 arp_restore.py --hosts 172.20.0.10 172.20.0.11 172.20.0.12

  # Configurar ARP estatico local
  python3 arp_restore.py --static

REQUISITOS:
  - Privilegios root (NET_ADMIN + NET_RAW)
  - Scapy instalado
=============================================================================
"""

import argparse
import os
import sys
import time
import signal
from scapy.all import Ether, ARP, srp, sendp, get_if_hwaddr, conf


# Hosts del laboratorio CTF
DEFAULT_HOSTS = [
    "172.20.0.2",    # Gateway
    "172.20.0.10",   # Victim 1
    "172.20.0.11",   # Victim 2
    "172.20.0.12",   # Victim 3
    "172.20.0.100",  # Red Team
]


def resolve_mac(ip, iface, timeout=2):
    """
    Obtiene la MAC real de un host via ARP Request.

    Paquete enviado:
      Ether(dst="ff:ff:ff:ff:ff:ff") -> Broadcast L2
      ARP(op="who-has", pdst=ip)     -> "Quien tiene esta IP?"

    Solo el host con esa IP responde con su MAC real.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
    result = srp(pkt, iface=iface, timeout=timeout, verbose=False)[0]

    if result:
        return result[0][1].hwsrc
    return None


def resolve_all_hosts(hosts, iface):
    """
    Resuelve las MACs reales de todos los hosts especificados.

    Retorna un diccionario {ip: mac} con solo los hosts que respondieron.
    """
    print(f"[*] Resolviendo MACs reales de {len(hosts)} hosts...")
    host_table = {}

    for ip in hosts:
        mac = resolve_mac(ip, iface)
        if mac:
            host_table[ip] = mac
            print(f"  [+] {ip:>15} -> {mac}")
        else:
            print(f"  [-] {ip:>15} -> No responde (host apagado?)")

    print(f"\n[+] {len(host_table)}/{len(hosts)} hosts resueltos")
    return host_table


def send_restore_packet(target_ip, target_mac, source_ip, source_mac, iface):
    """
    Envia un ARP Reply correcto al target para restaurar su tabla ARP.

    =========================================================================
    Paquete ARP Reply de restauracion:
    =========================================================================
    Capa 2 - Ethernet
      dst = target_mac           -> Unicast al host que queremos corregir
      src = source_mac           -> MAC REAL del host que estamos restaurando

    Capa 2.5 - ARP
      op = 2 (is-at)             -> ARP Reply
      pdst = target_ip           -> IP del host que debe actualizar su tabla
      hwdst = target_mac         -> MAC del host destino
      psrc = source_ip           -> IP que estamos restaurando
      hwsrc = source_mac         -> MAC REAL (la correcta, no la del atacante)

    RESULTADO: El target actualiza su tabla ARP con la MAC correcta
    =========================================================================
    """
    pkt = Ether(dst=target_mac, src=source_mac) / ARP(
        op="is-at",
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac    # MAC REAL - esto es lo que restaura la tabla
    )
    sendp(pkt, iface=iface, verbose=False)


def send_gratuitous_arp(ip, mac, iface):
    """
    Envia un Gratuitous ARP para anunciar la asociacion IP-MAC correcta.

    Un Gratuitous ARP es un ARP Reply broadcast donde:
    - psrc = pdst (la misma IP)
    - dst = broadcast (todos lo reciben)

    Todos los hosts de la red actualizan su tabla ARP con esta info.

    =========================================================================
    Paquete Gratuitous ARP:
    =========================================================================
    Capa 2 - Ethernet
      dst = "ff:ff:ff:ff:ff:ff"  -> Broadcast (todos reciben)
      src = mac                  -> MAC real del host

    Capa 2.5 - ARP
      op = 2 (is-at)             -> ARP Reply
      psrc = ip                  -> "Yo soy esta IP..."
      hwsrc = mac                -> "...y mi MAC es esta"
      pdst = ip                  -> (misma IP, gratuitous)
      hwdst = "ff:ff:ff:ff:ff:ff" -> (broadcast)
    =========================================================================
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
        op="is-at",
        psrc=ip,
        hwsrc=mac,
        pdst=ip,
        hwdst="ff:ff:ff:ff:ff:ff"
    )
    sendp(pkt, iface=iface, verbose=False)


def restore_once(host_table, iface):
    """
    Ejecuta una ronda de restauracion ARP.

    Para cada par de hosts (A, B):
    - Envia a A la MAC real de B
    - Envia a B la MAC real de A

    Ademas envia Gratuitous ARP para cada host.
    """
    hosts = list(host_table.items())
    packets_sent = 0

    # Restaurar cada par de hosts
    for i, (ip_a, mac_a) in enumerate(hosts):
        # Gratuitous ARP para que toda la red sepa la MAC correcta
        send_gratuitous_arp(ip_a, mac_a, iface)
        packets_sent += 1

        # Restaurar la tabla de cada otro host
        for j, (ip_b, mac_b) in enumerate(hosts):
            if i != j:
                send_restore_packet(ip_b, mac_b, ip_a, mac_a, iface)
                packets_sent += 1

    return packets_sent


def set_static_arp(host_table):
    """
    Configura entradas ARP estaticas en la tabla local.

    Las entradas estaticas NO pueden ser sobrescritas por ARP Replies,
    lo que las hace inmunes a ARP Spoofing.

    Comando: arp -s <ip> <mac>
    """
    print(f"\n[*] Configurando entradas ARP estaticas...")
    for ip, mac in host_table.items():
        os.system(f"arp -s {ip} {mac}")
        print(f"  [+] Estatico: {ip} -> {mac}")
    print(f"[+] {len(host_table)} entradas estaticas configuradas")


def main():
    parser = argparse.ArgumentParser(
        description="Restaurador de tablas ARP - Contramedida contra ARP Spoofing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Restaurar una vez
  python3 arp_restore.py

  # Restaurar continuamente (proteccion activa)
  python3 arp_restore.py --continuous --interval 3

  # Restaurar hosts especificos
  python3 arp_restore.py --hosts 172.20.0.10 172.20.0.2

  # Configurar ARP estatico
  python3 arp_restore.py --static
        """
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--hosts", nargs="+", default=None,
                        help="IPs a restaurar (default: todos los hosts del lab)")
    parser.add_argument("--continuous", action="store_true",
                        help="Modo continuo (restaurar periodicamente)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Intervalo en segundos para modo continuo (default: 5)")
    parser.add_argument("--count", type=int, default=3,
                        help="Paquetes por restauracion (default: 3)")
    parser.add_argument("--static", action="store_true",
                        help="Configurar entradas ARP estaticas")
    args = parser.parse_args()

    hosts = args.hosts or DEFAULT_HOSTS

    print("=" * 60)
    print("  ARP Restore - Restauracion de Tablas ARP")
    print("=" * 60)
    print(f"  Interface: {args.interface}")
    print(f"  Hosts:     {len(hosts)} hosts")
    print(f"  Modo:      {'Continuo' if args.continuous else 'Una vez'}")
    print("=" * 60)

    # Resolver MACs reales
    host_table = resolve_all_hosts(hosts, args.interface)

    if not host_table:
        print("[!] No se resolvio ningun host. Verifica la conectividad.")
        sys.exit(1)

    # Configurar ARP estatico si se pidio
    if args.static:
        set_static_arp(host_table)

    # Restaurar
    if args.continuous:
        print(f"\n[*] Restauracion continua cada {args.interval}s (Ctrl+C para detener)\n")
        total_sent = 0
        rounds = 0

        running = True

        def stop_handler(sig, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, stop_handler)
        signal.signal(signal.SIGTERM, stop_handler)

        while running:
            for _ in range(args.count):
                sent = restore_once(host_table, args.interface)
                total_sent += sent
            rounds += 1
            print(f"\r[*] Ronda {rounds} | Paquetes enviados: {total_sent}", end="", flush=True)
            time.sleep(args.interval)

        print(f"\n\n[+] Restauracion detenida. Total: {total_sent} paquetes en {rounds} rondas")
    else:
        print(f"\n[*] Restaurando tablas ARP...")
        total_sent = 0
        for _ in range(args.count):
            sent = restore_once(host_table, args.interface)
            total_sent += sent
        print(f"[+] Restauracion completada: {total_sent} paquetes enviados")


if __name__ == "__main__":
    main()
