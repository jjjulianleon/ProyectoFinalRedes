#!/usr/bin/env python3
"""
=============================================================================
MAC Anomaly Detector - Detector de MAC Flooding
=============================================================================
Este script detecta ataques de MAC Flooding monitoreando la cantidad
de direcciones MAC unicas que aparecen en la red.

COMO DETECTA EL ATAQUE:
  1. Monitorea todos los frames Ethernet en la red
  2. Registra cada MAC origen unica que observa
  3. Calcula la tasa de nuevas MACs por intervalo de tiempo
  4. Si la tasa supera un umbral, genera una ALERTA
  5. Tambien detecta MACs con formato sospechoso (aleatorias)

INDICADORES DE MAC FLOODING:
  - Aparicion masiva de MACs nuevas en poco tiempo
  - MACs con patrones aleatorios (sin OUI de fabricante conocido)
  - Trafico broadcast excesivo con MACs desconocidas
  - ARP Requests desde cientos de MACs diferentes

EJEMPLO DE USO:
  # Deteccion basica
  python3 mac_anomaly_detector.py

  # Con umbral personalizado (50 nuevas MACs en 10 segundos)
  python3 mac_anomaly_detector.py --threshold 50 --window 10

  # Guardar alertas en archivo
  python3 mac_anomaly_detector.py -o /logs/mac_flood_alerts.log

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
from scapy.all import sniff, Ether, ARP, conf


# OUIs conocidos de Docker y virtualizacion (primeros 3 bytes de la MAC)
KNOWN_OUIS = {
    "02:42": "Docker",
    "52:54": "QEMU/KVM",
    "08:00": "Oracle VirtualBox",
    "00:0c": "VMware",
    "00:50": "VMware",
}


class MACFloodDetector:
    """Detector de ataques de MAC Flooding."""

    def __init__(self, iface="eth0", threshold=30, window=10, output_file=None):
        self.iface = iface
        self.threshold = threshold     # Nuevas MACs para disparar alerta
        self.window = window           # Ventana de tiempo en segundos
        self.output_file = output_file

        # Registro de MACs
        self.known_macs = set()        # MACs vistas desde el inicio
        self.baseline_macs = set()     # MACs del periodo de aprendizaje
        self.new_mac_times = []        # Timestamps de nuevas MACs
        self.mac_to_ip = {}            # Asociacion MAC -> ultima IP vista
        self.suspicious_macs = set()   # MACs sospechosas (aleatorias)

        # Contadores
        self.pkt_count = 0
        self.alerts = []
        self.flood_detected = False

        # Estado del periodo de aprendizaje
        self.learning = True
        self.learning_start = time.time()
        self.learning_duration = 15  # segundos de aprendizaje inicial

    def _is_random_mac(self, mac):
        """
        Determina si una MAC parece ser aleatoria (generada por herramienta).

        Criterios:
        - No pertenece a un OUI conocido
        - Bit de "locally administered" activado (segundo bit del primer byte)
          Las MACs generadas por herramientas suelen tener este bit en 1
        """
        # Verificar OUI conocido
        prefix = mac[:5]
        if prefix in KNOWN_OUIS:
            return False

        # Verificar bit "locally administered"
        # El segundo bit del primer byte indica MAC local (no asignada por IEEE)
        first_byte = int(mac.split(":")[0], 16)
        is_local = bool(first_byte & 0x02)

        return is_local

    def _get_oui_vendor(self, mac):
        """Retorna el vendor basado en el OUI, o 'Desconocido'."""
        prefix = mac[:5]
        return KNOWN_OUIS.get(prefix, "Desconocido")

    def _alert(self, level, message, details=None):
        """Genera una alerta de seguridad."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{level}] {message}"
        if details:
            alert_msg += f"\n    Detalles: {details}"

        colors = {
            "CRITICO": "\033[91m",
            "ALERTA": "\033[93m",
            "INFO": "\033[94m",
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
        Analiza cada frame Ethernet capturado.

        Campos relevantes:
        =====================================================================
        pkt[Ether].src   -> MAC origen del frame (la que registra el switch)
        pkt[Ether].dst   -> MAC destino del frame
        pkt[Ether].type  -> EtherType (0x0800=IP, 0x0806=ARP, etc.)
        =====================================================================
        """
        if not pkt.haslayer(Ether):
            return

        self.pkt_count += 1
        src_mac = pkt[Ether].src
        now = time.time()

        # Asociar MAC con IP si el paquete tiene capa ARP
        if pkt.haslayer(ARP):
            self.mac_to_ip[src_mac] = pkt[ARP].psrc

        # ==================================================================
        # Periodo de aprendizaje (primeros N segundos)
        # ==================================================================
        # Durante este periodo, registramos las MACs legitimas de la red
        # sin generar alertas. Esto establece la linea base.
        if self.learning:
            self.known_macs.add(src_mac)
            self.baseline_macs.add(src_mac)

            elapsed = now - self.learning_start
            if elapsed >= self.learning_duration:
                self.learning = False
                print(f"\n[+] Aprendizaje completado: {len(self.baseline_macs)} "
                      f"MACs legitimas registradas")
                for mac in sorted(self.baseline_macs):
                    vendor = self._get_oui_vendor(mac)
                    ip = self.mac_to_ip.get(mac, "N/A")
                    print(f"    {mac} ({vendor}) -> {ip}")
                print(f"\n[*] Monitoreando anomalias... (Ctrl+C para detener)\n")
            else:
                remaining = self.learning_duration - elapsed
                if self.pkt_count % 10 == 0:
                    print(f"\r[*] Aprendizaje: {len(self.known_macs)} MACs | "
                          f"Quedan {remaining:.0f}s", end="", flush=True)
            return

        # ==================================================================
        # Deteccion de MAC nueva (post-aprendizaje)
        # ==================================================================
        if src_mac not in self.known_macs:
            self.known_macs.add(src_mac)
            self.new_mac_times.append(now)

            # Verificar si la MAC parece aleatoria
            if self._is_random_mac(src_mac):
                self.suspicious_macs.add(src_mac)

            # Limpiar timestamps fuera de la ventana
            self.new_mac_times = [
                t for t in self.new_mac_times
                if now - t < self.window
            ]

            new_count = len(self.new_mac_times)

            # ==============================================================
            # Deteccion: Tasa de nuevas MACs supera el umbral
            # ==============================================================
            if new_count >= self.threshold:
                if not self.flood_detected:
                    self.flood_detected = True
                    suspicious_pct = (
                        len(self.suspicious_macs) / len(self.known_macs) * 100
                        if self.known_macs else 0
                    )
                    self._alert(
                        "CRITICO",
                        f"MAC FLOODING DETECTADO!",
                        f"{new_count} nuevas MACs en {self.window}s "
                        f"(umbral={self.threshold})\n"
                        f"    Total MACs vistas: {len(self.known_macs)} "
                        f"(baseline: {len(self.baseline_macs)})\n"
                        f"    MACs sospechosas (aleatorias): "
                        f"{len(self.suspicious_macs)} ({suspicious_pct:.0f}%)"
                    )
            elif new_count >= self.threshold // 2:
                self._alert(
                    "ALERTA",
                    f"Tasa elevada de nuevas MACs",
                    f"{new_count} nuevas MACs en {self.window}s "
                    f"(umbral={self.threshold})"
                )

        # Estado periodico
        if self.pkt_count % 50 == 0:
            total_new = len(self.known_macs) - len(self.baseline_macs)
            print(f"\r[*] Pkts: {self.pkt_count} | "
                  f"MACs base: {len(self.baseline_macs)} | "
                  f"Nuevas: {total_new} | "
                  f"Sospechosas: {len(self.suspicious_macs)} | "
                  f"Alertas: {len(self.alerts)}", end="", flush=True)

    def print_summary(self):
        """Muestra resumen del monitoreo."""
        total_new = len(self.known_macs) - len(self.baseline_macs)

        print(f"\n\n{'='*60}")
        print(f"  Resumen de Deteccion MAC Flooding")
        print(f"{'='*60}")
        print(f"  Paquetes procesados:    {self.pkt_count}")
        print(f"  MACs en baseline:       {len(self.baseline_macs)}")
        print(f"  MACs nuevas detectadas: {total_new}")
        print(f"  MACs sospechosas:       {len(self.suspicious_macs)}")
        print(f"  Alertas generadas:      {len(self.alerts)}")
        print(f"  Flooding detectado:     {'SI' if self.flood_detected else 'NO'}")

        if self.alerts:
            print(f"\n  Alertas:")
            for alert in self.alerts:
                print(f"    {alert}")

        if self.suspicious_macs and len(self.suspicious_macs) <= 20:
            print(f"\n  Muestra de MACs sospechosas:")
            for mac in list(self.suspicious_macs)[:20]:
                print(f"    {mac}")

        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Detector de MAC Flooding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Deteccion basica
  python3 mac_anomaly_detector.py

  # Umbral personalizado
  python3 mac_anomaly_detector.py --threshold 50 --window 10

  # Guardar alertas
  python3 mac_anomaly_detector.py -o /logs/mac_flood.log
        """
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--threshold", type=int, default=30,
                        help="Nuevas MACs para disparar alerta (default: 30)")
    parser.add_argument("--window", type=int, default=10,
                        help="Ventana de tiempo en segundos (default: 10)")
    parser.add_argument("--learning-time", type=int, default=15,
                        help="Duracion del periodo de aprendizaje en seg (default: 15)")
    parser.add_argument("-o", "--output", default=None,
                        help="Archivo para guardar alertas")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Tiempo de monitoreo en segundos (0 = indefinido)")
    args = parser.parse_args()

    print("=" * 60)
    print("  MAC Anomaly Detector - Deteccion de MAC Flooding")
    print("=" * 60)
    print(f"  Interface:     {args.interface}")
    print(f"  Umbral:        {args.threshold} nuevas MACs en {args.window}s")
    print(f"  Aprendizaje:   {args.learning_time}s")
    print(f"  Output:        {args.output or 'Solo consola'}")
    print("=" * 60)

    detector = MACFloodDetector(
        iface=args.interface,
        threshold=args.threshold,
        window=args.window,
        output_file=args.output
    )
    detector.learning_duration = args.learning_time

    print(f"\n[*] Periodo de aprendizaje ({args.learning_time}s)...\n")

    try:
        sniff(
            iface=args.interface,
            prn=detector.process_packet,
            store=False,
            timeout=args.timeout if args.timeout > 0 else None
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Error: Se requieren privilegios root")
        sys.exit(1)

    detector.print_summary()


if __name__ == "__main__":
    main()
