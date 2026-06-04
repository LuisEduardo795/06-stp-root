# 06-stp-root
Ataque STP Root Claim

## Información del Laboratorio
- **Asignatura:** Seguridad de Redes
- **Estudiante:** Tu Nombre Completo
- **Matrícula:** Tu Matrícula
- **Fecha:** Junio 2026

---

## Objetivo del Laboratorio
Demostrar cómo un atacante puede manipular el protocolo STP
(Spanning Tree Protocol) enviando BPDUs maliciosos con prioridad
mínima para proclamarse Root Bridge, redirigiendo todo el tráfico
de capa 2 de la red a través del atacante y causando inestabilidad
en la topología.

---

## Objetivo del Script
Enviar BPDUs (Bridge Protocol Data Units) con prioridad 0 y
Bridge-ID mínimo para que el atacante sea elegido Root Bridge
por los switches de la red.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red (ej: eth0) | Obligatorio |
| `--priority` | Prioridad STP (múltiplo de 4096) | 0 |
| `-c` | BPDUs a enviar (0=infinito) | 0 |
| `--hello-time` | Hello time en segundos | 2.0 |
| `--max-age` | Max age en segundos | 20.0 |
| `--fwd-delay` | Forward delay en segundos | 15.0 |
| `--vlan` | VLAN ID | 1 |
| `--path-cost` | Path cost al Root | 0 |
| `--monitor` | Monitorear BPDUs entrantes | False |
| `-v` | Modo verbose | False |

### Requisitos
- Sistema operativo: Kali Linux / Ubuntu
- Python 3.8+
- Scapy: `pip3 install scapy`
- Privilegios root

- 
## Topología de Red
<img width="512" height="356" alt="image" src="https://github.com/user-attachments/assets/b2160e1d-aa9f-4d81-9241-4881b64e6856" />

| Dispositivo | Interfaz | IP |
|---|---|---|
| Ubuntu-Atacante | eth0 | 192.168.1.50/24 |
| SW-Core | e0/0 - e0/1 | — |
| Linux-Victima | eth0 | 192.168.1.10/24 |


## Funcionamiento del Script

1. Obtiene la MAC de la interfaz del atacante
2. Construye BPDUs Configuration con:
   - Root Bridge ID: `0 / attacker_mac` (prioridad mínima)
   - Path Cost: 0 (indica que somos el Root directamente)
   - Hello Time, Max Age y Forward Delay estándar
3. Envía al multicast `01:80:c2:00:00:00` (dirección STP)
4. Los switches comparan el Bridge-ID recibido con el Root actual
5. Si el Bridge-ID del atacante es menor, lo eligen como Root
6. Se recalcula el árbol STP y el tráfico fluye por el atacante

## Uso

```bash
# Ataque básico con prioridad 0
sudo python3 stp_root.py -i eth0 --priority 0

# Con monitoreo de BPDUs para verificar éxito
sudo python3 stp_root.py -i eth0 --priority 0 --monitor

# Enviar 50 BPDUs con verbose
sudo python3 stp_root.py -i eth0 --priority 0 -c 50 -v

# Verificar en el switch
# show spanning-tree vlan 1
```

### Verificar el ataque desde el switch
```cisco
show spanning-tree vlan 1
! El Root Bridge debe mostrar la MAC del atacante
! con prioridad 0

show spanning-tree detail
! Muestra el recálculo del árbol STP
```

---

## Contramedidas

### En el switch Cisco
```cisco
! BPDU Guard — deshabilita puerto si recibe BPDU
spanning-tree portfast bpduguard default
!
interface range FastEthernet0/1-24
 spanning-tree portfast
 spanning-tree bpduguard enable
!
! Root Guard — no permite nuevos Root Bridge por ese puerto
interface GigabitEthernet0/1
 spanning-tree guard root
!
! Establecer prioridad baja en switch legítimo
spanning-tree vlan 1,10,20 priority 4096
```

### Verificación de la contramedida
```cisco
show spanning-tree vlan 1
show spanning-tree inconsistentports
show errdisable recovery
```
