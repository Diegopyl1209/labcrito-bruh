import os
import socket
import struct
import time
import select
import sys
import random
import string

from main1 import cesar

ICMP_ECHO_REQUEST = 8 # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
ICMP_CODE = 0

ICMP_DATALEN = 64 - 8 # 64 bytes - 8 bytes del header

# el checksum se calcula sumando los pares de bytes de 16 bits
def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00" # si el numero de bytes es impar se añade 0x00
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1] # el resultado es de 16 bits asi q la parte mas significate se corre a la izquierda
    s = (s >> 16) + (s & 0xFFFF) # si s es mayor a 16 (es decir mayor a 16 bits) se trunca a 16 bits y se suma el carry (los bits que hayan quedado a la izquierda pasado los 16 bits permitidos)
    s += (s >> 16) # se vuelve a añadir el carry en caso de que la suma anterior tambien haya ocasionado un overflow
    return ~s & 0xFFFF

def build_icmp_echo(identifier: int, sequence: int, payload: bytes) -> bytes:
    # estructura del header: big endian, 1 byte, 1 byte, 2 bytes, 2 bytes
    #                              type               code       checksum identifier  sequience
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, 0,       identifier, sequence)
    chk = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, chk, identifier, sequence)
    return header + payload

#sobrescribe los primeros 16 bytes del payload con un timestamp (sec,usec)
def add_timestamp(payload: bytes) -> bytes:
    now = time.time()
    sec = int(now)
    usec = int((now - sec) * 1_000_000)

    # 2 enteros de 8 bytes
    timeval = struct.pack("!QQ", sec, usec)

    payload = bytearray(payload)

    payload[:len(timeval)] = timeval
    return bytes(payload)

def send_icmp(dest: str, payload: bytes, seq: int = 1):
    proto = socket.getprotobyname("icmp")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, proto) as sock:
        # sobreescribe el inicio del payload con timestamp
        payload = add_timestamp(payload)
        # normalmente el identificador es el pid del proceso que manda el ping
        # seq es el numero del paquete enviado, si mandamos n paquetes, el primer paquete sera 1, segundo 2 y asi...
        packet = build_icmp_echo(os.getpid() & 0xFFFF, seq, payload)
        sock.sendto(packet, (dest, 0))
        print(f"ICMP enviado a {dest} con payload len={len(payload)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python script.py <texto> <desplazamiento>")
        sys.exit(1)

    text = sys.argv[1]
    desplazamiento = int(sys.argv[2])

    cifrado = cesar(text, desplazamiento)
    #print(cifrado)

    icmp_data = bytearray()

    for i in range(ICMP_DATALEN - 1):
        icmp_data.append(i);

    #print(icmp_data)

    for char in cifrado:
        send_icmp("8.8.8.8", icmp_data + char.encode())
