import os
import socket
import struct
import time
import select
import sys
import random
import pyshark

from main1 import cesar

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python script.py <texto>")
        sys.exit(1)

    text = sys.argv[1]

    cap = pyshark.FileCapture("dump.pcapng", display_filter="icmp and ip.dst==8.8.8.8")
    captured_str = ""

    for pkt in cap:
        try:
            payload_hex = pkt.icmp.data
            payload_bytes = bytes.fromhex(payload_hex)
            payload_str = payload_bytes.decode(errors="ignore")
            captured_str += payload_str[39]
        except AttributeError:
            pass
    print(captured_str)

    desp = 0
    while(True):
        tex = cesar(captured_str, desp)
        print(f"desplazamiento: {desp}")
        print(tex)
        if tex == text:
            print(f"encontrado, desplazamiento usado al encriptar: {26 - desp}")
            break;
        if desp > 26:
            break;
        desp+=1
