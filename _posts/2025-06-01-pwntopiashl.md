---
title: pwntopiashl
date: 2025-06-01 10:39:00 -0700
categories: [N0PSctf]
tags: [reverse_engineering, re, fail]     # TAG names should always be lowercase
---

> N0PStopia has been attacked by PwnTopia! They installed a stealthy binary on one of our servers, but we did not understand what it does! Can you help? We saw some weird ICMP traffic during the attack, you can find attached a capture file.

We were given an elf binary and a pcap that had captured traffic from the binary. ChatGPT and I went round and round for days, right up to the last minute, and I just didn't get it.

The solution was simple and elegant:

```python
import struct

from pwn import xor
from scapy.all import *

def genkey(keybase: bytes) -> bytes:
    key = bytearray(8)

    key[0:4] = keybase
    key[4] = key[1] ^ key[0]
    key[5] = key[3] ^ key[2]
    key[6] = key[2] ^ key[0]
    key[7] = key[3] ^ key[1]

    return (bytes(key))

def decrypt(keybase, data):
    key = genkey(keybase)

    return xor(data, key)
    

def main():
    pcap = rdpcap("capture.pcap")

    k1 = b""
    k2 = b""
    update_k2 = False

    for packet in pcap:
        icmp = packet[ICMP]

        match icmp.type:
            case 12:
                k1 = struct.pack(">H", icmp.chksum)
                update_k2 = True
            case _:
                if update_k2:
                    k2 = struct.pack(">H", icmp.chksum)
                    update_k2 = False

        if icmp.payload:
            plain = decrypt(k1 + k2, bytes(icmp.payload))
            print(plain)

if __name__ == "__main__":
    main()
```
