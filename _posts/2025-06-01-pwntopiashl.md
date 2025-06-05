---
title: pwntopiashl (Fail)
date: 2025-06-01 10:39:00 -0700
categories: [N0PSctf]
tags: [reverse_engineering, re, fail]     # TAG names should always be lowercase
---
![N0PSctf Logo](/assets/img/logo-nopsctf.png){: .right }
> N0PStopia has been attacked by PwnTopia! They installed a stealthy binary on one of our servers, but we did not understand what it does! Can you help? We saw some weird ICMP traffic during the attack, you can find attached a capture file.

We were given an elf binary and a pcap that had captured traffic from the binary. ChatGPT and I went round and round for days, right up to the last minute, and just didn't get it.

The solution was 'simple' and elegant:

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

>The gist is that C2 traffic is hidden inside ICMP packets. The checksum fields are (mis)used to establish a secret symmetric XOR key between server and client (2 bytes each, plus some derived values you can find in the Python script). Then data is sent in the "data" field of the ICMP packet.

>All you need to do is go through the packets, decrypt them, and in the final plaintext will be your flag. Make sure you update the key whenever new keys are exchanged between client and server in the PCAP. - wallaby

As this was a fail, I'm going to do a little necropsy to see what went wrong and what could be improved going forward.

> The first misstep happened immediately as I didn't switch from o4 to o4-mini or o4-mini-high.
{: .prompt-warning }

1. Presented the binary to ChatGPT and asked if it could tell what the file was doing. ChatGPT read the magic bytes and confirmed that it was a 64-bit ELF binary. It asked where I wanted to go next and I chose to check for obfuscation. It did not find any obfuscation, stripping, or packing. Next it offered to disassemble or decompile the binary, and I didn't expect much as it usually says it doesn't have access to gdb or Ghidra. It honed in on icmp_packet_listener and wanted to go deeper into it.
2. Presented the pcap file to ChatGPT. It confirmed through magic bytes that it was a valid pcap file and then immediately stated that it didn't have access to pyshark, scapy, or tshark.
