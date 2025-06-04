---
title: Break My Stream
date: 2025-06-01 10:38:00 -0700
categories: [N0PSctf]
tags: [cryptography]     # TAG names should always be lowercase
---

> CrypTopia is testing their next gen encryption algorithm. We believe that the way they implemented it may have a flaw...

```python
import os

class CrypTopiaSC:

    @staticmethod
    def KSA(key, n):
        S = list(range(n))
        j = 0
        for i in range(n):
            j = ((j + S[i] + key[i % len(key)]) >> 4 | (j - S[i] + key[i % len(key)]) << 4) & (n-1)
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def PRGA(S, n):
        i = 0
        j = 0
        while True:
            i = (i+1) & (n-1)
            j = (j+S[i]) & (n-1)
            S[i], S[j] = S[j], S[i]
            yield S[((S[i] + S[j]) >> 4 | (S[i] - S[j]) << 4) & (n-1)]

    def __init__(self, key, n=256):
        self.KeyGenerator = self.PRGA(self.KSA(key, n), n)

    def encrypt(self, message):
        return bytes([char ^ next(self.KeyGenerator) for char in message])

def main():
    flag = b"XXX"
    key = os.urandom(256)
    encrypted_flag = CrypTopiaSC(key).encrypt(flag)
    print("Welcome to our first version of CrypTopia Stream Cipher!\nYou can here encrypt any message you want.")
    print(f"Oh, one last thing: {encrypted_flag.hex()}")
    while True:
        pt = input("Enter your message: ").encode()
        ct = CrypTopiaSC(key).encrypt(pt)
        print(ct.hex())

if __name__ == "__main__":
    main()
```

This challenge had a server to connect to that was running this program. The only difference is that the flag variable was obviously not b"XXX" as it gave a much longer response. 

I worked with ChatGPT to get a python script for this one. I didn't want the script to connect to the server, so I asked for the script to allow for a manually entered string. It seems my ChatGPT is overly complicating things. I think there is also a chance that my ChatGPT is avoiding using pwntools due to a previous incident.

What follows is the script and the information needed to call it:

```python
#!/usr/bin/env python3
import sys, argparse

def hex_to_bytes(s: str) -> bytes:
    try:
        return bytes.fromhex(s.strip())
    except ValueError:
        print(f"Error: '{s}' is not valid hex.", file=sys.stderr)
        sys.exit(1)

def recover_plaintext(flag_ct: bytes, dummy_ct: bytes, known_prefix: bytes) -> bytes:
    L = len(flag_ct)
    if len(dummy_ct) != L:
        print(
            f"Error: dummy ciphertext is {len(dummy_ct)} bytes but flag ciphertext is {L} bytes.",
            file=sys.stderr
        )
        sys.exit(1)

    # Build the keystream: keystream[i] = dummy_ct[i] ^ 0x41
    keystream = bytes(dummy_ct[i] ^ 0x41 for i in range(L))

    # Decrypt the flag: plaintext[i] = flag_ct[i] ^ keystream[i]
    plaintext = bytes(flag_ct[i] ^ keystream[i] for i in range(L))

    if not plaintext.startswith(known_prefix):
        print(
            "Warning: recovered plaintext does not start with the known prefix.\n"
            f"  Expected {known_prefix!r}, but got {plaintext[:len(known_prefix)]!r}.",
            file=sys.stderr
        )
    return plaintext

def main():
    parser = argparse.ArgumentParser(
        description="Recover a CrypTopiaSC‐encrypted flag given:\n"
                    "  1) the flag’s ciphertext (hex),\n"
                    "  2) the ciphertext of 'A'*L from the same key,\n"
                    "  3) a known prefix (e.g. N0PS{)."
    )
    parser.add_argument(
        "--flag", "-f",
        required=True,
        help="Flag’s ciphertext (hex) copied from the remote service."
    )
    parser.add_argument(
        "--dummy", "-d",
        required=True,
        help="Ciphertext (hex) you got by sending 'A'*L to the same remote service."
    )
    parser.add_argument(
        "--prefix", "-p",
        required=True,
        help="Known ASCII prefix of the flag (e.g. N0PS{)."
    )
    args = parser.parse_args()

    flag_ct   = hex_to_bytes(args.flag)
    dummy_ct  = hex_to_bytes(args.dummy)
    prefix    = args.prefix.encode("utf-8")

    recovered = recover_plaintext(flag_ct, dummy_ct, prefix)
    try:
        print("Recovered plaintext:", recovered.decode("utf-8"))
    except UnicodeDecodeError:
        print("Recovered plaintext (bytes):", recovered)

if __name__ == "__main__":
    main()
```
```bash
python3 decrypt_flag.py \
  --flag  9bda0f279f80ddb5c6e3d8f76f56a88f6f114300c44ea0 \
  --dummy <paste‑the‑46‑hex‑chars‑you‑got‑from‑encrypting "A"*23> \
  --prefix N0PS{
```

Here are some other scripts that accomplished the same thing:

```python
from pwn import *

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

conn = remote("0.cloud.chals.io", 31561)

# Read intro and get encrypted flag
line = conn.recvuntil(b"thing: ")
flag_ct_hex = conn.recvline().strip()
flag_ct = bytes.fromhex(flag_ct_hex.decode())
print("[+] Got encrypted flag:", flag_ct.hex())

# Send known plaintext of same length
known_pt = b'A' * len(flag_ct)
conn.sendlineafter(b"Enter your message: ", known_pt)

# Receive encrypted known plaintext
known_ct_hex = conn.recvline().strip()
known_ct = bytes.fromhex(known_ct_hex.decode())
print("[+] Got encrypted known plaintext:", known_ct.hex())

# Recover keystream
keystream = xor(known_ct, known_pt)

# Decrypt the flag
flag = xor(flag_ct, keystream)
print("[+] Recovered flag:", flag.decode())
```
