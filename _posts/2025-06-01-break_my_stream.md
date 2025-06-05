---
title: Break My Stream
date: 2025-06-01 10:38:00 -0700
categories: [N0PSctf]
tags: [cryptography, remote, port, web]     # TAG names should always be lowercase
image:
  lqip: /assets/img/logo-nopsctf-bib.png
---
![N0PSctf Logo](/assets/img/logo-nopsctf.png){: .right }

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

```python
import socket
import re
import sys
HOST = "0.cloud.chals.io"
PORT = 31561
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    print(f"Connecting to {HOST}:{PORT}...")
    sock.connect((HOST, PORT))
    print("Connected.")
    # Receive welcome message and encrypted flag
    initial_data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            print("Connection closed unexpectedly while reading initial data.", file=sys.stderr)
            sock.close()
            exit(1)
        initial_data += chunk
        # Wait until the prompt is fully received
        if b"Enter your message: " in initial_data:
            break
            
    initial_data_str = initial_data.decode(errors='ignore') # Fixed syntax error
    print("Received initial data:")
    print(initial_data_str)
    # Extract encrypted flag hex
    match_ef = re.search(r"Oh, one last thing: ([0-9a-f]+)", initial_data_str)
    if not match_ef:
        print("Could not find encrypted flag hex.", file=sys.stderr)
        sock.close()
        exit(1)
    encrypted_flag_hex = match_ef.group(1)
    print(f"Encrypted Flag HEX: {encrypted_flag_hex}")
    # Calculate flag length
    try:
        ef_bytes = bytes.fromhex(encrypted_flag_hex)
        flag_len = len(ef_bytes)
        print(f"Flag length: {flag_len}")
    except ValueError:
        print("Invalid hex string for encrypted flag.", file=sys.stderr)
        sock.close()
        exit(1)
    # Prepare message: Send 'A' repeated flag_len times.
    # The server reads this string and encodes it using .encode()
    message_payload_str = 'A' * flag_len
    message_payload_bytes = message_payload_str.encode("ascii") # This is what gets encrypted
    print(f"Sending message payload (string): {message_payload_str}")
    # Send message payload + newline
    sock.sendall((message_payload_str + '\n').encode())
    # Receive encrypted message hex
    response_data = b""
    while True: # Read until the prompt appears again
        try:
            sock.settimeout(10.0) # Increased timeout
            chunk = sock.recv(4096)
            if not chunk:
                print("Connection closed while waiting for response.", file=sys.stderr)
                break
            response_data += chunk
            # Check if the prompt is at the end of the accumulated data
            if response_data.strip().endswith(b"Enter your message:"):
                print("Detected prompt, stopping read.")
                break
        except socket.timeout:
            print("Socket timeout waiting for response/prompt.", file=sys.stderr)
            # Check if we received anything useful before timeout
            if response_data:
                print("Proceeding with received data despite timeout.")
                break
            else:
                print("No data received before timeout.", file=sys.stderr)
                sock.close()
                exit(1)
        except Exception as e:
            print(f"Error receiving data: {e}", file=sys.stderr)
            sock.close()
            exit(1)
            
    sock.settimeout(None) # Disable timeout
    response_str = response_data.decode(errors='ignore') # Fixed syntax error
    print(f"Raw response data: {repr(response_str)}")
    # Extract hex using regex, looking for a hex string of the correct length
    # The hex string should appear before the *next* "Enter your message:" prompt
    expected_hex_len = flag_len * 2
    # Regex to capture hex ending just before the prompt, allowing for optional whitespace
    match_em = re.search(r"([0-9a-f]{" + str(expected_hex_len) + r"})\s*Enter your message:", response_str)
    
    if not match_em:
         # Fallback: search anywhere if not found immediately before prompt
         print("Primary regex failed, trying fallback regex...")
         match_em = re.search(r"([0-9a-f]{" + str(expected_hex_len) + r"})", response_str)
    if not match_em:
        print(f"Could not find encrypted message hex of length {expected_hex_len} in response.", file=sys.stderr)
        print(f"Raw response was: {repr(response_str)}", file=sys.stderr)
        sock.close()
        exit(1)
    encrypted_message_hex = match_em.group(1)
    print(f"Extracted Encrypted Message HEX: {encrypted_message_hex}")
    # Calculate the flag: F = EF XOR EM XOR P
    try:
        em_bytes = bytes.fromhex(encrypted_message_hex)
        if len(em_bytes) != flag_len:
            print(f"Error: Encrypted message length ({len(em_bytes)}) does not match flag length ({flag_len}).", file=sys.stderr)
            sock.close()
            exit(1)
        # XOR all three components: EncryptedFlag, EncryptedMessage, PlaintextMessage
        flag_bytes = bytes(ef ^ em ^ pm for ef, em, pm in zip(ef_bytes, em_bytes, message_payload_bytes))
        try:
            flag = flag_bytes.decode()
            print(f"\nRecovered Flag: {flag}")
            # Basic validation
            if flag.startswith("flag{") and flag.endswith("}"):
                print("Flag format looks valid!")
            else:
                print("Warning: Flag format might be incorrect.")
        except UnicodeDecodeError:
            print(f"\nCould not decode flag bytes: {flag_bytes.hex()}", file=sys.stderr)
            print("The result might be binary data or incorrectly decrypted.", file=sys.stderr)
    except ValueError as e:
        print(f"Invalid hex string for encrypted message: {e}", file=sys.stderr)
        sock.close()
        exit(1)
finally:
    print("Closing connection.")
    sock.close()
```
