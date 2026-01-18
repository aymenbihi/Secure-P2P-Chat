# Secure P2P Chat

A **secure peer-to-peer chat application** with AES encryption and Diffie-Hellman key exchange.  
Designed for local networks (LAN) but can work over the internet if ports are forwarded.

---

## Features

- **UDP Device Discovery:** Automatically finds other peers on the same network.
- **Manual Connection:** Connect to any peer using IP and port.
- **Private Chat:** One-to-one encrypted messaging.
- **Group Chat:** Broadcast messages to all connected peers.
- **AES Encryption:** Messages are encrypted using AES-CBC 128-bit keys.
- **Diffie-Hellman Handshake:** Securely exchanges encryption keys.
- **Cross-platform:** Works on Windows, Linux, and Android (Termux).

---

## Requirements

- Python 3.10+  
- Libraries:
  - `pycryptodome`
  - `cryptography`

Install dependencies with:

```bash
pip install pycryptodome cryptography
