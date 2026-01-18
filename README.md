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

## How It Works

### 1. UDP Discovery (Broadcast & Listen)

- Each peer broadcasts a `DISCOVER_REQUEST` on UDP port **9999**.
- Peers respond with their TCP listening port.
- Automatically discovers other peers on the LAN.

### 2. TCP Connection & Diffie-Hellman Handshake

- TCP connection is established between peers.
- `HELLO` messages and **Diffie-Hellman parameters** are exchanged.
- Shared **AES key** is derived for encrypting messages.

### 3. Private and Group Chat

- **Private Chat**: Direct encrypted messages between two peers.  
- **Group Chat**: Messages encrypted individually and sent to all connected peers.

---

## Notes

- Ensure **UDP port 9999** is open on your firewall.  
- If the port is busy, the program retries binding automatically.  
- The program avoids connecting to itself (`127.0.0.1` or your own IP).  

---

## Security

- **AES-CBC encryption** with 128-bit keys.  
- Keys are generated dynamically through **Diffie-Hellman handshake**.  
- No personal information or passwords are stored.

---

## Usage

1. Run the program on all devices within the same LAN.  
2. Peers will automatically discover each other.  
3. Start private or group chats securely.  

---

## License

This project is open-source and free to use.

---

## Requirements

- Python 3.10+  
- Libraries:
  - `pycryptodome`
  - `cryptography`

Install dependencies with:

```bash
pip install pycryptodome cryptography
