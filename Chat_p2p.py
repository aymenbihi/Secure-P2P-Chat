import socket as sk
import threading
import pickle
import base64
import time
import sys
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

my_name = input("Enter your name: ").strip()

# ================== NETWORK UTILITIES ==================

def get_my_ip():
    """Get the actual IP address (not localhost)"""
    s = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception as e:
        print(f"⚠️ Could not get IP: {e}, using localhost")
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_connected():
    """Check if internet connection is available"""
    try:
        sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 80))
        sock.close()
        return True
    except Exception:
        return False


# ================== SOCKET SETUP ==================

tcp_sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
tcp_sock.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)
tcp_sock.bind(("0.0.0.0", 0))
my_ip = get_my_ip()
my_port = tcp_sock.getsockname()[1]
tcp_sock.listen(5)
tcp_sock.setblocking(False)

# UDP Discovery Setup
DISCOVERY_PORT = 9999
udp_recv = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
udp_recv.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)

# Keep trying port 9999 with multiple retries
for attempt in range(5):
    try:
        udp_recv.bind(("0.0.0.0", DISCOVERY_PORT))
        print(f"✅ UDP Discovery listening on port {DISCOVERY_PORT}")
        break
    except Exception as e:
        if attempt < 4:
            print(f"⚠️ Port {DISCOVERY_PORT} in use, retrying in 1 second...")
            time.sleep(1)
        else:
            print(f"❌ Could not bind to port {DISCOVERY_PORT}")
            raise

udp_send = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
udp_send.setsockopt(sk.SOL_SOCKET, sk.SO_BROADCAST, 1)
udp_send.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)

peers = []
devices = []
peers_lock = threading.Lock()
running = True


# ================== AES ENCRYPTION ==================

def Encrypt(key, message):
    """Encrypt message with AES"""
    try:
        iv = Random.new().read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad = 16 - len(message) % 16
        message = message + chr(pad) * pad
        encrypted = cipher.encrypt(message.encode("utf-8"))
        return base64.b64encode(iv + encrypted)
    except Exception as e:
        print(f"❌ Encryption error: {e}")
        return None


def Decrypt(key, data):
    """Decrypt message with AES"""
    try:
        raw = base64.b64decode(data)
        iv = raw[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(raw[16:]).decode("utf-8")
        return msg[:-ord(msg[-1])]
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return None


# ================== DIFFIE-HELLMAN HANDSHAKE ==================

def dh_server_handshake(conn):
    """Server side DH key exchange"""
    try:
        print("🔐 Generating DH parameters...")
        parameters = dh.generate_parameters(generator=2, key_size=1024)
        print("🔐 DH parameters generated!")
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print("📤 Sending DH parameters to client...")
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        conn.send(pickle.dumps(["DH", param_bytes, public_key_bytes]))
        conn.settimeout(60)
        
        print("⏳ Waiting for client DH response...")
        data = conn.recv(4096)
        if not data:
            raise Exception("No response from client")
        
        msg = pickle.loads(data)
        if msg[0] != "DH_OK":
            raise ValueError(f"Expected DH_OK, got {msg[0]}")
        other_public_key_bytes = msg[1]
        other_public_key = serialization.load_pem_public_key(other_public_key_bytes)

        print("🔑 Computing shared secret...")
        shared = private_key.exchange(other_public_key)
        aes_key = hashlib.sha256(shared).digest()[:16]
        print("✅ Handshake complete\n")
        return aes_key
    except Exception as e:
        print(f"❌ Server handshake failed: {e}")
        raise


def dh_client_handshake(conn):
    """Client side DH key exchange"""
    try:
        conn.settimeout(60)
        print("⏳ Waiting for DH parameters from server...")
        data = conn.recv(4096)
        if not data:
            raise Exception("No DH parameters from server")
        
        print("📥 Parsing DH parameters...")
        msg = pickle.loads(data)
        if msg[0] != "DH":
            raise ValueError(f"Expected DH, got {msg[0]}")
        
        param_bytes = msg[1]
        other_public_key_bytes = msg[2]
        
        parameters = serialization.load_pem_parameters(param_bytes)
        other_public_key = serialization.load_pem_public_key(other_public_key_bytes)
        print("📥 Received DH parameters")

        print("🔐 Generating client DH key...")
        private_key = parameters.generate_private_key()
        my_public_key = private_key.public_key()
        my_public_key_bytes = my_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print("📤 Sending DH response...")
        conn.send(pickle.dumps(["DH_OK", my_public_key_bytes]))

        print("🔑 Computing shared secret...")
        shared = private_key.exchange(other_public_key)
        aes_key = hashlib.sha256(shared).digest()[:16]
        print("✅ Handshake complete\n")
        return aes_key
    except Exception as e:
        print(f"❌ Client handshake failed: {e}")
        raise


# ================== DEVICE DISCOVERY ==================

def listen_discovery():
    """Listen for discovery broadcasts"""
    try:
        udp_recv.settimeout(1)
        while running:
            try:
                data, addr = udp_recv.recvfrom(1024)
                # Ignore self
                if addr[0] == my_ip or addr[0] == "127.0.0.1":
                    continue
                
                try:
                    decoded_data = data.decode("UTF-8")
                    if decoded_data == "DISCOVER_REQUEST":
                        response = str(my_port).encode("UTF-8")
                        udp_send.sendto(response, (addr[0], DISCOVERY_PORT))
                except ValueError:
                    continue
            except sk.timeout:
                continue
            except Exception as e:
                if running:
                    pass
    except Exception as e:
        print(f"❌ Discovery listen error: {e}")


def search_devices():
    """Search for available devices on network"""
    global devices
    
    print("🔍 Scanning for devices...")
    devices = []
    
    try:
        broadcast_addr = "255.255.255.255"
        udp_send.sendto(b"DISCOVER_REQUEST", (broadcast_addr, DISCOVERY_PORT))
        print(f"📡 Broadcast sent to {broadcast_addr}:{DISCOVERY_PORT}")
    except Exception as e:
        print(f"⚠️ Broadcast error: {e}")
        return
    
    udp_recv.settimeout(5)
    start = time.time()
    found_devices = {}
    
    try:
        while time.time() - start < 4:
            try:
                data, addr = udp_recv.recvfrom(1024)
                # Ignore self and localhost
                if addr[0] == my_ip or addr[0] == "127.0.0.1":
                    continue
                
                try:
                    port = int(data.decode("UTF-8"))
                    if addr[0] not in found_devices:
                        found_devices[addr[0]] = port
                        devices.append((addr[0], port))
                        print(f"✅ Found device: {addr[0]}:{port}")
                except ValueError:
                    continue
            except sk.timeout:
                continue
    except Exception as e:
        print(f"⚠️ Discovery error: {e}")
    
    udp_recv.settimeout(1)
    print(f"📋 Total devices found: {len(devices)}\n")


# ================== NETWORK HANDLERS ==================

def accept_peers():
    """Accept incoming peer connections (non-blocking)"""
    while running:
        try:
            conn, addr = tcp_sock.accept()
            print(f"\n📨 New connection from {addr}")
            threading.Thread(target=handle_peer, args=(conn, addr), daemon=True).start()
        except BlockingIOError:
            time.sleep(0.1)
            continue
        except Exception as e:
            if running:
                print(f"❌ Accept error: {e}")
            time.sleep(0.1)


def handle_peer(conn, addr):
    """Handle individual peer connection"""
    peer_name = None
    aes_key = None
    try:
        conn.settimeout(30)
        print(f"⏳ Waiting for HELLO from {addr}...")
        data = conn.recv(4096)
        
        if not data:
            print(f"❌ No data from {addr}")
            return
        
        try:
            hello = pickle.loads(data)
        except Exception as e:
            print(f"❌ Invalid pickle from {addr}: {e}")
            return
            
        if not isinstance(hello, list) or len(hello) < 2:
            print(f"❌ Invalid HELLO format from {addr}")
            return
        
        if hello[0] != "HELLO":
            print(f"❌ Expected HELLO, got {hello[0]} from {addr}")
            return
        
        peer_name = hello[1]
        print(f"📨 Received HELLO from {peer_name}")

        aes_key = dh_server_handshake(conn)
        
        with peers_lock:
            peers.append((conn, peer_name, aes_key))

        print(f"✅ {peer_name} connected successfully!")

        while running:
            try:
                conn.settimeout(30)
                data = conn.recv(4096)
                if not data:
                    break
                msg = Decrypt(aes_key, data)
                if msg:
                    print("-" * 40)
                    print(f"🟩 {peer_name}: {msg}")
                    print("-" * 40)
            except sk.timeout:
                continue
            except Exception as e:
                if running:
                    print(f"❌ Receive error: {e}")
                break
    except Exception as e:
        print(f"❌ Handle peer error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        if peer_name:
            with peers_lock:
                peers[:] = [p for p in peers if p[1] != peer_name]
            print(f"😔 {peer_name} disconnected\n")


def connect_to_peer(ip, port):
    """Connect to another peer"""
    if not is_connected():
        print("❌ No internet connection!")
        return False
    
    try:
        print(f"🔗 Connecting to {ip}:{port}...")
        s = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        print("✅ Connected!")

        print("📤 Sending HELLO message...")
        s.send(pickle.dumps(["HELLO", my_name]))
        aes_key = dh_client_handshake(s)

        with peers_lock:
            peers.append((s, f"{ip}:{port}", aes_key))
        
        print(f"✅ Securely connected to {ip}:{port}\n")
        return True
    except sk.timeout:
        print("❌ Connection timeout - peer not responding\n")
        return False
    except ConnectionRefusedError:
        print("❌ Connection refused - check IP and port\n")
        return False
    except Exception as e:
        print(f"❌ Connection failed: {e}\n")
        return False


# ================== CHAT FUNCTIONS ==================

def receive_messages(conn, name, key):
    """Receive messages in a separate thread"""
    while running:
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if not data:
                break
            msg = Decrypt(key, data)
            if msg:
                print("\n" + "-" * 40)
                print(f"🟩 {name}: {msg}")
                print("-" * 40)
                print("➡️ ", end="", flush=True)
        except sk.timeout:
            continue
        except Exception as e:
            break


def receive_group_messages(conn, name, key):
    """Receive group messages in a separate thread"""
    while running:
        try:
            conn.settimeout(5)
            data = conn.recv(4096)
            if not data:
                break
            msg = Decrypt(key, data)
            if msg:
                print("\n" + "-" * 40)
                print(f"🟩 {name}: {msg}")
                print("-" * 40)
                print("➡️ ", end="", flush=True)
        except sk.timeout:
            continue
        except Exception as e:
            break


def private_chat():
    """One-to-one private chat"""
    with peers_lock:
        if not peers:
            print("😞 No peers connected\n")
            return

        for i, p in enumerate(peers):
            print(f"{i + 1}. {p[1]}")

    try:
        choice = input("Enter peer number or type IP:port to connect: ").strip()
        
        # Check if it's a number (existing peer)
        if choice.isdigit():
            c = int(choice) - 1
            with peers_lock:
                if c < 0 or c >= len(peers):
                    print("❌ Invalid selection\n")
                    return
                conn, name, key = peers[c]
        else:
            # Try to connect to new device
            if ":" in choice:
                parts = choice.split(":")
                ip = parts[0]
                try:
                    port = int(parts[1])
                    if not connect_to_peer(ip, port):
                        return
                    with peers_lock:
                        conn, name, key = peers[-1]
                except ValueError:
                    print("❌ Invalid format. Use IP:port\n")
                    return
            else:
                print("❌ Invalid input\n")
                return

        print(f"💬 Chatting with {name} (type '/exit' to quit)\n")
        
        recv_thread = threading.Thread(target=receive_messages, args=(conn, name, key), daemon=True)
        recv_thread.start()
        
        while True:
            try:
                data = input("➡️ ").strip()
                if not data:
                    continue
                if data == "/exit":
                    break
                
                encrypted = Encrypt(key, data)
                if encrypted:
                    conn.send(encrypted)
            except BrokenPipeError:
                print("❌ Connection lost\n")
                break
            except Exception as e:
                print(f"❌ Error: {e}\n")
                break
    except ValueError:
        print("❌ Invalid input\n")
    except Exception as e:
        print(f"❌ Chat error: {e}\n")


def group_chat():
    """Group chat with all peers"""
    with peers_lock:
        if not peers:
            print("😞 No peers connected\n")
            print("Would you like to connect to a device first? (y/n): ", end="")
            if input().strip().lower() == 'y':
                if devices:
                    for i, (ip, port) in enumerate(devices):
                        print(f"{i + 1}. {ip}:{port}")
                    try:
                        d = int(input("Choose device (number): ")) - 1
                        if 0 <= d < len(devices):
                            connect_to_peer(devices[d][0], devices[d][1])
                        else:
                            print("❌ Invalid selection\n")
                            return
                    except ValueError:
                        print("❌ Invalid input\n")
                        return
                else:
                    print("❌ No devices found\n")
                    return
            else:
                return
        
        print(f"📢 Broadcasting to {len(peers)} peer(s) (type '/exit' to quit)\n")

        for conn, name, key in peers[:]:
            recv_thread = threading.Thread(target=receive_group_messages, args=(conn, name, key), daemon=True)
            recv_thread.start()

    while True:
        try:
            data = input("➡️ ").strip()
            if not data:
                continue
            if data == "/exit":
                break
            
            with peers_lock:
                for conn, name, key in peers[:]:
                    try:
                        encrypted = Encrypt(key, data)
                        if encrypted:
                            conn.send(encrypted)
                    except BrokenPipeError:
                        print(f"⚠️ {name} disconnected")
                    except Exception as e:
                        print(f"❌ Error sending to {name}: {e}")
        except Exception as e:
            print(f"❌ Group chat error: {e}\n")


# ================== MAIN PROGRAM ==================

print("🚀 Starting Secure P2P Chat...\n")

if not is_connected():
    print("⚠️ Warning: No internet connection detected\n")

threading.Thread(target=accept_peers, daemon=True).start()
threading.Thread(target=listen_discovery, daemon=True).start()
time.sleep(1)

while True:
    print("=" * 50)
    print("SECURE P2P CHAT")
    print("=" * 50)
    print(f"Your IP: {my_ip}")
    print(f"Your Port: {my_port}")
    with peers_lock:
        peer_count = len(peers)
    print(f"Connected Peers: {peer_count}")
    print("-" * 50)
    print("1. Search for devices")
    print("2. Connect to peer (manual)")
    print("3. Connect to found device")
    print("4. Private chat")
    print("5. Group chat")
    print("6. Exit")
    print("=" * 50)

    try:
        ch = input("➡️ Choose option: ").strip()

        if ch == "1":
            search_devices()
            if devices:
                for i, (ip, port) in enumerate(devices):
                    print(f"{i + 1}. {ip}:{port}")

        elif ch == "2":
            ip = input("Enter peer IP: ").strip()
            try:
                port = int(input("Enter peer port: "))
                connect_to_peer(ip, port)
            except ValueError:
                print("❌ Invalid port number\n")

        elif ch == "3":
            if not devices:
                print("❌ No devices found. Search first!\n")
            else:
                for i, (ip, port) in enumerate(devices):
                    print(f"{i + 1}. {ip}:{port}")
                try:
                    d = int(input("Choose device (number): ")) - 1
                    if 0 <= d < len(devices):
                        connect_to_peer(devices[d][0], devices[d][1])
                    else:
                        print("❌ Invalid selection\n")
                except ValueError:
                    print("❌ Invalid input\n")

        elif ch == "4":
            private_chat()

        elif ch == "5":
            group_chat()

        elif ch == "6":
            print("👋 Goodbye!")
            running = False
            break

        else:
            print("❌ Invalid option\n")

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        running = False
        break
    except Exception as e:
        print(f"❌ Error: {e}\n")