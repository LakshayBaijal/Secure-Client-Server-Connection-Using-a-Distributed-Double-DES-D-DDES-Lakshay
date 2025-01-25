import socket
import threading
import random
import struct
from Crypto.Cipher import DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

DH_PRIME = 0xFFFFFFFD
DH_GENERATOR = 2

def pad_message(msg):

    padding_len = 8 - (len(msg) % 8)
    return msg + bytes([padding_len]) * padding_len

def unpad_message(msg):

    padding_len = msg[-1]
    return msg[:-padding_len]

def des_encrypt(key, data):

    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad_message(data))

def des_decrypt(key, data):

    cipher = DES.new(key, DES.MODE_ECB)
    dec = cipher.decrypt(data)
    return unpad_message(dec)

def double_des_encrypt(plaintext, key1, key2):

    step1 = des_encrypt(key1, plaintext)
    step2 = des_encrypt(key2, step1)
    return step2

def double_des_decrypt(ciphertext, key1, key2):

    step1 = des_decrypt(key2, ciphertext)
    step2 = des_decrypt(key1, step1)
    return step2

def generate_dh_keypair(p, g):

    x = random.randint(2, p - 2)
    public_key = pow(g, x, p)
    return x, public_key

def compute_dh_shared_key(remote_pub_key, private_key, p):
    return pow(remote_pub_key, private_key, p)


def derive_des_keys(shared_secret_int):
    secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, 'big')
    hval = SHA256.new(secret_bytes).digest()
    return hval[:8], hval[8:16]


client_store = {} 
lock = threading.Lock()
global_aggregate = 0.0


def client_handler(conn, addr):

    client_id = f"{addr[0]}:{addr[1]}"
    print(f"[Server] Client connected: {client_id}")

    global global_aggregate

    try:
        header = conn.recv(4)
        if len(header) < 4:
            print(f"[Server] {client_id}: Connection ended unexpectedly.")
            conn.close()
            return
        opcode = struct.unpack('!I', header)[0]

        if opcode == 10:
            print("Opcode 10 - KEY VERIFICATION\n"
                  f"[Server] {client_id} sent Client Public Key. Proceeding with DH handshake.")
        else:
            print(f"[Server] {client_id}: Expected opcode 10, got {opcode}. Closing.")
            conn.close()
            return

        dh_pub_bytes = conn.recv(4)
        if len(dh_pub_bytes) < 4:
            print(f"[Server] {client_id}: No public key data. Closing.")
            conn.close()
            return
        client_pub_key = struct.unpack('!I', dh_pub_bytes)[0]

        server_x, server_pub_key = generate_dh_keypair(DH_PRIME, DH_GENERATOR)
        shared_secret = compute_dh_shared_key(client_pub_key, server_x, DH_PRIME)
        K1, K2 = derive_des_keys(shared_secret)
        client_store[client_id] = {"K1": K1, "K2": K2, "session_token": None}
        print(f"[Server] {client_id}: Derived K1={K1.hex()}, K2={K2.hex()}")

        resp = struct.pack('!I', 10) + struct.pack('!I', server_pub_key)
        conn.sendall(resp)
        print("Opcode 10 - KEY VERIFICATION\n"
              f"[Server] Replied to {client_id} with Server Public Key. Key verification done.\n")

    except Exception as e:
        print(f"[Server] {client_id}: Error in DH handshake: {e}")
        conn.close()
        return

    while True:
        try:

            session_token = get_random_bytes(8)
            client_store[client_id]["session_token"] = session_token

            K1 = client_store[client_id]["K1"]
            enc_token = des_encrypt(K1, session_token)  
            print("Opcode 20 - SESSION TOKEN\n"
                  f"[Server] Sending SESSION TOKEN to {client_id}.")
            conn.sendall(struct.pack('!I', 20) + enc_token)

            header = conn.recv(4)
            if not header:
                print(f"[Server] {client_id} disconnected.")
                break
            client_opcode = struct.unpack('!I', header)[0]

            if client_opcode == 50:
                print("Opcode 50 - DISCONNECT\n"
                      f"[Server] {client_id} Ending Session.")
                conn.close()
                break

            if client_opcode == 30:
                print("Opcode 30 - CLIENT ENC DATA\n"
                      f"[Server] Received Double DES Encrypted Data from {client_id}.")
            else:
                print(f"[Server] {client_id}: Expected opcode 30, got {client_opcode}. Closing.")
                conn.close()
                break

            length_bytes = conn.recv(4)
            if len(length_bytes) < 4:
                print(f"[Server] {client_id}: Incomplete length field.")
                conn.close()
                break
            msg_len = struct.unpack('!I', length_bytes)[0]

            enc_payload = b''
            while len(enc_payload) < msg_len:
                chunk = conn.recv(msg_len - len(enc_payload))
                if not chunk:
                    break
                enc_payload += chunk

            if len(enc_payload) != msg_len:
                print(f"[Server] {client_id}: Encrypted data truncated.")
                conn.close()
                break

            hmac_recv = conn.recv(32)
            if len(hmac_recv) < 32:
                print(f"[Server] {client_id}: Incomplete HMAC.")
                conn.close()
                break

            K2 = client_store[client_id]["K2"]
            h = HMAC.new(K2, enc_payload, digestmod=SHA256)
            try:
                h.verify(hmac_recv)
            except ValueError:
                print(f"[Server] {client_id}: HMAC failed! Ignoring this message.")
                continue

            plaintext = double_des_decrypt(enc_payload, K1, K2)
            session_stored = client_store[client_id]["session_token"]

            if len(plaintext) < 8:
                print(f"[Server] {client_id}: Invalid plaintext (no token). Discarding.")
                continue

            user_data = plaintext[:-8]
            token_received = plaintext[-8:]

            if token_received != session_stored:
                print(f"[Server] {client_id}: Invalid session token!")
                conn.close()
                break

            try:
                numeric_value = float(user_data.decode('utf-8'))
            except:
                print(f"[Server] {client_id}: Non-numeric data. Discarding.")
                continue

            with lock:
                global_aggregate += numeric_value
            print(f"[Server] {client_id}: Data={numeric_value}, new global sum={global_aggregate}")

            agg_str = str(global_aggregate).encode('utf-8')
            enc_agg = double_des_encrypt(agg_str, K1, K2)
            h2 = HMAC.new(K2, enc_agg, digestmod=SHA256)
            mac_agg = h2.digest()

            print("Opcode 40 - ENC AGGR RESULT\n"
                  f"[Server] Sending Encrypted Aggregated Result to {client_id}.\n")
            conn.sendall(struct.pack('!I', 40) +
                         struct.pack('!I', len(enc_agg)) +
                         enc_agg + mac_agg)

        except Exception as e:
            print(f"[Server] {client_id} Exception: {e}")
            conn.close()
            break

    print(f"[Server] Client {client_id} handler ended.")


def start_server(host='127.0.0.1', port=5000):
    """Start the server, handle multiple clients via threads."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[Server] Listening on {host}:{port}")

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
