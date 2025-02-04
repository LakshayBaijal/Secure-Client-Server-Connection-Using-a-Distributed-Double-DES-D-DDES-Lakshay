
import socket
import threading
import struct
import random
from Crypto.Cipher import DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

OPCODE_DH_EXCHANGE     = 10
OPCODE_SESSION_TOKEN   = 20
OPCODE_CLIENT_DATA     = 30
OPCODE_AGGREGATE       = 40
OPCODE_DISCONNECT      = 50

DH_PRIME     = 0xFFFFFFFD
DH_GENERATOR = 2

client_registry = {}
registry_lock = threading.Lock()

def pad_block(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad_block(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def des_cbc_encrypt(key: bytes, iv: bytes, plain: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = pad_block(plain)
    return cipher.encrypt(padded)

def des_cbc_decrypt(key: bytes, iv: bytes, ciphered: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ciphered)
    return unpad_block(dec)

def gen_dh_keypair(p: int, g: int) -> tuple:
    private = random.randint(2, p - 2)
    public = pow(g, private, p)
    return private, public

def compute_dh_secret(pub: int, priv: int, p: int) -> int:
    return pow(pub, priv, p)

def derive_des_keys(shared_val: int) -> tuple:

    from Crypto.Hash import SHA256
    shared_bytes = shared_val.to_bytes((shared_val.bit_length() + 7) // 8, 'big')
    digest = SHA256.new(shared_bytes).digest()
    return digest[:8], digest[8:16]  # K1, K2

def handle_client(conn: socket.socket, addr: tuple):

    client_id = f"{addr[0]}:{addr[1]}"
    print(f"[Server] Connected: {client_id}")

    try:
        header = conn.recv(4)
        if len(header) < 4:
            print(f"[Server] {client_id}: No opcode received, closing.")
            conn.close()
            return
        opcode = struct.unpack('!I', header)[0]
        print(f"[Server] {client_id} - Received opcode: {opcode}")
        if opcode != OPCODE_DH_EXCHANGE:
            print(f"[Server] {client_id}: Unexpected opcode {opcode}, expected {OPCODE_DH_EXCHANGE}. Closing.")
            conn.close()
            return

        data = conn.recv(4)
        if len(data) < 4:
            print(f"[Server] {client_id}: Incomplete DH public key.")
            conn.close()
            return
        client_pub = struct.unpack('!I', data)[0]
        print(f"[Server] {client_id}: DH pub from client: {client_pub}")

        s_priv, s_pub = gen_dh_keypair(DH_PRIME, DH_GENERATOR)
        shared = compute_dh_secret(client_pub, s_priv, DH_PRIME)
        K1, K2 = derive_des_keys(shared)
        print(f"[Server] {client_id}: Derived DES keys K1,K2")

        reply = struct.pack('!I', OPCODE_DH_EXCHANGE) + struct.pack('!I', s_pub)
        conn.sendall(reply)
        print(f"[Server] {client_id} - Sent opcode {OPCODE_DH_EXCHANGE}, server_pub={s_pub}")

        with registry_lock:
            client_registry[client_id] = {
                'K1': K1,
                'K2': K2,
                'sum': 0.0
            }

    except Exception as ex:
        print(f"[Server] {client_id}: Error in DH handshake - {ex}")
        conn.close()
        return

    while True:
        try:
            session = get_random_bytes(8)
            iv_server = get_random_bytes(8)
            enc_token = des_cbc_encrypt(K1, iv_server, session)
            print(f"[Server] {client_id} - Sending opcode {OPCODE_SESSION_TOKEN} (session token)")

            token_msg = struct.pack('!I', OPCODE_SESSION_TOKEN) + iv_server + enc_token
            conn.sendall(token_msg)

            head = conn.recv(4)
            if not head:
                print(f"[Server] {client_id} disconnected.")
                break
            client_op = struct.unpack('!I', head)[0]
            print(f"[Server] {client_id} - Received opcode: {client_op}")

            if client_op == OPCODE_DISCONNECT:
                print(f"[Server] {client_id} - Disconnecting by client request (OPCODE 50).")
                conn.close()
                break

            if client_op != OPCODE_CLIENT_DATA:
                print(f"[Server] {client_id}: Unexpected opcode {client_op}, closing.")
                conn.close()
                break

            iv_client = conn.recv(8)
            if len(iv_client) < 8:
                print(f"[Server] {client_id}: Incomplete IV from client.")
                conn.close()
                break

            length_data = conn.recv(4)
            if len(length_data) < 4:
                print(f"[Server] {client_id}: No length data.")
                conn.close()
                break
            length_val = struct.unpack('!I', length_data)[0]

            enc_payload = b''
            while len(enc_payload) < length_val:
                chunk = conn.recv(length_val - len(enc_payload))
                if not chunk:
                    break
                enc_payload += chunk
            if len(enc_payload) < length_val:
                print(f"[Server] {client_id}: truncated payload.")
                conn.close()
                break

            recv_hmac = conn.recv(32)
            if len(recv_hmac) < 32:
                print(f"[Server] {client_id}: Incomplete HMAC.")
                conn.close()
                break

            current_K2 = client_registry[client_id]['K2']
            hasher = HMAC.new(current_K2, enc_payload, digestmod=SHA256)
            try:
                hasher.verify(recv_hmac)
                print(f"[Server] {client_id}: HMAC validated.")
            except ValueError:
                print(f"[Server] {client_id}: HMAC mismatch. Ignoring data.")
                continue

            current_K1 = client_registry[client_id]['K1']
            try:
                plain_data = des_cbc_decrypt(current_K1, iv_client, enc_payload)
                print(f"[Server] {client_id}: Decrypted - {plain_data}")
            except Exception as ex:
                print(f"[Server] {client_id}: Decryption error - {ex}")
                conn.close()
                break

            if len(plain_data) < 8:
                print(f"[Server] {client_id}: No space for session token, ignoring.")
                continue
            user_text = plain_data[:-8]

            try:
                num_val = float(user_text.decode('utf-8'))
                print(f"[Server] {client_id}: Numeric - {num_val}")
            except:
                print(f"[Server] {client_id}: Non-numeric data, ignoring.")
                continue

            with registry_lock:
                client_registry[client_id]['sum'] += num_val
                new_sum = client_registry[client_id]['sum']
            print(f"[Server] {client_id}: Aggregator - {new_sum}")

            iv_for_agg = get_random_bytes(8)
            agg_str = str(new_sum).encode('utf-8')
            enc_agg = des_cbc_encrypt(current_K1, iv_for_agg, agg_str)
            aggregator_h = HMAC.new(current_K2, enc_agg, digestmod=SHA256)
            aggregator_mac = aggregator_h.digest()

            aggregator_msg = struct.pack('!I', OPCODE_AGGREGATE) + iv_for_agg + struct.pack('!I', len(enc_agg)) + enc_agg + aggregator_mac
            conn.sendall(aggregator_msg)
            print(f"[Server] {client_id} - Sent opcode {OPCODE_AGGREGATE} with aggregator result.")

        except Exception as ex2:
            print(f"[Server] {client_id}: Exception - {ex2}")
            conn.close()
            break

    with registry_lock:
        if client_id in client_registry:
            del client_registry[client_id]
    print(f"[Server] {client_id}: Handler ended.")

def start_server(host='127.0.0.1', port=5000):
    """Start the server, accept clients and spawn threads."""
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv_sock.bind((host, port))
    serv_sock.listen(5)
    print(f"[Server] Listening on {host}:{port}")

    try:
        while True:
            conn, addr = serv_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[Server] Stopping.")
    finally:
        serv_sock.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        start_port = int(sys.argv[1])
        start_server(port=start_port)
    else:
        start_server()
