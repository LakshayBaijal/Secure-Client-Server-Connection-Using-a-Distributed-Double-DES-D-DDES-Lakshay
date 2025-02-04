import socket
import struct
import sys
import random
from Crypto.Cipher import DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Same opcodes
OPCODE_DH_EXCHANGE     = 10
OPCODE_SESSION_TOKEN   = 20
OPCODE_CLIENT_DATA     = 30
OPCODE_AGGREGATE       = 40
OPCODE_DISCONNECT      = 50

DH_PRIME     = 0xFFFFFFFD
DH_GENERATOR = 2

def pad_block(data: bytes) -> bytes:
    pl = 8 - (len(data) % 8)
    return data + bytes([pl] * pl)

def unpad_block(data: bytes) -> bytes:
    pl = data[-1]
    return data[:-pl]

def des_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = pad_block(plaintext)
    return cipher.encrypt(padded)

def des_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    dec = cipher.decrypt(ciphertext)
    return unpad_block(dec)

def dh_keypair(p: int, g: int):
    x = random.randint(2, p - 2)
    return x, pow(g, x, p)

def dh_shared(remote_pub: int, local_priv: int, p: int):
    return pow(remote_pub, local_priv, p)

def derive_keys(share_val: int):
    from Crypto.Hash import SHA256
    bts = share_val.to_bytes((share_val.bit_length() + 7)//8, 'big')
    h = SHA256.new(bts).digest()
    return h[:8], h[8:16]

def run_client(server_ip='127.0.0.1', server_port=5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_ip, server_port))
    print(f"[Client] Connected to {server_ip}:{server_port}")


    x, c_pub = dh_keypair(DH_PRIME, DH_GENERATOR)
    op_10 = struct.pack('!I', OPCODE_DH_EXCHANGE)
    s.sendall(op_10 + struct.pack('!I', c_pub))
    print(f"{OPCODE_DH_EXCHANGE} - Initiate DH Exchange \n [Client] Sent public={c_pub}")

    resp = s.recv(8)
    if len(resp) < 8:
        print("[Client] Incomplete response. Exiting.")
        s.close()
        return
    server_op, server_pub = struct.unpack('!II', resp)
    print(f"{server_op} - Received Server's Public Key: {server_pub}")
    if server_op != OPCODE_DH_EXCHANGE:
        print(f"[Client] Unexpected opcode {server_op}, expected {OPCODE_DH_EXCHANGE}. Exiting.")
        s.close()
        return

    share = dh_shared(server_pub, x, DH_PRIME)
    K1, K2 = derive_keys(share)
    print(f"[Client] Derived K1={K1.hex()}, K2={K2.hex()}")

    while True:
        h = s.recv(4)
        if not h:
            print("[Client] Server closed.")
            break
        token_op = struct.unpack('!I', h)[0]
        print(f"{token_op} - Session Token from Server")
        if token_op != OPCODE_SESSION_TOKEN:
            print(f"[Client] Unexpected opcode {token_op}, expected {OPCODE_SESSION_TOKEN}.")
            break

        iv_data = s.recv(8)
        enc_token = s.recv(16)
        if len(iv_data) < 8 or len(enc_token) < 16:
            print("[Client] Incomplete token data.")
            break

        try:
            token_plain = des_cbc_decrypt(K1, iv_data, enc_token)
            print(f"[Client] Session Token - {token_plain.hex()}")
        except Exception as e:
            print(f"[Client] Token decrypt error - {e}")
            break

        user_input = input("[Client] Enter any Number or Type 'quit' ").strip()
        if user_input.lower() == 'quit':

            s.sendall(struct.pack('!I', OPCODE_DISCONNECT))
            print(f"{OPCODE_DISCONNECT} - Disconnect Request")
            break

        try:
            val = float(user_input)
            data_bytes = str(val).encode('utf-8')
        except ValueError:
            print("[Client] Invalid numeric, ignoring.")
            continue

        final_payload = data_bytes + token_plain

        iv_client = get_random_bytes(8)
        enc_pl = des_cbc_encrypt(K1, iv_client, final_payload)

        hmac_cal = HMAC.new(K2, enc_pl, digestmod=SHA256)
        mac_val = hmac_cal.digest()

        data_msg = struct.pack('!I', OPCODE_CLIENT_DATA) + iv_client + struct.pack('!I', len(enc_pl)) + enc_pl + mac_val
        s.sendall(data_msg)
        print(f"{OPCODE_CLIENT_DATA} - Sent Encrypted Data \n [Client] Sent numeric + Sessional token")

        aggregator_hdr = s.recv(4)
        if len(aggregator_hdr) < 4:
            print("[Client] aggregator opcode not found.")
            break
        aggregator_op = struct.unpack('!I', aggregator_hdr)[0]
        print(f"{aggregator_op} - Response from Server")
        if aggregator_op != OPCODE_AGGREGATE:
            print(f"[Client] Unexpected aggregator opcode {aggregator_op}, expected {OPCODE_AGGREGATE}.")
            break

        agg_iv = s.recv(8)
        if len(agg_iv) < 8:
            print("[Client] Incomplete aggregator IV.")
            break

        agg_len_data = s.recv(4)
        if len(agg_len_data) < 4:
            print("[Client] aggregator length missing.")
            break
        agg_len = struct.unpack('!I', agg_len_data)[0]

        aggregator_cipher = b''
        while len(aggregator_cipher) < agg_len:
            chunk = s.recv(agg_len - len(aggregator_cipher))
            if not chunk:
                break
            aggregator_cipher += chunk
        if len(aggregator_cipher) < agg_len:
            print("[Client] aggregator truncated.")
            break

        aggregator_hmac = s.recv(32)
        if len(aggregator_hmac) < 32:
            print("[Client] aggregator HMAC incomplete.")
            break

        hv = HMAC.new(K2, aggregator_cipher, digestmod=SHA256)
        try:
            hv.verify(aggregator_hmac)
            print("[Client] Aggregator HMAC OK.")
        except ValueError:
            print("[Client] Aggregator HMAC mismatch.")
            continue

        try:
            dec_agg = des_cbc_decrypt(K1, agg_iv, aggregator_cipher)
            print(f"[Client] Aggregator - {dec_agg.decode('utf-8')}\n")
        except Exception as e:
            print(f"[Client] Decrypt aggregator failed - {e}")

    s.close()
    print("[Client] Connection ended.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host_arg = sys.argv[1]
        if len(sys.argv) > 2:
            port_arg = int(sys.argv[2])
            run_client(host_arg, port_arg)
        else:
            run_client(host_arg, 5000)
    else:
        run_client()
