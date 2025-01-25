import socket
import struct
import random
from Crypto.Cipher import DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from client1 import run_client


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

    x = random.randint(2, p-2)
    public_key = pow(g, x, p)
    return x, public_key


def compute_dh_shared_key(pub_key, private_key, p):

    return pow(pub_key, private_key, p)

def derive_des_keys(shared_secret_int):

    hval = SHA256.new(shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7)//8, 'big')).digest()
    return hval[:8], hval[8:16]



def run_client(host='127.0.0.1', port=5000):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print("[Client2] Connected to server.")

    x, client_pub_key = generate_dh_keypair(DH_PRIME, DH_GENERATOR)
    print("Opcode 10 - KEY VERIFICATION\n"
          "[Client2] Sending KEY VERIFICATION with Public Key of Client to Server.")
    
    s.sendall(struct.pack('!I', 10) + struct.pack('!I', client_pub_key))

    resp = s.recv(8)
    if len(resp) < 8:
        print("[Client2] Failed to complete handshake.")
        s.close()
        return
    
    srv_opcode = struct.unpack('!I', resp[:4])[0]
    srv_pub_key = struct.unpack('!I', resp[4:8])[0]

    if srv_opcode != 10:
        print(f"[Client2] Unexpected opcode {srv_opcode}, Expected Opcode = 10 Closing")
        s.close()
        return
    print("Opcode 10 - KEY VERIFICATION\n"
          f"[Client2] Server replied with KEY VERIFICATION with Public Key of Server = {srv_pub_key}.\n"
          "Key verification done.")

    shared_secret = compute_dh_shared_key(srv_pub_key, x, DH_PRIME)
    K1, K2 = derive_des_keys(shared_secret)
    print(f"[Client2] Derived K1={K1.hex()}, K2={K2.hex()}")

    while True:

        hdr = s.recv(4)
        if not hdr:
            print("[Client2] Server closed connection.")
            break
        opcode_20 = struct.unpack('!I', hdr)[0]

        if opcode_20 == 50:

            print("50 → DISCONNECT\n[Client2] Server ended session.")
            break

        if opcode_20 == 20:
            print("Opcode 20 - SESSION TOKEN\n"
                  "[Client2] Received SESSION TOKEN with Encryption. Decrypting with K1.")
        else:
            print(f"[Client2] Unexpected opcode {opcode_20}, expected 20 Closing")
            break

        enc_token = s.recv(16)
        if len(enc_token) < 16:
            print("[Client2] Incomplete token data.")
            break

        session_token = des_decrypt(K1, enc_token)
        print(f"[Client2] Session token = {session_token.hex()}")

        user_input = input("[Client2] Enter numeric data (or 'quit' to disconnect): ").strip()
        if user_input.lower() == 'quit':

            print("Opcode 50 - DISCONNECT\n[Client2] Sending (50) to server.")
            s.sendall(struct.pack('!I', 50))
            break

        plaintext = user_input.encode('utf-8') + session_token
        enc_payload = double_des_encrypt(plaintext, K1, K2)

        h = HMAC.new(K2, enc_payload, SHA256)
        mac = h.digest()

        print("Opcode 30 - CLIENT ENC DATA\n"
              "[Client2] Sending Double DES Encrypted Data to server.")
        s.sendall(struct.pack('!I', 30) +
                  struct.pack('!I', len(enc_payload)) +
                  enc_payload + mac)

        hdr = s.recv(4)
        if len(hdr) < 4:
            print("[Client2] Server closed unexpectedly.")
            break
        opcode_40 = struct.unpack('!I', hdr)[0]

        if opcode_40 != 40:
            print(f"[Client2] Unexpected opcode {opcode_40}, expected 40. Closing.")
            break
        print("Opcode 40 - ENC AGGR RESULT\n"
              "[Client2] Received Aggregated Data from Server Decrypting...")

        len_buf = s.recv(4)
        if len(len_buf) < 4:
            print("[Client2] Incomplete aggregator length.")
            break
        agg_len = struct.unpack('!I', len_buf)[0]

        enc_agg = b''
        while len(enc_agg) < agg_len:
            chunk = s.recv(agg_len - len(enc_agg))
            if not chunk:
                break
            enc_agg += chunk

        hmac_agg = s.recv(32)  
        if len(hmac_agg) < 32:
            print("[Client2] Incomplete aggregator HMAC.")
            break

        h2 = HMAC.new(K2, enc_agg, SHA256)
        try:
            h2.verify(hmac_agg)
        except ValueError:
            print("[Client2] Aggregator HMAC verification FAILED.")
            continue

        try:
            agg_decrypted = double_des_decrypt(enc_agg, K1, K2).decode('utf-8')
            print(f"[Client2] The server's aggregated result = {agg_decrypted}\n")
        except Exception as e:
            print(f"[Client2] Decryption error: {e}\n")

    s.close()
    print("[Client2] Connection closed.")

if __name__ == "__main__":
    print("[Client2] Starting second client...")
    run_client()