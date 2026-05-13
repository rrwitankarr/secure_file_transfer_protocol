import socket, os, struct, hashlib, sys, time
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from tqdm import tqdm  # <-- for progress bar

HOST = "0.0.0.0"
PORT = 9009
SERVER_KEY_FILE = "server_rsa.pem"
LOG_FILE = "server_log.txt"

def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event}\n")

def send_msg(conn, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]
    data = b""
    with tqdm(total=msg_len, unit="B", unit_scale=True, desc="Receiving", ncols=70) as bar:
        while len(data) < msg_len:
            chunk = conn.recv(min(4096, msg_len - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while receiving.")
            data += chunk
            bar.update(len(chunk))
    return data

def sha256_checksum(filename):
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# Load or generate RSA key pair
if os.path.exists(SERVER_KEY_FILE):
    with open(SERVER_KEY_FILE, "rb") as f:
        server_key = RSA.import_key(f.read())
else:
    server_key = RSA.generate(2048)
    with open(SERVER_KEY_FILE, "wb") as f:
        f.write(server_key.export_key('PEM'))

server_priv = server_key
server_pub = server_key.publickey().export_key()

print(f" Secure File Transfer Server started on {HOST}:{PORT}")
log_event(f"Server started on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        log_event(f"Connection established with {addr}")

        # Exchange public keys
        send_msg(conn, server_pub)
        client_pub_pem = recv_msg(conn)
        client_pub = RSA.import_key(client_pub_pem)

        # Verify client
        client_proof = recv_msg(conn)
        h = SHA256.new(b"client_identity_check")
        try:
            pkcs1_15.new(client_pub).verify(h, client_proof)
            print(" Client authentication successful")
            send_msg(conn, b"AUTH_OK")
            log_event("Client authentication successful.")
        except (ValueError, TypeError):
            print(" Client authentication failed")
            send_msg(conn, b"AUTH_FAIL")
            log_event("Client authentication failed.")
            conn.close()
            exit(0)

        # Send server proof
        server_hash = SHA256.new(b"server_identity_check")
        server_signature = pkcs1_15.new(server_priv).sign(server_hash)
        send_msg(conn, server_signature)

        # Receive AES key
        enc_session = recv_msg(conn)
        rsa_cipher = PKCS1_OAEP.new(server_priv)
        session_key = rsa_cipher.decrypt(enc_session)
        log_event("AES session key received and decrypted.")

        # Receive encrypted file
        fname = recv_msg(conn).decode()
        nonce = recv_msg(conn)
        ciphertext = recv_msg(conn)
        tag = recv_msg(conn)

        aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes.decrypt_and_verify(ciphertext, tag)

        with open(fname, "wb") as f:
            f.write(plaintext)
        print(f" Received file saved as: {fname}")
        log_event(f"Received file '{fname}' successfully.")

        # Receive hash
        client_hash = recv_msg(conn).decode()
        server_hash = sha256_checksum(fname)

        if client_hash == server_hash:
            print(" SHA-256 integrity verified.")
            send_msg(conn, b"INTEGRITY_OK")
            log_event(f"Integrity verified for {fname}.")
        else:
            print(" Integrity check failed.")
            send_msg(conn, b"INTEGRITY_FAIL")
            log_event(f"Integrity failed for {fname}.")

        send_msg(conn, b"OK")

        # Send reply file if exists
        reply_file = "server_reply.pdf"
        if not os.path.exists(reply_file):
            send_msg(conn, b"NO_FILE")
            log_event("No reply file found.")
        else:
            with open(reply_file, "rb") as f:
                reply_data = f.read()
            aes_out = AES.new(session_key, AES.MODE_GCM)
            cipher_out, tag_out = aes_out.encrypt_and_digest(reply_data)
            send_msg(conn, os.path.basename(reply_file).encode())
            send_msg(conn, aes_out.nonce)
            send_msg(conn, cipher_out)
            send_msg(conn, tag_out)
            print(f" Sent reply file: {reply_file}")
            log_event(f"Sent reply file '{reply_file}' to client.")
