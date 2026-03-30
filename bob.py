import socket
import ast
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

# Langkah-langkah:
# 1. Menerima payload dari Alice via TCP socket
# 2. Dekripsi symmetric key (RSA-OAEP)
# 3. Dekripsi ciphertext (AES-EAX)
# 4. Verifikasi hash (SHA-256)
# 5. Verifikasi digital signature (RSA-OAEP)

HOST = "0.0.0.0"  
PORT = 65432

print("BOB (Penerima Pesan)")
print(f"\nMenunggu koneksi di port {PORT}...")

# 1. Menerima payload dari Alice via TCP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Koneksi diterima dari: {addr[0]}:{addr[1]}")
        
        # Terima semua data
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

# Parse payload (Alice mengirim str(dict), jadi pakai ast.literal_eval)
payload = ast.literal_eval(data.decode("utf-8"))

print("\nPayload Diterima")
print(f"Encrypted Symmetric Key: {payload['encrypted_symmetric_key'][:40]}...")
print(f"Cipher Text:             {payload['cipher_text'][:40]}...")
print(f"Tag:                     {payload['tag']}")
print(f"Nonce:                   {payload['nonce']}")
print(f"Signature:               {payload['signature'][:40]}...")
print(f"Source IP:               {payload['source_ip']}")
print(f"Destination IP:          {payload['destination_ip']}")
print(f"Hash Algorithm:          {payload['hash_algorithm']}")
print(f"Symmetric Algorithm:     {payload['symmetric_algorithm']}")
print(f"Asymmetric Algorithm:    {payload['asymmetric_algorithm']}")

# Decode semua hex values ke bytes
encrypted_symmetric_key = bytes.fromhex(payload["encrypted_symmetric_key"])
cipher_text = bytes.fromhex(payload["cipher_text"])
tag = bytes.fromhex(payload["tag"])
nonce = bytes.fromhex(payload["nonce"])
signature = bytes.fromhex(payload["signature"])

# 2. Dekripsi Symmetric Key menggunakan private key Bob (RSA-OAEP)
print("\nDekripsi Symmetric Key")
with open(".privatekey/private_key_bob.pem", "rb") as f:
    private_key_bob = RSA.import_key(f.read())
    aes_key = PKCS1_OAEP.new(private_key_bob).decrypt(encrypted_symmetric_key)
    print(f"AES Key (hex): {aes_key.hex()}")
    print("Status: Symmetric key berhasil didekripsi")

# 3. Dekripsi Ciphertext menggunakan AES-EAX
print("\nDekripsi Ciphertext")
cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt_and_verify(cipher_text, tag)
plaintext_str = plaintext.decode("utf-8")
print(f"Plaintext: {plaintext_str}")
print("Status: Ciphertext berhasil didekripsi")

# 4. Verifikasi Hash (SHA-256)
print("\nVerifikasi Hash")
hash_local = SHA256.new(plaintext_str.encode("utf-8")).hexdigest()
print(f"Hash lokal (dihitung ulang): {hash_local}")

# 5. Verifikasi Digital Signature (RSA-OAEP decrypt signature pakai public key Alice)
print("\nVerifikasi Digital Signature")
with open("public_key_alice.pem", "rb") as f:
    public_key_alice = RSA.import_key(f.read())
    hash_from_signature = PKCS1_OAEP.new(public_key_alice).decrypt(signature)
    hash_from_signature_str = hash_from_signature.decode("utf-8")
    print(f"Hash dari signature:        {hash_from_signature_str}")

# Bandingkan hash lokal dengan hash dari signature
if hash_local == hash_from_signature_str:
    print("\nHash MATCH")
    print("Integritas pesan terjaga, pesan tidak berubah selama transmisi.")
    print("Signature valid, pesan benar berasal dari Alice.")
else:
    print("\nHash MISMATCH")
    print("PERINGATAN: Pesan mungkin telah dimodifikasi atau pengirim tidak valid!")

# 6. Kesimpulan
print("KESIMPULAN")
print(f"Pesan berhasil didekripsi   : Ya")
print(f"Integritas pesan terjaga    : {'Ya' if hash_local == hash_from_signature_str else 'Tidak'}")
print(f"Pengirim terverifikasi      : {'Ya' if hash_local == hash_from_signature_str else 'Tidak'}")
print(f"Plaintext                   : {plaintext_str}")
