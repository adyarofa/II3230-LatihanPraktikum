import socket
import re
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from urllib.request import urlopen

text = input("Masukkan pesan yang ingin kamu kirim: ")
ip_tujuan = input("Masukkan IP Address penerima (harus berada di jaringan yang sama): ")
port = 65432

# source = urlopen('http://checkip.dyndns.com')
# data = str(source.read())
hostname = socket.gethostname()
ip_asal = socket.gethostbyname(hostname)

key = get_random_bytes(16)
symmetrical = AES.new(key, AES.MODE_EAX)
cipher_text, tag = symmetrical.encrypt_and_digest(text.encode("utf-8"))
nonce = symmetrical.nonce
print("Cipher Text:", cipher_text.hex())
print("Tag:", tag.hex())
print("Nonce:", nonce.hex())

with open("public_key_bob.pem","rb") as f:
    public_key_bob = RSA.import_key(f.read())
    encrypted_symmetric_key = PKCS1_OAEP.new(public_key_bob).encrypt(key)
    print("Encrypted Symmetric Key:", encrypted_symmetric_key.hex())

hash_object = SHA256.new(text.encode("utf-8"))
print("Hash:", hash_object.hexdigest())

with open(".privatekey/private_key_alice.pem","rb") as f:
    private_key_alice = RSA.import_key(f.read())
    sign = pkcs1_15.new(private_key_alice).sign(hash_object)
    print("Signature:", sign.hex())

payload = {
    "source_ip": ip_asal,
    "destination_ip": ip_tujuan,
    "encrypted_symmetric_key": encrypted_symmetric_key.hex(),
    "cipher_text": cipher_text.hex(),
    "tag": tag.hex(),
    "nonce": nonce.hex(),
    "hash": hash_object.hexdigest(),
    "signature": sign.hex(),
    "hash_algorithm": "SHA256",
    "symmetric_algorithm": "AES256",
    "asymmetric_algorithm": "RSA"
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((ip_tujuan, port))
    s.sendall(str(payload).encode("utf-8"))
    print("\nPayload Terkirim")
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
    print("Pesan dikirim dari IP Address", ip_asal, "ke IP Address", ip_tujuan)