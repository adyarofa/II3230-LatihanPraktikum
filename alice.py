import socket
import re
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from urllib.request import urlopen

text = input("Masukkan pesan yang ingin kamu kirim: ")
ip_tujuan = input("Masukkan IP Address penerima (harus berada di jaringan yang sama): ")
port = 65432

source = urlopen('http://checkip.dyndns.com')
data = str(source.read())
ip_asal = re.search(r"\d+\.\d+\.\d+\.\d+", data).group()

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

hash = SHA256.new(text.encode("utf-8")).hexdigest()
print("Hash:", hash)

with open(".privatekey/private_key_alice.pem","rb") as f:
    private_key_alice = RSA.import_key(f.read())
    sign = PKCS1_OAEP.new(private_key_alice).encrypt(hash.encode("utf-8"))
    print("Signature:", sign.hex())

payload = {
    "source_ip": ip_asal,
    "destination_ip": ip_tujuan,
    "encrypted_symmetric_key": encrypted_symmetric_key.hex(),
    "cipher_text": cipher_text.hex(),
    "tag": tag.hex(),
    "nonce": nonce.hex(),
    "signature": sign.hex(),
    "hash_algorithm": "SHA256",
    "symmetric_algorithm": "AES256",
    "asymmetric_algorithm": "RSA"
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((ip_tujuan, port))
    s.sendall(str(payload).encode("utf-8"))
    print("Pesan dikirim dari IP Address ", ip_asal, " ke IP Address ", ip_tujuan)