# Latihan Praktikum End-to-End Message Delivery

Mata Kuliah: II3230 Keamanan Informasi

## Anggota Kelompok

| Nama | NIM |
|---|---|
| Allodya Qonnita Arofa | 18223054 |
| Wijaksara Aptaluhung | 18223088 |

## Deskripsi

Implementasi skenario end-to-end secure message delivery antara Alice (pengirim) dan Bob (penerima) menggunakan TCP socket programming dengan Python.

## Algoritma yang Digunakan

| Komponen | Algoritma | Keterangan |
|---|---|---|
| Symmetric Encryption | AES-128 (mode EAX) | Enkripsi isi pesan |
| Asymmetric Encryption | RSA-2048 (PKCS#1 OAEP) | Enkripsi kunci simetris |
| Hash Function | SHA-256 | Verifikasi integritas data |
| Digital Signature | RSA (PKCS#1 v1.5) | Autentikasi pengirim |
| Komunikasi | TCP Socket (port 65432) | Pengiriman payload antar IP |

## Struktur File

```
II3230-LatihanPraktikum/
├── key_generation.py        # Generate RSA key pair (public + private)
├── alice.py                 # Pengirim: enkripsi, sign, kirim payload
├── bob.py                   # Penerima: dekripsi, verifikasi hash & signature
├── public_key_alice.pem     # Public key Alice (untuk verifikasi signature)
├── public_key_bob.pem       # Public key Bob (untuk enkripsi AES key)
└── .privatekey/
    ├── private_key_alice.pem  # Private key Alice (untuk signing)
    └── private_key_bob.pem    # Private key Bob (untuk dekripsi AES key)
```

## Cara Menjalankan

### 1. Install Dependencies

```bash
pip install pycryptodome
```

### 2. Generate Key Pair

Jalankan `key_generation.py` untuk masing-masing pihak (Alice dan Bob). Sesuaikan nama file output di script.

```bash
python key_generation.py
```

### 3. Tukar Public Key

- Alice memberikan `public_key_alice.pem` ke Bob
- Bob memberikan `public_key_bob.pem` ke Alice

### 4. Jalankan Bob (Penerima) Terlebih Dahulu

```bash
python bob.py
```

Bob akan menunggu koneksi masuk di port 65432.

### 5. Jalankan Alice (Pengirim)

```bash
python alice.py
```

Masukkan pesan dan IP address penerima (Bob).

## Alur End-to-End

### Sisi Alice (Pengirim)

1. Menyiapkan plaintext
2. Membuat AES key (128-bit) secara random
3. Mengenkripsi plaintext dengan AES-EAX
4. Mengenkripsi AES key dengan RSA-OAEP menggunakan public key Bob
5. Membuat hash SHA-256 dari plaintext
6. Membuat digital signature dengan PKCS#1 v1.5 menggunakan private key Alice
7. Mengirim payload via TCP socket

### Sisi Bob (Penerima)

1. Menerima payload via TCP socket
2. Mendekripsi AES key dengan RSA-OAEP menggunakan private key Bob
3. Mendekripsi ciphertext dengan AES-EAX
4. Menghitung ulang hash SHA-256 dan membandingkan dengan hash dari payload
5. Memverifikasi digital signature menggunakan public key Alice
6. Menyimpulkan validitas pesan

## Format Payload

```json
{
  "source_ip": "IP Alice",
  "destination_ip": "IP Bob",
  "encrypted_symmetric_key": "hex",
  "cipher_text": "hex",
  "tag": "hex",
  "nonce": "hex",
  "hash": "hex",
  "signature": "hex",
  "hash_algorithm": "SHA256",
  "symmetric_algorithm": "AES256",
  "asymmetric_algorithm": "RSA"
}
```