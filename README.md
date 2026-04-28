# CS134 Machine Problem 2 (MP2)

This project implements authenticated encryption using RSA-OAEP for encryption and RSA-PSS for digital signatures. It follows an encrypt-then-sign and verify-then-decrypt workflow using the Python `cryptography` library.

---

# Features

- Generates separate RSA keypairs for encryption and signing
- Maintains a simple trusted directory (`directory.json`)
- Encrypts messages using RSA-OAEP
- Signs ciphertext using RSA-PSS
- Verifies signatures before decryption
- Supports CLI-based messaging between users

---

# How it works

## User registration
Each user gets:
- encryption keypair (used for receiving messages)
- signing keypair (used for sending messages)

Public keys are stored in `directory.json`.

---

## Sending a message

1. Message is encrypted using receiver's public key
2. Ciphertext is signed using sender's private key
3. Stored in `message.json`

Command:

python3 mp2.py send <sender> <receiver> <message>


---

## Receiving a message

1. Signature is verified using sender's public key
2. If valid, ciphertext is decrypted using receiver's private key
3. Plaintext is displayed

Command:

python3 mp2.py receive <receiver>


---

## Generate user


python3 mp2.py generate <username>


---

# Files generated

- `<user>_enc_priv.pem`
- `<user>_enc_pub.pem`
- `<user>_sign_priv.pem`
- `<user>_sign_pub.pem`
- `directory.json`
- `message.json`

---

# Requirements

- Python 3.x
- cryptography library

Install:

pip3 install cryptography


---

# Summary

This project demonstrates secure communication using:
- RSA-OAEP encryption
- RSA-PSS signatures
- Encrypt-then-sign design
- Verify-then-decrypt validation
