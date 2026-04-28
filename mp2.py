import os
import json
import base64
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# key generation

def generate_keypair():
    """
    Generates a 2048-bit RSA private key.
    The public key can be derived from it.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def save_private_key(key, filename):
    """
    Saves a private key to a file in PEM format.
    """
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_public_key(key, filename):
    """
    Saves the corresponding public key to a file.
    """
    with open(filename, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# directory

DIRECTORY_FILE = "directory.json"


def load_directory():
    """
    Loads the directory mapping users to their key files.
    Acts as a simple 'trusted directory service'.
    """
    if not os.path.exists(DIRECTORY_FILE):
        return {}
    with open(DIRECTORY_FILE, "r") as f:
        return json.load(f)


def save_directory(directory):
    with open(DIRECTORY_FILE, "w") as f:
        json.dump(directory, f, indent=4)


def register_user(username):
    """
    Generates two keypairs:
    - encryption keypair
    - signing keypair
    Then stores public keys in the directory.
    """
    directory = load_directory()

    if username in directory:
        print("User already exists.")
        return

    enc_key = generate_keypair()
    sign_key = generate_keypair()

    enc_priv = f"{username}_enc_priv.pem"
    enc_pub = f"{username}_enc_pub.pem"
    sign_priv = f"{username}_sign_priv.pem"
    sign_pub = f"{username}_sign_pub.pem"

    save_private_key(enc_key, enc_priv)
    save_public_key(enc_key, enc_pub)

    save_private_key(sign_key, sign_priv)
    save_public_key(sign_key, sign_pub)

    directory[username] = {
        "enc_pub": enc_pub,
        "sign_pub": sign_pub
    }

    save_directory(directory)
    print(f"User '{username}' registered successfully.")


# crypto operations

def encrypt(public_key, message):
    """
    Encrypts a short ASCII message using RSA-OAEP.
    """
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(private_key, ciphertext):
    """
    Decrypts RSA-OAEP ciphertext.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()


def sign(private_key, data):
    """
    Signs data using RSA-PSS.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(public_key, signature, data):
    """
    Verifies a signature.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# message handling

def resolve_message_input(message_input):
    """
    Determines whether input is a file or direct text.
    """
    if os.path.exists(message_input):
        with open(message_input, "r") as f:
            return f.read().strip()
    return " ".join(message_input.split())


def send_message(sender, receiver, message_input):
    """
    Encrypt-then-sign:
    1. Encrypt message using receiver's public key
    2. Sign ciphertext using sender's private key
    """
    directory = load_directory()

    if sender not in directory or receiver not in directory:
        print("Sender or receiver not registered.")
        return

    message = resolve_message_input(message_input)

    if len(message) > 140:
        print("Message too long (max 140 chars).")
        return

    receiver_pub = load_public_key(directory[receiver]["enc_pub"])
    sender_priv_sign = load_private_key(f"{sender}_sign_priv.pem")

    ciphertext = encrypt(receiver_pub, message)
    signature = sign(sender_priv_sign, ciphertext)

    package = {
        "sender": sender,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode()
    }

    with open("message.json", "w") as f:
        json.dump(package, f, indent=4)

    print("Message sent and saved to message.json")


def receive_message(receiver):
    """
    Verify-then-decrypt:
    1. Verify signature using sender's public key
    2. Decrypt if valid
    """
    directory = load_directory()

    if receiver not in directory:
        print("User not found.")
        return

    if not os.path.exists("message.json"):
        print("No message found.")
        return

    with open("message.json", "r") as f:
        package = json.load(f)

    sender = package["sender"]

    if sender not in directory:
        print("Unknown sender.")
        return

    ciphertext = base64.b64decode(package["ciphertext"])
    signature = base64.b64decode(package["signature"])

    sender_pub_sign = load_public_key(directory[sender]["sign_pub"])

    if not verify(sender_pub_sign, signature, ciphertext):
        print("Signature invalid! Message rejected.")
        return

    receiver_priv_enc = load_private_key(f"{receiver}_enc_priv.pem")

    plaintext = decrypt(receiver_priv_enc, ciphertext)
    print("Message received:", plaintext)

# cli interface

def main():
    """
    Command-line interface:

    generate <username>
    send <sender> <receiver> <message_or_file>
    receive <receiver>
    """

    if len(sys.argv) < 2:
        print("Usage:")
        print("  generate <username>")
        print("  send <sender> <receiver> <message_or_file>")
        print("  receive <receiver>")
        return

    command = sys.argv[1]

    if command == "generate":
        register_user(sys.argv[2])

    elif command == "send":
        sender = sys.argv[2]
        receiver = sys.argv[3]
        message_input = " ".join(sys.argv[4:])
        send_message(sender, receiver, message_input)

    elif command == "receive":
        receiver = sys.argv[2]
        receive_message(receiver)

    else:
        print("Unknown command.")


if __name__ == "__main__":
    main()
