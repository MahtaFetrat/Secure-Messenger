from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import pickle
from cryptography.hazmat.primitives.asymmetric import padding

BUFFSIZE = 1024

def client_rsa_keys(username, password):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3000,
        backend=default_backend()
    )

    # Generate public key from the private key
    public_key = private_key.public_key()

    # Serialize and store the public key
    public_key_path = f"public_key_{username}.pem"
    with open(public_key_path, "wb") as file:
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        file.write(public_key_bytes)

    # Derive encryption key from password using SHA3-256
    password_bytes = password.encode('utf-8')
    kdf = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    kdf.update(password_bytes)
    encryption_key = kdf.finalize()

    # Serialize and encrypt the private key
    private_key_path = f"private_key_{username}.pem"
    encryption_algorithm = serialization.BestAvailableEncryption(encryption_key)
    with open(private_key_path, "wb") as file:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        file.write(private_key_bytes)
        # print(private_key_bytes)


def send_encrypted_message(sock, message, receiver_public_key_path, sender_private_key_path, password):
    with open(receiver_public_key_path, "rb") as file:
        receiver_public_key = file.read().decode('utf-8')
    encrypted_message = encrypt_message_public_key(receiver_public_key, message)
    signed_message = sign_message(sender_private_key_path, password, encrypted_message)
    # Serialize the signed_message tuple
    serialized_message = pickle.dumps(signed_message)
    sock.sendall(serialized_message)


def receive_encrypted_message(sock, receiver_private_key_path, sender_public_key_path, password):
    private_key_receiver = decrypt_private_key(receiver_private_key_path, password)
    private_key_receiver = private_key_receiver.decode('utf-8')
    signed_message = sock.recv(BUFFSIZE)
    is_valid_signature, message = verify_signature(sender_public_key_path, signed_message)
    if is_valid_signature:
        decrypted_message = decrypt_message_private_key(private_key_receiver, message)
        return decrypted_message
    else:
        return "The message has been tampered with and the signature is not valid."


def encrypt_message_public_key(public_key_str, message):
    # Load the RSA public key from the string
    public_key = serialization.load_pem_public_key(public_key_str.encode(), backend=default_backend())

    # Encrypt the message using the public key

    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Base64 encode the encrypted message
    encoded_encrypted_message = base64.b64encode(encrypted_message)
    return encoded_encrypted_message.decode('utf-8')


def sign_message(private_key_path, password, message):
    # Decrypt the private key
    private_key = decrypt_private_key(private_key_path, password)

    # Load the private key object
    if isinstance(private_key, bytes):
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

    # Encode the message to bytes
    message_bytes = message.encode('utf-8')

    # Sign the message
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return message_bytes, signature


def decrypt_private_key(private_key_path, password):
    with open(private_key_path, "rb") as file:
        encrypted_private_key = file.read()
    if password == 'SERVER':
        return encrypted_private_key
    # Derive encryption key from password using SHA3-256
    password_bytes = password.encode('utf-8')
    kdf = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    kdf.update(password_bytes)

    encryption_key = kdf.finalize()
    # print(encryption_key)

    # encryption_algorithm = serialization.BestAvailableEncryption(encryption_key)
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=encryption_key,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # private_key_str = private_key_pem.decode('utf-8')
    # print(private_key_pem)
    return private_key_pem


def decrypt_message_private_key(private_key, encrypted_message):
    if isinstance(private_key, str):
        # Convert the private key string to the key object
        private_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None,
            backend=default_backend()
        )
    else:
        # Assume private_key is already an RSA private key object
        pass
    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')



def verify_signature(public_key_path, signed_message):
    # Deserialize the signed_message
    message_bytes, signature = pickle.loads(signed_message)

    # Load the public key
    with open(public_key_path, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )

    # Verify the signature
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return (True, message_bytes)  # Signature is valid
    except Exception:
        return (False, None)  # Signature is not valid
