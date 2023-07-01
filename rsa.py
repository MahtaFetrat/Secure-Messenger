from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def client_rsa_keys(username, password):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
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

