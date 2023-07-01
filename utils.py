import hashlib
import string
from elgamal import elgamal_encrypt, elgamal_decrypt
import math

def sha3_256_hash(message):
    hash_object = hashlib.sha3_256()
    hash_object.update(message.encode('utf-8'))
    return hash_object.hexdigest()

# password = "Helloworld!"
# hash_value = sha3_256_hash(password)
# print("SHA-3 hash:", hash_value)


def check_password_strength(password):
    length = len(password)
    uppercase_count = sum(1 for c in password if c.isupper())
    lowercase_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    special_count = sum(1 for c in password if c in string.punctuation)
    if length >= 8 and uppercase_count >= 1 and lowercase_count >= 1 and digit_count >= 1 and special_count >= 1:
        return True
    else:
        return False


def create_e2e_message(message, sequence_number, elgamal_key):
    FORMAT = "{sequence_numbers}\n\n{message}"
    formatted_message = FORMAT.format(
        sequence_numbers=sequence_number,
        message=message
    )
    return elgamal_encrypt(formatted_message, elgamal_key)

def read_e2e_message(username, sequence_numbers, C1, C2, elgamal_key):
    decrypted_message = elgamal_decrypt(C1, C2, elgamal_key)
    splitted_message = decrypted_message.split("\n\n")
    sequence_number = int(splitted_message[0])
    message = '\n\n'.join(splitted_message[1:])

    if username not in sequence_numbers:
        sequence_numbers[username] = sequence_number - 1
        
    if sequence_number != sequence_numbers[username] + 1:
        return 0, ""
    else:
        return sequence_number, message
    
def send(message, sock, BUFFSIZE=1024):
    # message_lenght = len(message)
    # chuncks = math.ceil(message_lenght / BUFFSIZE)
    # sock.send(str(chuncks).encode())
    # sock.recv(BUFFSIZE).decode()    # ACK
    # for chunk in range(chuncks):
    #     sock.send(message[chunk * BUFFSIZE:(chunk + 1) * BUFFSIZE].encode())
    #     sock.recv(BUFFSIZE).decode()    # ACK

    sock.send(message.encode())

def receive(sock, BUFFSIZE=1024):
    # chunks = int(sock.recv(BUFFSIZE).decode())
    # sock.send("ACK".encode())

    # message_parts = []
    # for _ in range(chunks):
    #     message_parts.append(sock.recv(BUFFSIZE).decode())
    #     sock.send("ACK".encode())    # ACK

    # return ''.join(message_parts)

    return sock.recv(BUFFSIZE).decode()
