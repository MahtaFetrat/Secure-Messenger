import hashlib
import string
from elgamal import elgamal_encrypt, elgamal_decrypt


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


def create_e2e_message(username, message, sequence_numbers, elgamal_key):
    (q, α, Y), X = elgamal_key.unpack()

    FORMAT = "{sequence_numbers}\n\n{message}"
    sequence_numbers[username] += 1
    formatted_message = FORMAT.format(
        sequence_numbers=sequence_numbers[username],
        message=message
    )
    return elgamal_encrypt(formatted_message, q, α, Y, elgamal_key.mod_size)

def read_e2e_message(username, sequence_numbers, C1, C2, elgamal_key):
    (q, α, Y), X = elgamal_key.unpack()

    decrypted_message = elgamal_decrypt(X, C1, C2, q)
    splitted_message = decrypted_message.split("\n\n")
    sequence_number = int(splitted_message[0])
    message = '\n\n'.join(splitted_message[1:])

    if username not in sequence_numbers:
        sequence_numbers[username] = sequence_number - 1
        
    if sequence_number != sequence_numbers[username] + 1:
        return 0, ""
    else:
        return sequence_number, message