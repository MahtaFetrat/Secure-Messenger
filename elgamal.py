# Source: https://github.com/mubix/elgamalcrypto/tree/master

# Notations:
#   Private Key: X
#   Public key: (q, α, Y), where Y = α^X mod q
#   Random parameter: r
#   Message Key: k, where k = Y^r mod q
#   C = (C1, C2)
#   C1 = α^r mod q
#   C2 = kM mod q, where M is the message

from Crypto.Util.number import inverse
import sympy
import random
from binascii import hexlify, unhexlify


def elgamal_encrypt(m, q, α, Y, BUFFSIZE):
  inputbytes = str.encode(m)
  M = int(hexlify(inputbytes), 16)
  r = random.randint(int(BUFFSIZE/2), BUFFSIZE)
  k = pow(Y, r, q)
  C1 = pow(α, r, q)
  C2 = (k * M) % q
  return (C1, C2)


def elgamal_decrypt(X, C1, C2, q):
  k = pow(C1, X, q)
  dec_M = (C2 * inverse(k, q)) % q
  hex_M = format(dec_M, 'x')
  # make hex_M of even length required by unhexlify
  hex_M = '0' + hex_M if len(hex_M) % 2 != 0 else hex_M
  return unhexlify(hex_M)


def elgamal_generate_key(BUFFSIZE):
  q = sympy.randprime(BUFFSIZE*2, BUFFSIZE*4)
  α = sympy.randprime(int(BUFFSIZE/2), BUFFSIZE)
  X = random.randint(int(BUFFSIZE/2), BUFFSIZE)
  Y = pow(α, X, q)
  return (q, α, Y), X


# (q, α, Y), X = elgamal_generate_key(1e250)
# message = "Hello World!"
# (C1, C2) = elgamal_encrypt(message, q, α, Y, 1024)
# print(C1, C2)

# m = elgamal_decrypt(X, C1, C2, q)
# print(m)
