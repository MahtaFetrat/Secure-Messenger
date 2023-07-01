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


class ElgamalKey():
  def __init__(self, q, α, Y, X=None, mod_size=1e250):
    self.q = q
    self.α = α
    self.Y = Y
    
    self.X = X
    
    self.mod_size=mod_size

  def unpack(self):
    return (self.q, self.α, self.Y), self.X
  

def elgamal_encrypt(m, elgamal_key):
  (q, α, Y), X = elgamal_key.unpack()

  inputbytes = str.encode(m)
  M = int(hexlify(inputbytes), 16)
  r = random.randint(int(elgamal_key.mod_size/2), elgamal_key.mod_size)
  k = pow(Y, r, q)
  C1 = pow(α, r, q)
  C2 = (k * M) % q
  return (str(C1), str(C2))


def elgamal_decrypt(C1, C2, elgamal_key):
  (q, α, Y), X = elgamal_key.unpack()

  C1, C2 = int(C1), int(C2)
  k = pow(C1, X, q)
  dec_M = (C2 * inverse(k, q)) % q
  hex_M = format(dec_M, 'x')
  # make hex_M of even length required by unhexlify
  hex_M = '0' + hex_M if len(hex_M) % 2 != 0 else hex_M
  return unhexlify(hex_M).decode()


def elgamal_generate_key(mod_size=1e250):
  q = sympy.randprime(mod_size*2, mod_size*4)
  α = sympy.randprime(int(mod_size/2), mod_size)
  X = random.randint(int(mod_size/2), mod_size)
  Y = pow(α, X, q)
  return ElgamalKey(q, α, Y, X, mod_size)


# elgamal_key = elgamal_generate_key(mod_size)
# message = "Hello World!"
# (C1, C2) = elgamal_encrypt(message, elgamal_key, 1024)
# print(C1, C2)

# m = elgamal_decrypt(C1, C2, elgamal_key)
# print(m)
