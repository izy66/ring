from sage.all import *
from nizk import *
from keygen import *

class User:

  # Generate a random key pair for each RING user

  def __init__(self) -> None:
    self.__secret_key = pp.RandInt()
    self.public_key = pp.G1(self.__secret_key)
    self.public_id = pp.Gt(self.__secret_key)
    self.index = len(Ring)
    Ring.append(R(self.public_key, self.public_id))

  # Generate a random signing key pair 
  # (PKsign, SKsign) in (Gt, G1)

  def gen_signing_keys():

    r = pp.RandInt()
    SKsign = pp.G1(r)
    PKsign = pp.Gt(r)

    return (PKsign, SKsign)

  # encrypt self's secret signing key under each user's public key 
  # and generate a proof of correct encryption:

  def encrypt_sig_key_and_proof(self, sign_key, ring_public_key):

    r = pp.RandInt()

    key_encryption = (pp.g1 * r, ring_public_key * r + sign_key)
    key_proof = (schnorr_proof(r, pp.g3), schnorr_proof(r, pairing(ring_public_key, pp.g2)))

    return (key_encryption, key_proof)

  # encrypt self's public identification under tracer's public key
  # and self's signing key, and generate a signature of correct encryption

  ### Signature of Knowledge ###

  # parse (c1, c2, c3) <- c23,
  # prove {(r2, r3, SKu, i): PID_i = g3 ^ SKu, and
  #        PKtr ^ r2 * PKsign ^ r3 = c3 / PID_i}

  def encrypt_PID_and_sign(self, PKtr, PKsign, message):

    r2, r3 = (pp.RandInt(), pp.RandInt())

    PID_encryption = [pp.g3 ** r2, pp.g2 * r3, PKtr ** r2 * PKsign ** r3 * self.public_id]
    PID_signature = signature_of_knowledge_proof(self.index, self.__secret_key, r2, r3, PKtr, PKsign, PID_encryption, message)

    return (PID_encryption, PID_signature)

  # sign a message (bytes) by encrypting the secret signing key to each Ring member
  # and encrypt self's public identity with the public signing key and tracer's public key
  # with ZK proofs to ensure correct encryption to both parties.

  def sign(self, PKtr, message):

    PKsign, SKsign = User.gen_signing_keys()

    key_encryption_proof = [self.encrypt_sig_key_and_proof(SKsign, Public_User[0]) for Public_User in Ring]
    PID_encryption_signature = self.encrypt_PID_and_sign(PKtr, PKsign, message)

    return [PKsign, key_encryption_proof, PID_encryption_signature]

  # report a signature by decrypting the corresponding signing key
  # no proof of correct decryption is needed since every party can check
  # (PKsign, SKsign) is a correct key pair if both are known

  def report(self, PKtr, message, signature):

    if not signature_verify(PKtr, message, signature):
      return 0

    signing_key_encryption_proof = signature[1]
    
    cipher = signing_key_encryption_proof[self.index][0]
    SKsign = cipher[1] - cipher[0] * self.__secret_key

    return SKsign
