from sage.all import *
from nizk import *
from keygen import *

class Tracer():

  # Generate a random key pair for the Tracer
  # (PKt, SKt) in (Gt, Z/rZ)

  def __init__(self) -> None:
    self.__secret_key = pp.RandInt()
    self.public_key = pp.Gt(self.__secret_key)

  # tracer first verify the signature,
  # then decrypt the public identification of the signer
  # and generate a proof of correct decryption

  def trace(self, message, signature, report):

    try:
      if not signature_verify(self.public_key, message, signature):
        return 0
    except:
      raise("Signature verification issue!")

    SKsign = report
    PKsign, key_encryption_proof, PID_encryption_signature = signature

    try:

      if not PKsign == pairing(SKsign, pp.g2):
        return 0
    
    except:

      raise("Opps! What's wrong with this report?")

    PID_encryption, PID_signature = PID_encryption_signature

    tr = PID_encryption[2] / pairing(SKsign, PID_encryption[1])
    PID = tr / (PID_encryption[0] ** self.__secret_key) 

    proof_of_trace = [
      schnorr_proof(self.__secret_key, pp.g3),
      schnorr_proof(self.__secret_key, PID_encryption[0])
    ]
    
    return (PID, (tr, SKsign), proof_of_trace)
