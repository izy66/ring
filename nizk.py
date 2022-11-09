from sage.all import *
from keygen import *

# NIZK{r: a^r = b}

def schnorr_proof(r, a, message = 1, on_curve = False):

  u = pp.RandInt()

  if not on_curve:
    t = a ** u
  else:
    t = a * u
  
  c = pp.Zr_hash(t) * message
  z = u + r * c

  return (z, t)

def schnorr_verify(a, b, resp, message = 1, on_curve = False):

  z, t = resp
  c = pp.Zr_hash(t) * message

  if not on_curve:
    return a ** z == b ** c * t
  else:
    return a * z == b * c + t

# NIZK{a,b: g^a * h^b = u}
# in our case, g, h, u are elements of Gt, a, b are elements of Z/rZ

def okamoto_proof(a, b, g, h, message = 1):

  x, y = (pp.RandInt(), pp.RandInt())
  t = g ** x * h ** y
  c = pp.Zr_hash(t) * message
  z = (x + c * a, y + c * b)

  return (z, t)

def okamoto_verify(g, h, u, resp, message):

  z, t = resp
  c = pp.Zr_hash(t) * message

  return g ** z[0] * h ** z[1] == t * u ** c

def verify_signature(PKtr, message, signature):

  PKsign, key_encryption_proof, PID_encryption_proof = signature
  PID_encryption, PID_proof = PID_encryption_proof
  message_hash = pp.Zr_hash(message)

  index = 0
  knowledge = 0

  for key_encryption, key_proof in key_encryption_proof:

    c1, c2 = key_encryption
    PKu = Ring[index][0]

    if not all([
      schnorr_verify(pp.g3, pairing(c1, pp.g2), key_proof[0]),
      schnorr_verify(pairing(PKu, pp.g2), pairing(c2, pp.g2)/PKsign, key_proof[1])]):

      return 0

    if not knowledge:

      user_PID = Ring[index][1]

      if all([
        schnorr_verify(pp.g3, user_PID, resp=PID_proof[0], message=message_hash),
        okamoto_verify(PKtr, PKsign, PID_encryption[2]/user_PID, resp=PID_proof[3], message=message_hash)]):

        knowledge = 1

    index += 1
  
  return all([
    knowledge, 
    schnorr_verify(pp.g3, PID_encryption[0], PID_proof[1], message=message_hash),
    schnorr_verify(pp.g2, PID_encryption[1], PID_proof[2], message=message_hash, on_curve=True)])

def verify_trace(PKtr, message, signature, PID, trace, proof_of_trace):

  if not verify_signature(PKtr, message, signature):

    print("Signature forgery detected!")
    return 0

  PKsign, key_encryption_proof, PID_encryption_proof = signature
  PID_encryption, PID_proof = PID_encryption_proof
  tr, SKsign = trace

  if not PID_encryption[2] / pairing(SKsign, PID_encryption[1]) == tr:

    print("Incorrect decryption of secret signing key!")
    return 0
  
  if not all([
    schnorr_verify(pp.g3, PKtr, proof_of_trace[0]),
    schnorr_verify(PID_encryption[0], tr / PID, proof_of_trace[1])]):
    
    print("Proof of trace didn't pass!")
    return 0

  if not pairing(SKsign, pp.g2) == PKsign:
    
    print("Signing key pair doesn't match!")
    return 0

  return 1
