from sage.all import *
from keygen import *

# NIZK{r: a^r = b}

def schnorr_proof(r, a):

  u = pp.RandInt()
  t = a ** u
  c = pp.Zr_hash(t)
  z = u + r * c

  return (t, z)

def schnorr_verify(a, b, resp):

  t, z = resp
  c = pp.Zr_hash(t)

  return a ** z == b ** c * t

# verify the correctness of signature by checking:
# 1. correct encryption of signature key to each ring members;
# 2. correct encryption of public id under verification key and tracer's key

# !!! any third parties (not nessesary a Ring member) should be able to verify the signature
# without revealing which member generated such signature,
# thus anonymity is ensured among the Ring.

def signature_verify(PKtr, message, signature):

  PKsign, key_encryption_proof, PID_encryption_signature = signature

  for i in range(len(Ring)):

    key_encryption, key_proof = key_encryption_proof[i]

    c1, c2 = key_encryption
    PKu = Ring[i].public_key
    PID = Ring[i].public_id

    if not all([
      schnorr_verify(pp.g3, pairing(c1, pp.g2), key_proof[0]),
      schnorr_verify(PID, pairing(c2, pp.g2)/PKsign, key_proof[1])]):

      return 0
  
  return signature_of_knowledge_verify(PID_encryption_signature, PKtr, PKsign, message)

# generate a simulation with Schnorr's protocol,

def schnorr_simulate(g, u, c):

  z = pp.RandInt()
  t = g ** z / u ** c

  return (t, z)

def schnorr_sim_verify(a, b, t, c, z):

  return a ** z == b ** c * t

# generate a simulation with Okamoto protocol,

def okamoto_simulate(g, h, u, c):

  z = (pp.RandInt(), pp.RandInt())
  t = g ** z[0] * h ** z[1] / u ** c
  
  return (t, z)

def okamoto_sim_verify(g, h, u, t, c, z):

  return g ** z[0] * h ** z[1] == u ** c * t

# 1. prove the signer is a member of the Ring
# 2. prove the correct encryption of signer's own public id
# {(sk, r2, r3, i) : g3 ^ sk = PID_i and PKtr ^ r2 * PKsign ^ r3 * PID_i = c3}

def signature_of_knowledge_proof(index, secret_key, r2, r3, PKtr, PKsign, PID_encryption, message):

  commit_schnorr, commit_okamoto = ([0] * len(Ring), [0] * len(Ring))
  challenge = []
  response_schnorr, response_okamoto = ([0] * len(Ring), [0] * len(Ring))

  c_sum = 0
  c = pp.Zr_hash(message)

  for i in range(len(Ring)):

    challenge.append(Integer(pp.RandInt()))
    commit_schnorr[i], response_schnorr[i] = (schnorr_simulate(pp.g3, Ring[i].public_id, challenge[i]))
    commit_okamoto[i], response_okamoto[i] = (okamoto_simulate(PKtr, PKsign, PID_encryption[2] / Ring[i].public_id, challenge[i]))

    if i != index:
      c_sum = c_sum ^ challenge[i]
      c *= pp.Zr_hash(commit_schnorr[i]) * pp.Zr_hash(commit_okamoto[i])

  u = (pp.RandInt(), pp.RandInt())

  commit_schnorr[index] = pp.g3 ** u[0]
  commit_okamoto[index] = PKtr ** u[0] * PKsign ** u[1]

  c *= pp.Zr_hash(commit_schnorr[index]) * pp.Zr_hash(commit_okamoto[index])

  challenge[index] = Integer(c) ^ c_sum

  response_schnorr[index] = secret_key * challenge[index] + u[0]
  response_okamoto[index] = (r2 * challenge[index] + u[0], r3 * challenge[index] + u[1])

  return [(commit_schnorr, commit_okamoto), challenge[:-1], (response_schnorr, response_okamoto)]

def signature_of_knowledge_verify(PID_encryption_signature, PKtr, PKsign, message):

  PID_encryption, PID_signature = PID_encryption_signature
  (commit_schnorr, commit_okamoto), challenge, (response_schnorr, response_okamoto) = PID_signature

  c = pp.Zr_hash(message)

  for com in commit_schnorr: 
    c *= pp.Zr_hash(com) 

  for com in commit_okamoto:
    c *= pp.Zr_hash(com)

  c = Integer(c)

  for ch in challenge:
    c = c ^ ch
  
  challenge.append(c)

  return all([
    schnorr_sim_verify(pp.g3, Ring[i].public_id, commit_schnorr[i], challenge[i], response_schnorr[i])
    for i in range(len(Ring))
  ]) and all([
    okamoto_sim_verify(PKtr, PKsign, PID_encryption[2] / Ring[i].public_id, commit_okamoto[i], challenge[i], response_okamoto[i])
    for i in range(len(Ring))
  ])

def trace_verify(PKtr, message, signature, PID, trace, proof_of_trace):

  if not signature_verify(PKtr, message, signature):

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
