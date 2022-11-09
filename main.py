from sage.all import *
from nizk import *
from keygen import Ring, pp
import user, tracer
from time import time

if __name__ == "__main__":

  [user.User() for _ in range(50)]

  user = user.User()
  tracer = tracer.Tracer()

  message = b"Yellow Submarine"

  clock = time()
  signature = user.sign(tracer.public_key, message)

  print("signature time:", time() - clock)
  clock = time()

  report = user.report(tracer.public_key, message, signature)
  print("report time:", time() - clock)
  clock = time()

  PID, trace, proof_of_trace = tracer.trace(message, signature, report)
  print("trace time:", time() - clock)
  clock = time()

  assert(trace_verify(tracer.public_key, message, signature, PID, trace, proof_of_trace))
  print("trace verification time:", time() - clock)

