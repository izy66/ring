from sage.all import *
from nizk import *
from keygen import Ring, pp
import user, tracer

if __name__ == "__main__":

  [user.User() for _ in range(10)]

  user = user.User()
  tracer = tracer.Tracer()

  message = b"Yellow Submarine"

  signature = user.sign(tracer.public_key, message)

  report = user.report(tracer.public_key, message, signature)

  PID, trace, proof_of_trace = tracer.trace(message, signature, report)

  assert(verify_trace(tracer.public_key, message, signature, PID, trace, proof_of_trace))

