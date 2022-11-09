from sage.all import *
from sage.calculus.predefined import x
from cryptography.hazmat.primitives import hashes

# Parameters of Type D curve : 
#    q : base field size
# a, b : curve parameters
#    n : group order on curve
#    r : torsion group size
#    k : embedding degree

q = 15028799613985034465755506450771565229282832217860390155996483840017
a = 1871224163624666631860092489128939059944978347142292177323825642096
b = 9795501723343380547144152006776653149306466138012730640114125605701

n = 15028799613985034465755506450771561352583254744125520639296541195021
r = 15028799613985034465755506450771561352583254744125520639296541195021
k = 6

F = GF(q ** 6, modulus=x**6+x+1, name='a')
E = EllipticCurve(F, [a, b])
Frob = [F.frobenius_endomorphism(i) for i in range(k)]

Ring = []

def pairing(e1, e2):
  return e1.weil_pairing(e2, r)

class GenPP:

  # Generate public parameters for pairing and encryption
  # g1 : generator of G1 group
  # g2 : generator of G2 group
  # g3 : generator of Gt group

  def Trace(self, P):
    Q = P
    
    for i in range(1,k):
      X = Frob[i](P[0])
      Y = Frob[i](P[1])
      Q = Q + E(X, Y)
    
    return Q

  def __init__(self) -> None:

    ord = E.order() / r ** 2

    g = E.random_point()

    while (g * ord).is_zero():
      g = E.random_point()

    g = g * ord

    self.g1 = self.Trace(g)
    self.g2 = k * g - self.g1

    self.g3 = pairing(self.g1, self.g2)

    self.ModRing = IntegerModRing(r)

  # return a point in G1 by computing g1 ^ index

  def G1(self, index = 1):
    return self.g1 * index

  # return the point in Gt mapped from (x, g2)

  def Gt(self, index = 1):
    return pairing(self.g1 * index, self.g2)

  # returns a deterministic hashing to Z/rZ
  # element can either be 
  # - a bytes string, or
  # - a finite field element, or
  # - a r-torsion point on curve

  def Zr_hash(self, element):

    try:

      element.decode()
      message = element

    except AttributeError:

      try:

        element = element.xy()[0]

      except:

        pass
    
      coef_str = '.'.join(map(str, element.polynomial().coefficients()))
      message = coef_str.encode()

    digest = hashes.Hash(hashes.SHA224())
    digest.update(message)
    return self.ModRing(int.from_bytes(digest.finalize(), 'big'))

  # return a random element from Z/rZ

  def RandInt(self):
    return self.ModRing.random_element()

pp = GenPP()