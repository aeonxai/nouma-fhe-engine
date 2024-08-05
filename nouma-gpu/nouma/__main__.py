from . import EncryptionParameters, Context, CKKSEncoder, SecretKey, PublicKey, RelinKey, GaloisKey, dot_product

import numpy as np

scale = 2**40

parms = EncryptionParameters.new(8192, [60, 40, 40, 40])
context = Context.new(parms)

encoder = CKKSEncoder.new(context)

secret_key = SecretKey.new(context)
public_key = PublicKey.new(context, secret_key)
relin_key = RelinKey.new(context, secret_key)
galois_key = GaloisKey.new(context, secret_key)

vec1 = np.array([1, 2, 3, 4], dtype=np.float64)
vec2 = np.array([5, 6, 7, 8], dtype=np.float64)

c1 = secret_key.encrypt(context, encoder.encode(context, vec1, scale))
c2 = secret_key.encrypt(context, encoder.encode(context, vec2, scale))


c3 = dot_product(context, c1, c2, relin_key, galois_key)

vec3 = encoder.decode(context, secret_key.decrypt(context, c3))

print(vec3)