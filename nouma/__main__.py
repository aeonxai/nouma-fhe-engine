import numpy as np
from nouma import CKKSEncoder, Decryptor, EncryptionParameters, Evaluator, KeyGenerator, SEALContext, SymmetricEncryptor

if __name__ == "__main__":
    scale = 2 ** 40
    parms = EncryptionParameters.new(8192, [60, 40, 40, 40])
    context = SEALContext(parms)
    encoder = CKKSEncoder(context)
    keygen = KeyGenerator(context)
    secret_key = keygen.secret_key()
    public_key = keygen.public_key()
    relin_keys = keygen.relin_keys()
    gal_keys = keygen.galois_keys()
    encryptor = SymmetricEncryptor(context, secret_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)
    a1 = np.ones(10, "float64") * 2
    a2 = np.ones(10, "float64") * 3
    v1 = encryptor.encrypt(encoder.encode(a1, scale))
    v2 = encryptor.encrypt(encoder.encode(a2, scale))
    v3 = evaluator.dot_product(relin_keys, gal_keys, v1, v2)
    # c = CiphertextList.deserialize(context, v3.serialize())
    print(encoder.decode(decryptor.decrypt(v3)))
    print(np.sum(a1 * a2))