import ctypes
import os
from typing import List
import numpy as np


lib = ctypes.cdll.LoadLibrary(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "build", "lib", "libPhantom.so")))

lib.EncryptionParameters_CKKSCreate.argtypes = (ctypes.c_size_t, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t)
lib.EncryptionParameters_CKKSCreate.restype = ctypes.c_void_p

lib.EncryptionParameters_Delete.argtypes = (ctypes.c_void_p,)
lib.EncryptionParameters_Delete.restype = None


class EncryptionParameters:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, poly_modulus_degree: int, bit_sizes: List[int]):
        return cls(lib.EncryptionParameters_CKKSCreate(poly_modulus_degree, (ctypes.c_int * len(bit_sizes))(*bit_sizes), len(bit_sizes)))

    def __del__(self) -> None:
        lib.EncryptionParameters_Delete(self.pointer)

lib.Context_New.argtypes = (ctypes.c_void_p,)
lib.Context_New.restype = ctypes.c_void_p

lib.Context_Delete.argtypes = (ctypes.c_void_p,)
lib.Context_Delete.restype = None


class Context:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, parms: EncryptionParameters):
        return cls(lib.Context_New(parms.pointer))
    def __del__(self) -> None:
        lib.Context_Delete(self.pointer)


lib.Plaintext_New.argtypes = None
lib.Plaintext_New.restype = ctypes.c_void_p

lib.Ciphertext_New.argtypes = None
lib.Ciphertext_New.restype = ctypes.c_void_p

lib.Plaintext_Delete.argtypes = (ctypes.c_void_p,)
lib.Plaintext_Delete.restype = None

lib.Ciphertext_Delete.argtypes = (ctypes.c_void_p,)
lib.Ciphertext_Delete.restype = None


class Plaintext:
    def __init__(self, pointer, size) -> None:
        self.pointer = pointer
        self.size = size

    @classmethod
    def new(cls, size=0):
        return cls(lib.Plaintext_New(), size)

    def __del__(self):
        lib.Plaintext_Delete(self.pointer)

class Ciphertext:
    def __init__(self, pointer, size) -> None:
        self.pointer = pointer
        self.size = size

    @classmethod
    def new(cls, size=0):
        return cls(lib.Ciphertext_New(), size)

    def __del__(self):
        lib.Ciphertext_Delete(self.pointer)


lib.SecretKey_Create.argtypes = (ctypes.c_void_p,)
lib.SecretKey_Create.restype = ctypes.c_void_p

lib.PublicKey_Create.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.PublicKey_Create.restype = ctypes.c_void_p

lib.RelinKey_Create.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.RelinKey_Create.restype = ctypes.c_void_p

lib.GaloisKey_Create.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.GaloisKey_Create.restype = ctypes.c_void_p

lib.SecretKey_Delete.argtypes = (ctypes.c_void_p,)
lib.SecretKey_Delete.restype = None

lib.PublicKey_Delete.argtypes = (ctypes.c_void_p,)
lib.PublicKey_Delete.restype = None

lib.RelinKey_Delete.argtypes = (ctypes.c_void_p,)
lib.RelinKey_Delete.restype = None

lib.GaloisKey_Delete.argtypes = (ctypes.c_void_p,)
lib.GaloisKey_Delete.restype = None


lib.SecretKey_EncryptSymmetric.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.SecretKey_EncryptSymmetric.restype = None

lib.SecretKey_Decrypt.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.SecretKey_Decrypt.restype = None

class SecretKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, context: Context):
        return cls(lib.SecretKey_Create(context.pointer))

    def __del__(self):
        lib.SecretKey_Delete(self.pointer)

    def encrypt(self, context: Context, plaintext: Plaintext):
        ciphertext = Ciphertext.new(plaintext.size)
        lib.SecretKey_EncryptSymmetric(self.pointer, context.pointer, plaintext.pointer, ciphertext.pointer)
        return ciphertext

    def decrypt(self, context: Context, ciphertext: Ciphertext):
        plaintext = Plaintext.new(ciphertext.size)
        lib.SecretKey_Decrypt(self.pointer, context.pointer, ciphertext.pointer, plaintext.pointer)
        return plaintext


class PublicKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, context: Context, secret_key: SecretKey):
        return cls(lib.PublicKey_Create(context.pointer, secret_key.pointer))

    def __del__(self):
        lib.PublicKey_Delete(self.pointer)


class RelinKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, context: Context, secret_key: SecretKey):
        return cls(lib.RelinKey_Create(context.pointer, secret_key.pointer))

    def __del__(self):
        lib.RelinKey_Delete(self.pointer)


class GaloisKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, context: Context, secret_key: SecretKey):
        return cls(lib.GaloisKey_Create(context.pointer, secret_key.pointer))

    def __del__(self):
        lib.GaloisKey_Delete(self.pointer)



lib.CKKSEncoder_New.argtypes = (ctypes.c_void_p,)
lib.CKKSEncoder_New.restype = ctypes.c_void_p

lib.CKKSEncoder_Delete.argtypes = (ctypes.c_void_p,)
lib.CKKSEncoder_Delete.restype = None

lib.CKKSEncoder_Encode.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_size_t, ctypes.c_double, ctypes.c_void_p)
lib.CKKSEncoder_Encode.restype = None

lib.CKKSEncoder_Decode.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_size_t)
lib.CKKSEncoder_Decode.restype = None

class CKKSEncoder:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, context: Context):
        return cls(lib.CKKSEncoder_New(context.pointer))

    def encode(self, context: Context, array: np.ndarray, scale: float):
        plaintext = Plaintext.new(array.size)
        lib.CKKSEncoder_Encode(self.pointer, context.pointer, array.ctypes.data_as(ctypes.POINTER(ctypes.c_double)), array.size, scale, plaintext.pointer)
        return plaintext

    def decode(self, context: Context, plaintext: Plaintext):
        array = np.empty(shape=plaintext.size, dtype=np.float64)
        lib.CKKSEncoder_Decode(self.pointer, context.pointer, plaintext.pointer, array.ctypes.data_as(ctypes.POINTER(ctypes.c_double)), array.size)
        return array

    def __del__(self):
        lib.CKKSEncoder_Delete(self.pointer)


lib.Dot_Product.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Dot_Product.restype = None

def dot_product(context: Context, left: Ciphertext, right: Ciphertext, relin_key: RelinKey, galois_key: GaloisKey):
    assert left.size == right.size
    output = Ciphertext.new(left.size)
    
    lib.Dot_Product(context.pointer, left.pointer, right.pointer, output.pointer, relin_key.pointer, galois_key.pointer)

    return output