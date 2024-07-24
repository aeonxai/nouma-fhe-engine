import pickle
import ctypes
import os
from typing import List
import numpy as np

# import platform

# os_name = platform.system()
# dll_path = ""

# if os_name == "Linux":
#     dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "lib", "seal_bin", "linux", "libseal.so"))
# elif os_name == "Darwin":
#     dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "lib", "seal_bin", "darwin", "libseal.dylib"))
# elif os_name == "Windows":
#     dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "lib", "seal_bin", "windows", "libseal.dll"))
    
# lib = ctypes.cdll.LoadLibrary(dll_path)

lib = ctypes.cdll.LoadLibrary(os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "lib", "SEAL-4.1.2", "build", "lib", "libseal.so")))

lib.PlaintextList_Delete.argtypes = (ctypes.c_void_p,)
lib.PlaintextList_Delete.restype = None

lib.CiphertextList_Delete.argtypes = (ctypes.c_void_p,)
lib.CiphertextList_Delete.restype = None

lib.SecretKey_Delete.argtypes = (ctypes.c_void_p,)
lib.SecretKey_Delete.restype = None

lib.PublicKey_Delete.argtypes = (ctypes.c_void_p,)
lib.PublicKey_Delete.restype = None

lib.RelinKeys_Delete.argtypes = (ctypes.c_void_p,)
lib.RelinKeys_Delete.restype = None

lib.EncryptionParameters_CKKSCreate.argtypes = (ctypes.c_size_t, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t)
lib.EncryptionParameters_CKKSCreate.restype = ctypes.c_void_p

lib.EncryptionParameters_Delete.argtypes = (ctypes.c_void_p,)
lib.EncryptionParameters_Delete.restype = None

lib.EncryptionParameters_Serialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.EncryptionParameters_Serialize.restype = None

lib.EncryptionParameters_Deserialize.argtypes = (ctypes.c_void_p, )
lib.EncryptionParameters_Deserialize.restype = ctypes.c_void_p

lib.SEALContext_New.argtypes = (ctypes.c_void_p,)
lib.SEALContext_New.restype = ctypes.c_void_p

lib.SEALContext_Delete.argtypes = (ctypes.c_void_p,)
lib.SEALContext_Delete.restype = None

lib.CKKSEncoder_New.argtypes = (ctypes.c_void_p,)
lib.CKKSEncoder_New.restype = ctypes.c_void_p

lib.CKKSEncoder_Delete.argtypes = (ctypes.c_void_p,)
lib.CKKSEncoder_Delete.restype = None

lib.CKKSEncoder_EncodeMany.argtypes = (ctypes.c_void_p, ctypes.c_double, ctypes.POINTER(ctypes.c_double), ctypes.c_size_t)
lib.CKKSEncoder_EncodeMany.restype = ctypes.c_void_p

lib.CKKSEncoder_DecodeMany.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_double), ctypes.c_size_t)
lib.CKKSEncoder_DecodeMany.restype = None

lib.KeyGenerator_New.argtypes = (ctypes.c_void_p,)
lib.KeyGenerator_New.restype = ctypes.c_void_p

lib.KeyGenerator_Delete.argtypes = (ctypes.c_void_p,)
lib.KeyGenerator_Delete.restype = None

lib.KeyGenerator_SecretKey.argtypes = (ctypes.c_void_p,)
lib.KeyGenerator_SecretKey.restype = ctypes.c_void_p

lib.KeyGenerator_PublicKey.argtypes = (ctypes.c_void_p,)
lib.KeyGenerator_PublicKey.restype = ctypes.c_void_p

lib.KeyGenerator_RelinKeys.argtypes = (ctypes.c_void_p,)
lib.KeyGenerator_RelinKeys.restype = ctypes.c_void_p

lib.Encryptor_New.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Encryptor_New.restype = ctypes.c_void_p

lib.SymmetricEncryptor_New.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.SymmetricEncryptor_New.restype = ctypes.c_void_p

lib.AsymmetricEncryptor_New.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.AsymmetricEncryptor_New.restype = ctypes.c_void_p

lib.Encryptor_Delete.argtypes = (ctypes.c_void_p,)
lib.Encryptor_Delete.restype = ctypes.c_void_p

lib.Encryptor_SymmetricEncryptMany.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.Encryptor_SymmetricEncryptMany.restype = ctypes.c_void_p

lib.Decryptor_New.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.Decryptor_New.restype = ctypes.c_void_p

lib.Decryptor_Delete.argtypes = (ctypes.c_void_p,)
lib.Decryptor_Delete.restype = None

lib.Decryptor_DecryptMany.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.Decryptor_DecryptMany.restype = ctypes.c_void_p

lib.Evaluator_New.argtypes = (ctypes.c_void_p,)
lib.Evaluator_New.restype = ctypes.c_void_p

lib.Evaluator_Delete.argtypes = (ctypes.c_void_p,)
lib.Evaluator_Delete.restype = None

lib.Evaluator_Add.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_Add.restype = ctypes.c_void_p

lib.Evaluator_AddInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_AddInplace.restype = None

lib.Evaluator_AddPlain.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_AddPlain.restype = ctypes.c_void_p

lib.Evaluator_AddPlainInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_AddPlainInplace.restype = None

lib.Evaluator_Subtract.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_Subtract.restype = ctypes.c_void_p

lib.Evaluator_SubtractInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_SubtractInplace.restype = None

lib.Evaluator_SubtractPlain.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_SubtractPlain.restype = ctypes.c_void_p

lib.Evaluator_SubtractPlainInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_SubtractPlainInplace.restype = None

lib.Evaluator_Multiply.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_Multiply.restype = ctypes.c_void_p

lib.Evaluator_MultiplyInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_MultiplyInplace.restype = None

lib.Evaluator_MultiplyPlain.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_MultiplyPlain.restype = ctypes.c_void_p

lib.Evaluator_MultiplyPlainInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_MultiplyPlainInplace.restype = None

lib.Evaluator_Relinearize.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_Relinearize.restype = ctypes.c_void_p

lib.Evaluator_RelinearizeInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_RelinearizeInplace.restype = None

lib.Evaluator_RescaleToNextInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_RescaleToNextInplace.restype = None

lib.Evaluator_ModSwitchToInplace.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.Evaluator_ModSwitchToInplace.restype = None

lib.CiphertextList_SetScale.argtypes = (ctypes.c_void_p, ctypes.c_double)
lib.CiphertextList_SetScale.restype = None

lib.SEALContext_PrintParms.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.SEALContext_PrintParms.restype = None

lib.CiphertextList_Scale.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
lib.CiphertextList_Scale.restype = ctypes.c_double

lib.CiphertextList_Clone.argtypes = (ctypes.c_void_p,)
lib.CiphertextList_Clone.restype = ctypes.c_void_p

lib.StringStream_New.argtypes = None
lib.StringStream_New.restype = ctypes.c_void_p

lib.StringStream_Delete.argtypes = (ctypes.c_void_p,)
lib.StringStream_Delete.restype = None

lib.StringStream_Tellg.argtypes = (ctypes.c_void_p,)
lib.StringStream_Tellg.restype = ctypes.c_size_t

lib.StringStream_Tellp.argtypes = (ctypes.c_void_p,)
lib.StringStream_Tellp.restype = ctypes.c_size_t

lib.StringStream_Write.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
lib.StringStream_Write.restype = None

lib.StringStream_Read.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
lib.StringStream_Read.restype = None

lib.CiphertextList_Serialize.argtypes = (ctypes.c_void_p,)
lib.CiphertextList_Serialize.restype = ctypes.c_void_p

lib.CiphertextList_Deserialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.CiphertextList_Deserialize.restype = ctypes.c_void_p

lib.SecretKey_Serialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.SecretKey_Serialize.restype = None

lib.PublicKey_Serialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.PublicKey_Serialize.restype = None

lib.RelinKeys_Serialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
lib.RelinKeys_Serialize.restype = None

lib.SecretKey_Deserialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.SecretKey_Deserialize.restype = None

lib.PublicKey_Deserialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.PublicKey_Deserialize.restype = None

lib.RelinKeys_Deserialize.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
lib.RelinKeys_Deserialize.restype = None

lib.SecretKey_New.argtypes = None
lib.SecretKey_New.restype = ctypes.c_void_p

lib.PublicKey_New.argtypes = None
lib.PublicKey_New.restype = ctypes.c_void_p

lib.RelinKeys_New.argtypes = None
lib.RelinKeys_New.restype = ctypes.c_void_p


lib.example.argtypes = None
lib.example.restype = None

class PlaintextList:
    def __init__(self, pointer, size) -> None:
        self.pointer = pointer
        self.size = size

    def __del__(self):
        lib.PlaintextList_Delete(self.pointer)


class CiphertextList:
    def __init__(self, pointer, size) -> None:
        self.pointer = pointer
        self.size = size

    @classmethod
    def clone(cls, other):
        return cls(lib.CiphertextList_Clone(other.pointer), other.size)

    def set_scale(self, scale: float):
        lib.CiphertextList_SetScale(self.pointer, scale)

    def scale(self, index: int) -> float:
        return lib.CiphertextList_Scale(self.pointer, index)

    def serialize(self) -> bytes:
        stream = StringStream(lib.CiphertextList_Serialize(self.pointer))
        data = stream.read()
        return pickle.dumps((data, self.size))

    @classmethod
    def deserialize(cls, context, data: bytes):
        data, size = pickle.loads(data)
        stream = StringStream.new()
        stream.write(data)
        return cls(lib.CiphertextList_Deserialize(context.pointer, stream.pointer), size)

    def __del__(self):
        lib.CiphertextList_Delete(self.pointer)


class EncryptionParameters:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls, poly_modulus_degree: int, bit_sizes: List[int]):
        return cls(lib.EncryptionParameters_CKKSCreate(poly_modulus_degree, (ctypes.c_int * len(bit_sizes))(*bit_sizes),
                                                       len(bit_sizes)))

    def serialize(self):
        stream = StringStream.new()
        lib.EncryptionParameters_Serialize(self.pointer, stream.pointer)
        return stream.read()

    @classmethod
    def deserialize(cls, data: bytes):
        stream = StringStream.new()
        stream.write(data)
        return cls(lib.EncryptionParameters_Deserialize(stream.pointer))

    def __del__(self) -> None:
        lib.EncryptionParameters_Delete(self.pointer)


class SEALContext:
    def __init__(self, parms: EncryptionParameters) -> None:
        self.pointer = lib.SEALContext_New(parms.pointer)

    def print_parms(self, ciphertext: CiphertextList):
        lib.SEALContext_PrintParms(self.pointer, ciphertext.pointer)

    def __del__(self) -> None:
        lib.SEALContext_Delete(self.pointer)


class CKKSEncoder:
    def __init__(self, context) -> None:
        self.pointer = lib.CKKSEncoder_New(context.pointer)

    def encode(self, array: np.ndarray, scale: float):
        return PlaintextList(
            pointer=lib.CKKSEncoder_EncodeMany(
                self.pointer,
                scale,
                array.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
                array.size
            ),
            size=array.size)

    def decode(self, inputs: PlaintextList):
        array = np.empty(shape=inputs.size, dtype=np.float64)
        lib.CKKSEncoder_DecodeMany(self.pointer, inputs.pointer, array.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
                                   inputs.size)
        return array

    def __del__(self):
        lib.CKKSEncoder_Delete(self.pointer)


class SecretKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls):
        return cls(lib.SecretKey_New())

    def serialize(self):
        stream = StringStream.new()
        lib.SecretKey_Serialize(self.pointer, stream.pointer)
        return stream.read()

    @staticmethod
    def deserialize(context: SEALContext, data: bytes):
        stream = StringStream.new()
        stream.write(data)
        secret_key = SecretKey.new()
        lib.SecretKey_Deserialize(secret_key.pointer, context.pointer, stream.pointer)
        return secret_key

    def __del__(self):
        lib.SecretKey_Delete(self.pointer)


class PublicKey:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls):
        return cls(lib.PublicKey_New())

    def serialize(self):
        stream = StringStream.new()
        lib.PublicKey_Serialize(self.pointer, stream.pointer)
        return stream.read()

    @classmethod
    def deserialize(cls, context: SEALContext, data: bytes):
        raise NotImplemented

    def __del__(self):
        lib.PublicKey_Delete(self.pointer)


class RelinKeys:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls):
        return cls(lib.RelinKeys_New())

    def serialize(self):
        stream = StringStream.new()
        lib.RelinKeys_Serialize(self.pointer, stream.pointer)
        return stream.read()

    @classmethod
    def deserialize(cls, context: SEALContext, data: bytes):
        raise NotImplemented

    def __del__(self):
        lib.RelinKeys_Delete(self.pointer)


class KeyGenerator:
    def __init__(self, context: SEALContext) -> None:
        self.pointer = lib.KeyGenerator_New(context.pointer)

    def secret_key(self):
        return SecretKey(lib.KeyGenerator_SecretKey(self.pointer))

    def public_key(self):
        return PublicKey(lib.KeyGenerator_PublicKey(self.pointer))

    def relin_keys(self):
        return RelinKeys(lib.KeyGenerator_RelinKeys(self.pointer))

    def __del__(self):
        lib.KeyGenerator_Delete(self.pointer)


class SymmetricEncryptor:
    def __init__(self, context: SEALContext, secret_key: SecretKey) -> None:
        self.pointer = lib.SymmetricEncryptor_New(context.pointer, secret_key.pointer)

    def encrypt(self, inputs: PlaintextList):
        return CiphertextList(lib.Encryptor_SymmetricEncryptMany(self.pointer, inputs.pointer), inputs.size)

    def __del__(self):
        lib.Encryptor_Delete(self.pointer)


class Decryptor:
    def __init__(self, context: SEALContext, secret_key: SecretKey) -> None:
        self.pointer = lib.Decryptor_New(context.pointer, secret_key.pointer)

    def decrypt(self, inputs: CiphertextList):
        return PlaintextList(lib.Decryptor_DecryptMany(self.pointer, inputs.pointer), inputs.size)

    def __del__(self):
        lib.Decryptor_Delete(self.pointer)


class Evaluator:
    def __init__(self, context: SEALContext) -> None:
        self.pointer = lib.Evaluator_New(context.pointer)

    def add(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator add expression")
        return CiphertextList(lib.Evaluator_Add(self.pointer, a.pointer, b.pointer), a.size)

    def add_inplace(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator add expression")
        lib.Evaluator_AddInplace(self.pointer, a.pointer, b.pointer)
        return a

    def add_plain(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator add expression")
        return CiphertextList(lib.Evaluator_AddPlain(self.pointer, a.pointer, b.pointer), a.size)

    def add_plain_inplace(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator add expression")
        lib.Evaluator_AddPlainInplace(self.pointer, a.pointer, b.pointer)
        return a

    def subtract(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator subtract expression")
        return CiphertextList(lib.Evaluator_Subtract(self.pointer, a.pointer, b.pointer), a.size)

    def subtract_inplace(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator subtract expression")
        lib.Evaluator_SubtractInplace(self.pointer, a.pointer, b.pointer)
        return a

    def subtract_plain(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator subtract expression")
        return CiphertextList(lib.Evaluator_SubtractPlain(self.pointer, a.pointer, b.pointer), a.size)

    def subtract_plain_inplace(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator subtract expression")
        lib.Evaluator_SubtractPlainInplace(self.pointer, a.pointer, b.pointer)
        return a

    def multiply(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator multiply expression")
        return CiphertextList(lib.Evaluator_Multiply(self.pointer, a.pointer, b.pointer), a.size)

    def multiply_inplace(self, a: CiphertextList, b: CiphertextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator multiply expression")
        lib.Evaluator_MultiplyInplace(self.pointer, a.pointer, b.pointer)
        return a

    def multiply_plain(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator multiply expression")
        return CiphertextList(lib.Evaluator_MultiplyPlain(self.pointer, a.pointer, b.pointer), a.size)

    def multiply_plain_inplace(self, a: CiphertextList, b: PlaintextList):
        if a.size != b.size:
            raise ValueError("a and b must have the same size in evaluator multiply expression")
        lib.Evaluator_MultiplyPlainInplace(self.pointer, a.pointer, b.pointer)
        return a

    def relinearize(self, relin_keys: RelinKeys, ciphertext: CiphertextList):
        return CiphertextList(lib.Evaluator_Relinearize(self.pointer, relin_keys.pointer, ciphertext.pointer),
                              ciphertext.size)

    def relinearize_inplace(self, relin_keys: RelinKeys, ciphertext: CiphertextList):
        lib.Evaluator_RelinearizeInplace(self.pointer, relin_keys.pointer, ciphertext.pointer)
        return ciphertext

    def rescale_to_next_inplace(self, ciphertext: CiphertextList):
        lib.Evaluator_RescaleToNextInplace(self.pointer, ciphertext.pointer)
        return ciphertext

    def mod_switch_to_inplace(self, destination: CiphertextList, source: CiphertextList):
        lib.Evaluator_ModSwitchToInplace(self.pointer, destination.pointer, source.pointer)
        return destination

    def __del__(self):
        lib.Evaluator_Delete(self.pointer)


class StringStream:
    def __init__(self, pointer) -> None:
        self.pointer = pointer

    @classmethod
    def new(cls):
        return cls(lib.StringStream_New())

    def tellg(self) -> int:
        return lib.StringStream_Tellg(self.pointer)

    def tellp(self) -> int:
        return lib.StringStream_Tellp(self.pointer)

    def write(self, data: bytes) -> None:
        lib.StringStream_Write(self.pointer, data, len(data))

    def read(self, size: int = None):
        size = size or self.tellp()
        data = bytes(size)
        lib.StringStream_Read(self.pointer, data, size)
        return data

    def __del__(self):
        lib.StringStream_Delete(self.pointer)
