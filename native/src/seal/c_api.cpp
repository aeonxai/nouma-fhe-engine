#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "seal/seal.h"

using namespace seal;

using Vector = std::vector<double>;
using PlaintextList = std::vector<Plaintext>;
using CiphertextList = std::vector<Ciphertext>;

const double kScale = pow(2.0, 40);
const size_t kPolyModulusDegreePower = 12;
const size_t kPolyModulusDegree = pow(2, kPolyModulusDegreePower);

template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}


void rotate_sum(const Evaluator &evaluator, Ciphertext &cipher, const GaloisKeys &keys) {
    Ciphertext rotated;
    for (int i = 0; i < kPolyModulusDegreePower; i++) {
        evaluator.rotate_vector(cipher, pow(2, i), keys, rotated);
        evaluator.add_inplace(cipher, rotated);
    }
}



extern "C" {

EncryptionParameters *EncryptionParameters_CKKSCreate(size_t poly_modulus_degree, const int *bit_sizes, size_t length) {
    // std::cout << "EncryptionParameters_CKKSCreate" << std::endl;
    EncryptionParameters *params =  new EncryptionParameters(scheme_type::ckks);
    params->set_poly_modulus_degree(poly_modulus_degree);
    params->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, std::vector<int>(bit_sizes, bit_sizes + length)));
    return params;
}

void EncryptionParameters_Delete(EncryptionParameters *params) {
    // std::cout << "EncryptionParameters_Delete" << std::endl;
    delete params;
}

void EncryptionParameters_Serialize(EncryptionParameters *parms, std::stringstream *stream) {
    parms->save(*stream);
}

EncryptionParameters *EncryptionParameters_Deserialize(std::stringstream *stream) {
    auto parms = new EncryptionParameters();
    parms->load(*stream);
    return parms;
}

SEALContext *SEALContext_New(EncryptionParameters *params) {
    // std::cout << "SEALContext_New" << std::endl;
    return new SEALContext(*params);
}

void SEALContext_Delete(SEALContext *ctx) {
    // std::cout << "SEALContext_Delete" << std::endl;
    delete ctx;
}

CKKSEncoder *CKKSEncoder_New(SEALContext *ctx) {
    // std::cout << "CKKSEncoder_New" << std::endl;
    return new CKKSEncoder(*ctx);
}



PlaintextList *CKKSEncoder_EncodeMany(CKKSEncoder *encoder, double scale, double *inputs, size_t length) {
    // std::cout << "CKKSEncoder_EncodeMany" << std::endl;
    auto slot_count = encoder->slot_count();
    auto outputs = new PlaintextList((size_t) ceil((double) length / slot_count));
    Vector vec(slot_count);
    for (auto &plaintext : *outputs) {
        vec.assign(inputs, inputs + std::min(slot_count, length));
        encoder->encode(vec, scale, plaintext);
        inputs += slot_count;
        length -= slot_count;
    }
    return outputs;
}

void CKKSEncoder_DecodeMany(CKKSEncoder *encoder, PlaintextList *inputs, double *outputs, size_t length) {
    // std::cout << "CKKSEncoder_DecodeMany" << std::endl;
    auto slot_count = encoder->slot_count();
    Vector vec(slot_count);
    for (auto &plaintext : *inputs) {
        encoder->decode(plaintext, vec);
        std::copy(vec.begin(), vec.begin() + std::min(slot_count, length), outputs);
        outputs += slot_count;
        length -= slot_count;
    }
}

// ========================================================================= //
// ============================= KeyGenerator ============================== //
// ========================================================================= //

KeyGenerator *KeyGenerator_New(SEALContext *ctx) {
    // std::cout << "KeyGenerator_New" << std::endl;
    return new KeyGenerator(*ctx);
}

SecretKey *KeyGenerator_SecretKey(KeyGenerator *keygen) {
    // std::cout << "KeyGenerator_SecretKey" << std::endl;
    auto secret_key = new SecretKey();
    *secret_key = keygen->secret_key();
    return secret_key;
}

PublicKey *KeyGenerator_PublicKey(KeyGenerator *keygen) {
    // std::cout << "KeyGenerator_PublicKey" << std::endl;
    auto public_key = new PublicKey();
    keygen->create_public_key(*public_key);
    return public_key;
}

RelinKeys *KeyGenerator_RelinKeys(KeyGenerator *keygen) {
    // std::cout << "KeyGenerator_RelinKeys" << std::endl;
    auto relin_keys = new RelinKeys();
    keygen->create_relin_keys(*relin_keys);
    return relin_keys;
}

GaloisKeys *KeyGenerator_GaloisKeys(KeyGenerator *keygen) {
    auto galois_keys = new GaloisKeys();
    keygen->create_galois_keys(*galois_keys);
    return galois_keys;
}

// ========================================================================= //
// ============================ Encrypt/Decrypt ============================ //
// ========================================================================= //

Encryptor *Encryptor_New(SEALContext *ctx, PublicKey *public_key, SecretKey *secret_key) {
    // std::cout << "Encryptor_New" << std::endl;
    return new Encryptor(*ctx, *public_key, *secret_key);
}

Encryptor *SymmetricEncryptor_New(SEALContext *ctx, SecretKey *secret_key) {
    // std::cout << "SymmetricEncryptor_New" << std::endl;
    return new Encryptor(*ctx, *secret_key);
}

Encryptor *AsymmetricEncryptor_New(SEALContext *ctx, PublicKey *public_key) {
    // std::cout << "AsymmetricEncryptor_New" << std::endl;
    return new Encryptor(*ctx, *public_key);
}

Decryptor *Decryptor_New(SEALContext *ctx, SecretKey *secret_key) {
    // std::cout << "Decryptor_New" << std::endl;
    return new Decryptor(*ctx, *secret_key);
}

CiphertextList *Encryptor_SymmetricEncryptMany(Encryptor *encryptor, PlaintextList *inputs) {
    // std::cout << "Encryptor_SymmetricEncrypt" << std::endl;
    auto size = inputs->size();
    auto outputs = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        encryptor->encrypt_symmetric((*inputs)[i], (*outputs)[i]);
    }
    return outputs;
}

CiphertextList *Encryptor_AsymmetricEncryptMany(Encryptor *encryptor, PlaintextList *inputs) {
    // std::cout << "Encryptor_AsymmetricEncrypt" << std::endl;
    auto size = inputs->size();
    auto outputs = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        encryptor->encrypt((*inputs)[i], (*outputs)[i]);
    }
    return outputs;
}

PlaintextList *Decryptor_DecryptMany(Decryptor *decryptor, CiphertextList *inputs) {
    // std::cout << "Decryptor_DecryptMany" << std::endl;
    auto size = inputs->size();
    auto outputs = new PlaintextList(inputs->size());
    for (int i = 0; i < size; ++i) {
        decryptor->decrypt((*inputs)[i], (*outputs)[i]);
    }
    return outputs;
}

// ========================================================================= //
// ============================== Evaluator ================================ //
// ========================================================================= //

Evaluator *Evaluator_New(SEALContext *ctx) {
    // std::cout << "Evaluator_New" << std::endl;
    return new Evaluator(*ctx);
}

void Evaluator_Delete(Evaluator *evaluator) {
    // std::cout << "Evaluator_Delete" << std::endl;
    delete evaluator;
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_Add(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_Add" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->add((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_AddInplace(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_AddInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->add_inplace((*a)[i], (*b)[i]);
    }
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_AddPlain(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_AddPlain" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->add_plain((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_AddPlainInplace(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_AddPlainInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->add_plain_inplace((*a)[i], (*b)[i]);
    }
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_Subtract(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_Subtract" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->sub((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_SubtractInplace(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_SubtractInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->sub_inplace((*a)[i], (*b)[i]);
    }
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_SubtractPlain(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_SubtractPlain" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->sub_plain((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_SubtractPlainInplace(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_SubtractPlainInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->sub_plain_inplace((*a)[i], (*b)[i]);
    }
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_Multiply(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_Multiply" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->multiply((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_MultiplyInplace(Evaluator *evaluator, CiphertextList *a, CiphertextList *b) {
    // std::cout << "Evaluator_MultiplyInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->multiply_inplace((*a)[i], (*b)[i]);
    }
}

// We assume that a->size() == b->size()
CiphertextList *Evaluator_MultiplyPlain(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_MultiplyPlain" << std::endl;
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->multiply_plain((*a)[i], (*b)[i], (*c)[i]);
    }
    return c;

}

// we assume that a->size() == b->size()
void Evaluator_MultiplyPlainInplace(Evaluator *evaluator, CiphertextList *a, PlaintextList *b) {
    // std::cout << "Evaluator_MultiplyPlainInplace" << std::endl;
    auto size = a->size();
    for (int i = 0; i < size; ++i) {
        evaluator->multiply_plain_inplace((*a)[i], (*b)[i]);
    }
}

CiphertextList *Evaluator_Relinearize(Evaluator *evaluator, RelinKeys *relin_keys, CiphertextList *ciphertext) {
    // std::cout << "Evaluator_Relinearize" << std::endl;
    auto size = ciphertext->size();
    auto outputs = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        evaluator->relinearize((*ciphertext)[i], *relin_keys, (*outputs)[i]);
    }
    return outputs;
}

void Evaluator_RelinearizeInplace(Evaluator *evaluator,  RelinKeys *relin_keys, CiphertextList *ciphertext) {
    // std::cout << "Evaluator_RelinearizeInplace" << std::endl;
    auto size = ciphertext->size();
    for (int i = 0; i < size; ++i) {
        evaluator->relinearize_inplace((*ciphertext)[i], *relin_keys);
    }
}

void Evaluator_RescaleToNextInplace(Evaluator *evaluator, CiphertextList *ciphertext) {
    // std::cout << "Evaluator_RescaleToNextInplace" << std::endl;
    auto size = ciphertext->size();
    for (int i = 0; i < size; ++i) {
        evaluator->rescale_to_next_inplace((*ciphertext)[i]);
    }
}

// ========================================================================= //
// ================================ Delete ================================= //
// ========================================================================= //

void CKKSEncoder_Delete(CKKSEncoder *encoder) {
    // std::cout << "CKKSEncoder_Delete" << std::endl;
    delete encoder;
}

void KeyGenerator_Delete(KeyGenerator *keygen) {
    // std::cout << "KeyGenerator_Delete" << std::endl;
    delete keygen;
}

void Encryptor_Delete(Encryptor *encryptor) {
    // std::cout << "Encryptor_Delete" << std::endl;
    delete encryptor;
}

void Decryptor_Delete(Decryptor *decryptor) {
    // std::cout << "Decryptor_Delete" << std::endl;
    delete decryptor;
}

void PlaintextList_Delete(PlaintextList *inputs) {
    // std::cout << "PlaintextList_Delete" << std::endl;
    delete inputs;
}

void CiphertextList_Delete(CiphertextList *inputs) {
    // std::cout << "CiphertextList_Delete" << std::endl;
    delete inputs;
}

//

void Evaluator_ModSwitchToInplace(Evaluator *evaluator, CiphertextList *destination, CiphertextList *source) {
    auto size = destination->size();
    for (int i = 0; i < size; ++i) {
        evaluator->mod_switch_to_inplace((*destination)[i], (*source)[i].parms_id());
    }
}

void Evaluator_ModSwitchToPlainInplace(Evaluator *evaluator, PlaintextList *destination, CiphertextList *source) {
    auto size = destination->size();
    for (int i = 0; i < size; ++i) {
        evaluator->mod_switch_to_inplace((*destination)[i], (*source)[i].parms_id());
    }
}

void CiphertextList_SetScale(CiphertextList *ciphertext, double scale) {
    auto size = ciphertext->size();
    for (int i = 0; i < size; ++i) {
        (*ciphertext)[i].scale() = scale;
    }
}

CiphertextList *CiphertextList_Clone(CiphertextList *ciphertext) {
    auto size = ciphertext->size();
    CiphertextList *ouputs = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        (*ouputs)[i] = (*ciphertext)[i];
    }
    return ouputs;
}

double CiphertextList_Scale(CiphertextList *ciphertext, size_t index) {
    return (*ciphertext)[index].scale();
}

std::stringstream *CiphertextList_Serialize(CiphertextList *ciphertext) {
    auto stream = new std::stringstream();
    *stream << ciphertext->size();
    for (const auto &v : *ciphertext) {
        v.save(*stream);
    }
    return stream;
}

CiphertextList *CiphertextList_Deserialize(SEALContext *context, std::stringstream *stream) {
    size_t size;
    *stream >> size;
    auto ciphertext = new CiphertextList(size);
    for (auto &v : *ciphertext) {
        v.load(*context, *stream);
    }
    return ciphertext;
}

void SEALContext_PrintParms(SEALContext *context, CiphertextList *ciphertext) {
    auto size = ciphertext->size();
    std::cout << "Parameters are: " << std::endl;
    for (int i = 0; i < size; ++i) {
        std::cout << "    " << context->get_context_data((*ciphertext)[i].parms_id())->chain_index() << std::endl;
    }
}

// std::stringstream

std::stringstream *StringStream_New() {
    return new std::stringstream();
}

void StringStream_Delete(std::stringstream *stream) {
    delete stream;
}

size_t StringStream_Tellg(std::stringstream *stream) {
    return stream->tellg();
}

size_t StringStream_Tellp(std::stringstream *stream) {
    return stream->tellp();
}

void StringStream_Write(std::stringstream *stream, char *buffer, int size) {
    stream->write(buffer, size);
}

void StringStream_Read(std::stringstream *stream, char *buffer, int size) {
    stream->read(buffer, size);
}

// Serialize/Deserialize Keys

SecretKey *SecretKey_New() {
    return new SecretKey();
}

void SecretKey_Delete(SecretKey *secret_key) {
    delete secret_key;
}
void SecretKey_Serialize(SecretKey *secret_key, std::stringstream *stream) {
    secret_key->save(*stream);
}

void SecretKey_Deserialize(SecretKey *secret_key, SEALContext *context, std::stringstream *stream) {
    secret_key->load(*context, *stream);
}

PublicKey *PublicKey_New() {
    return new PublicKey();
}

void PublicKey_Delete(PublicKey *public_key) {
    delete public_key;
}
void PublicKey_Serialize(PublicKey *public_key, std::stringstream *stream) {
    public_key->save(*stream);
}

void PublicKey_Deserialize(PublicKey *public_key, SEALContext *context, std::stringstream *stream) {
    public_key->load(*context, *stream);
}

RelinKeys *RelinKeys_New() {
    return new RelinKeys();
}

void RelinKeys_Delete(RelinKeys *relin_keys) {
    delete relin_keys;
}
void RelinKeys_Serialize(RelinKeys *relin_keys, std::stringstream *stream) {
    relin_keys->save(*stream);
}

void RelinKeys_Deserialize(RelinKeys *relin_keys, SEALContext *context, std::stringstream *stream) {
    relin_keys->load(*context, *stream);
}

GaloisKeys *GaloisKeys_New() {
    return new GaloisKeys();
}

void GaloisKeys_Delete(GaloisKeys *gal_keys) {
    delete gal_keys;
}
void GaloisKeys_Serialize(GaloisKeys *gal_keys, std::stringstream *stream) {
    gal_keys->save(*stream);
}

void GaloisKeys_Deserialize(GaloisKeys *gal_keys, SEALContext *context, std::stringstream *stream) {
    gal_keys->load(*context, *stream);
}

Ciphertext *DotProduct(Evaluator *evaluator, RelinKeys *relin_keys, GaloisKeys *gal_keys, Ciphertext *a, Ciphertext *b) {
    auto c = new Ciphertext();

    evaluator->multiply(*a, *b, *c);

    evaluator->relinearize_inplace(*c, *relin_keys);

    Ciphertext rotated;
    for (int i = 0; i < kPolyModulusDegreePower; i++) {
        evaluator->rotate_vector(*c, pow(2, i), *gal_keys, rotated);
        evaluator->add_inplace(*c, rotated);
    }

    return c;
}

void DotProduct_(Evaluator *evaluator, RelinKeys *relin_keys, GaloisKeys *gal_keys, Ciphertext *a, Ciphertext *b, Ciphertext *c) {

    evaluator->multiply(*a, *b, *c);

    evaluator->relinearize_inplace(*c, *relin_keys);

    Ciphertext rotated;
    for (int i = 0; i < kPolyModulusDegreePower; i++) {
        evaluator->rotate_vector(*c, pow(2, i), *gal_keys, rotated);
        evaluator->add_inplace(*c, rotated);
    }

}

CiphertextList *Evaluator_DotProduct(Evaluator *evaluator, RelinKeys *relin_keys, GaloisKeys *gal_keys, CiphertextList *a, CiphertextList *b) {
    auto size = a->size();
    auto c = new CiphertextList(size);
    for (int i = 0; i < size; ++i) {
        DotProduct_(evaluator, relin_keys, gal_keys, &(*a)[i], &(*b)[i], &(*c)[i]);
    }
    return c;

}


} // extern "C"