#include "phantom.h"

#include <vector>
#include <algorithm>

using namespace std;
using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;

template<typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3) {
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size) {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++) {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++) {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size) {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++) {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

extern "C" {

EncryptionParameters *EncryptionParameters_CKKSCreate(size_t poly_modulus_degree, const int *bit_sizes, size_t length) {
    EncryptionParameters *params =  new EncryptionParameters(scheme_type::ckks);
    params->set_poly_modulus_degree(poly_modulus_degree);
    params->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, vector<int>(bit_sizes, bit_sizes + length)));
    return params;
}

void EncryptionParameters_Delete(EncryptionParameters *params) {
    delete params;
}


PhantomContext *Context_New(EncryptionParameters *params) {
    return new PhantomContext(*params);
}

void Context_Delete(PhantomContext *ctx) {
    delete ctx;
}

PhantomCKKSEncoder *CKKSEncoder_New(PhantomContext *ctx) {
    return new PhantomCKKSEncoder(*ctx);
}

void CKKSEncoder_Delete(PhantomCKKSEncoder *encoder) {
    delete encoder;
}

PhantomSecretKey *SecretKey_Create(PhantomContext *ctx) {
    auto secret_key = new PhantomSecretKey(*ctx);
    return secret_key;
}

PhantomPublicKey *PublicKey_Create(PhantomContext *ctx, PhantomSecretKey *secret_key) {
    return secret_key->gen_publickey(ctx);
}

PhantomRelinKey *RelinKey_Create(PhantomContext *ctx, PhantomSecretKey *secret_key) {
    return secret_key->gen_relinkey(ctx);
}

PhantomGaloisKey *GaloisKey_Create(PhantomContext *ctx, PhantomSecretKey *secret_key) {
    return secret_key->create_galois_keys(ctx);
}

void SecretKey_Delete(PhantomSecretKey *secret_key) {
    delete secret_key;
}


void PublicKey_Delete(PhantomPublicKey *public_key) {
    delete public_key;
}


void RelinKey_Delete(PhantomRelinKey *relin_key) {
    delete relin_key;
}

void GaloisKey_Delete(PhantomGaloisKey *galois_key) {
    delete galois_key;
}

PhantomPlaintext *Plaintext_New() {
    return new PhantomPlaintext();
}

PhantomCiphertext *Ciphertext_New() {
    return new PhantomCiphertext();
}

void Plaintext_Delete(PhantomPlaintext *plaintext) {
    delete plaintext;
}


void Ciphertext_Delete(PhantomCiphertext *ciphertext) {
    delete ciphertext;
}


void CKKSEncoder_Encode(PhantomCKKSEncoder *encoder, PhantomContext *ctx, double *inputs, size_t size, double scale, PhantomPlaintext *plaintext) {
    auto slot_count = encoder->slot_count();
    vector<double> vec(size, 0);
    vec.assign(inputs, inputs + min(slot_count, size));
    vec.resize(slot_count);
    fill(vec.begin() + min(slot_count, size), vec.end(), 0);
    encoder->encode(*ctx, vec, scale, *plaintext);
}

void CKKSEncoder_Decode(PhantomCKKSEncoder *encoder, PhantomContext *ctx, PhantomPlaintext *plaintext, double *outputs, size_t size) {
    auto slot_count = encoder->slot_count();
    vector<double> vec;
    encoder->decode(*ctx, *plaintext, vec);
    copy(vec.begin(), vec.begin() + min(slot_count, size), outputs);
}

void SecretKey_EncryptSymmetric(PhantomSecretKey *secret_key, PhantomContext *ctx, PhantomPlaintext *plaintext, PhantomCiphertext *ciphertext) {
    secret_key->encrypt_symmetric(*ctx, *plaintext, *ciphertext);
}

void PublicKey_EncryptAsymmetric(PhantomPublicKey *public_key, PhantomContext *ctx, PhantomPlaintext *plaintext, PhantomCiphertext *ciphertext) {
    public_key->encrypt_asymmetric(*ctx, *plaintext, *ciphertext);
}

void SecretKey_Decrypt(PhantomSecretKey *secret_key, PhantomContext *ctx, PhantomCiphertext *ciphertext, PhantomPlaintext *plaintext) {
    secret_key->decrypt(*ctx, *ciphertext, *plaintext);
}

void Dot_Product(PhantomContext *ctx, PhantomCiphertext *src1, PhantomCiphertext *src2, PhantomCiphertext *dst, PhantomRelinKey *relin_keys, PhantomGaloisKey *galois_keys) {
    *dst = *src1;
    multiply_inplace(*ctx, *dst, *src2);

    relinearize_inplace(*ctx, *dst, *relin_keys);

    PhantomCiphertext r;
    for (int i = 0; i < 12; i++) {
        r = *dst;
        rotate_vector_inplace(*ctx, r, pow(2, i), *galois_keys);
        add_inplace(*ctx, *dst, r);
    }

}

} // extern "C"