#include <iostream>
#include <vector>

#include "example.h"
#include "phantom.h"
#include "util.cuh"

using namespace std;
using namespace phantom;
using namespace phantom::arith;
using namespace phantom::util;

void example_dot_product() {
    cout << "Example: Dot Product" << endl;
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    PhantomContext context(parms);
    PhantomSecretKey secret_key(context);
    PhantomGaloisKey galois_keys = secret_key.create_galois_keys(context);
    PhantomRelinKey relin_keys = secret_key.gen_relinkey(context);



    PhantomCKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    double scale = pow(2.0, 40);

    // vector<cuDoubleComplex> v1, v2;

    // v1.push_back(make_cuDoubleComplex(1, 0));
    // v1.push_back(make_cuDoubleComplex(2, 0));
    // v1.push_back(make_cuDoubleComplex(3, 0));
    // v1.push_back(make_cuDoubleComplex(4, 0));

    // v2.push_back(make_cuDoubleComplex(5, 0));
    // v2.push_back(make_cuDoubleComplex(6, 0));
    // v2.push_back(make_cuDoubleComplex(7, 0));
    // v2.push_back(make_cuDoubleComplex(8, 0));

    // for (int i = 5; i <= slot_count; i++) {
    //     v1.push_back(make_cuDoubleComplex(0, 0));
    //     v2.push_back(make_cuDoubleComplex(0, 0));
    // }

    vector<double> v1, v2;

    v1.push_back(1);
    v1.push_back(2);
    v1.push_back(3);
    v1.push_back(4);

    v2.push_back(5);
    v2.push_back(6);
    v2.push_back(7);
    v2.push_back(8);

    for (int i = 5; i <= slot_count; i++) {
        v1.push_back(0);
        v2.push_back(0);
    }
    

    PhantomPlaintext p1, p2;
    encoder.encode(context, v1, scale, p1);
    encoder.encode(context, v2, scale, p2);

    PhantomCiphertext c1, c2;
    secret_key.encrypt_symmetric(context, p1, c1);
    secret_key.encrypt_symmetric(context, p2, c2);


    PhantomCiphertext c = c1;
    multiply_inplace(context, c, c2);

    relinearize_inplace(context, c, relin_keys);

    PhantomCiphertext r;
    for (int i = 0; i < 12; i++) {
        r = c;
        rotate_vector_inplace(context, r, pow(2, i), galois_keys);
        add_inplace(context, c, r);
    }

    PhantomPlaintext p;
    secret_key.decrypt(context, c, p);

    vector<double> v;
    encoder.decode(context, p, v);

    print_vector(v1, 3, 7);
    print_vector(v2, 3, 7);
    print_vector(v, 3, 7);

    // vector<double> v3(5, 0);
    // print_vector(v3, 3, 7);

}