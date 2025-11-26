#include "LS_CKKS.h"
#include "LS_Inference_CKKS.h"
#include "LS_Train_CKKS.h"
#include "seal/seal.h"

#include <iostream>

using namespace std;
using namespace seal;

int main()
{
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 65536;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 60 }));
    double scale = pow(2.0, 30);

    SEALContext context(params);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    Ciphertext trained_beta = logistic_train(context, encoder, evaluator, encryptor, decryptor, relin_keys, gal_keys, scale);
    
    logistic_train();
    run_inference();

    return 0;
}