#include "LS_CKKS.h"
#include "LS_Inference_CKKS.h"
#include "LS_Train_CKKS.h"
#include "seal/seal.h"

#include <iostream>

using namespace std;
using namespace seal;
using namespace std::chrono;

int main()
{
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 65536;
    params.set_poly_modulus_degree(poly_modulus_degree);
    std::vector<int> modulus_bits = { 60 };
    for(int i=0; i<60; ++i)
        modulus_bits.push_back(50); // 중간을 40으로
    
    modulus_bits.push_back(60);

    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_bits));
    
    double scale = pow(2.0, 50);

    SEALContext context(params, true, sec_level_type::none);
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

    // ⬇️ Enc time / Learn time 측정은 logistic_train 내부에서 각각 출력한다.
    Ciphertext trained_beta = logistic_train(context, encoder, evaluator, encryptor, decryptor, relin_keys, gal_keys, scale);
    
    run_inference(context, encoder, evaluator, encryptor, decryptor, relin_keys, gal_keys, trained_beta, scale);

    return 0;
}
