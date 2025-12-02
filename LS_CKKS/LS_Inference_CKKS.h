#pragma once
#include "seal/seal.h"

using namespace seal;

void run_inference(SEALContext& context,
    CKKSEncoder& encoder,
    Evaluator& evaluator,
    Encryptor& encryptor,
    Decryptor& decryptor,
    RelinKeys& relin_keys,
    GaloisKeys& gal_keys,
    Ciphertext& trained_beta,
    double scale);
