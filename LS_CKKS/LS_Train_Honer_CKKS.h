#pragma once
#include "seal/seal.h"

using namespace seal;

Ciphertext logistic_train_honer(SEALContext& context,
    CKKSEncoder& encoder,
    Evaluator& evaluator,
    Encryptor& encryptor,
    Decryptor& decryptor,
    RelinKeys& relin_keys,
    GaloisKeys& gal_keys,
    double scale);