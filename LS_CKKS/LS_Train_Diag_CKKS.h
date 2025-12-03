#ifndef LS_TRAIN_DIAG_CKKS_H
#define LS_TRAIN_DIAG_CKKS_H

#include <vector>
#include <string>
#include "seal/seal.h"

void load_data_raw(const std::string& filename, std::vector<std::vector<double>>& X, std::vector<double>& y);

std::vector<std::vector<double>> extract_diagonals(const std::vector<std::vector<double>>& X, size_t num_features);

seal::Ciphertext logistic_train_diag(
    seal::SEALContext& context, 
    seal::CKKSEncoder& encoder, 
    seal::Evaluator& evaluator, 
    seal::Encryptor& encryptor, 
    seal::Decryptor& decryptor, 
    seal::RelinKeys& relin_keys, 
    seal::GaloisKeys& gal_keys, 
    double scale
);

#endif // LS_TRAIN_DIAG_CKKS_H