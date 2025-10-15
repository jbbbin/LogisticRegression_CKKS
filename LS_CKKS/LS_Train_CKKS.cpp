#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void load_data(const string& filename,vector<vector<double>>& X, vector<double>& y) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("파일을 열 수 없습니다: " + filename);
    }

    string line;
    // 헤더(첫 번째 줄)는 읽고 무시
    getline(file, line);

    while (getline(file, line)) {
        stringstream ss(line);
        string value;

        // 첫 번째 값은 y (종속 변수, Cancer_status)
        getline(ss, value, ',');
        double y_val = stod(value);
        if (y_val == 0) {
            y.push_back(-1.0);
        }
        else {
            y.push_back(1.0);
        }

        // 나머지 값들은 X (독립 변수, features)
        vector<double> row;
        // bias 항과 곱해질 해당하는 1.0을 맨 앞에 추가
        row.push_back(1.0);
        while (getline(ss, value, ',')) {
            row.push_back(stod(value));
        }
        X.push_back(row);
    }
    file.close();
}

int logistic_train()
{
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 32768;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 60 }));
    double scale = pow(2.0, 40);

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
    size_t slot_count = encoder.slot_count();

    vector<vector<double>> all_X; // 데이터셋 전체의 특징(features)
    vector<double> all_y;         // 데이터셋 전체의 결과 레이블

    try {
        load_data("C:/Users/82108/OneDrive/바탕 화면/4-2학기/연구실인턴십/LS_CKKS/LS_CKKS/LBW.txt", all_X, all_y);
        cout << "Txt파일에 총 " << all_X.size() << "개의 샘플이 존재합니다" << endl;
    }
    catch (const exception& e) {
        cerr << "오류 발생: " << e.what() << endl;
        return 1;
    }

    size_t num_samples = all_X.size();
    size_t num_features = all_X[0].size(); // bias 포함

    // z = y*x 데이터셋 생성
    // all_X를 복사하고, 각 행에 해당하는 y값을 곱해줌(y값은 1 or -1).
    vector<vector<double>> all_Z = all_X;
    for (size_t i = 0; i < num_samples; ++i) {
        double y_val = all_y[i]; // y는 이미 {-1, 1} 상태

        for (size_t j = 0; j < num_features; ++j) {
            all_Z[i][j] *= y_val; // all_X의 각 원소에 y값을 곱해 Z를 완성
        }
    }

    //전체 데이터셋 Z를 행 우선 순서(row-order)
    vector<double> Z_row_order;
    Z_row_order.reserve(num_samples * num_features); //메모리 공간 미리 확보
    for (const auto& row : all_Z) {
        Z_row_order.insert(Z_row_order.end(), row.begin(), row.end());
    }

    //평탄화된 Z 벡터를 인코딩하고 암호화
    Plaintext plain_Z;
    encoder.encode(Z_row_order, scale, plain_Z);
    Ciphertext ct_Z;
    encryptor.encrypt(plain_Z, ct_Z);

    vector<double> beta_vec(num_features, 0.01); //논문에 초기 값을 random으로 잡는다고 되어있기에

}

int main() {
    logistic_train();
}