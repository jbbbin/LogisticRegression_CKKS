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
        throw runtime_error("������ �� �� �����ϴ�: " + filename);
    }

    string line;
    // ���(ù ��° ��)�� �а� ����
    getline(file, line);

    while (getline(file, line)) {
        stringstream ss(line);
        string value;

        // ù ��° ���� y (���� ����, Cancer_status)
        getline(ss, value, ',');
        double y_val = stod(value);
        if (y_val == 0) {
            y.push_back(-1.0);
        }
        else {
            y.push_back(1.0);
        }

        // ������ ������ X (���� ����, features)
        vector<double> row;
        // bias �װ� ������ �ش��ϴ� 1.0�� �� �տ� �߰�
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

    vector<vector<double>> all_X; // �����ͼ� ��ü�� Ư¡(features)
    vector<double> all_y;         // �����ͼ� ��ü�� ��� ���̺�

    try {
        load_data("C:/Users/82108/OneDrive/���� ȭ��/4-2�б�/���������Ͻ�/LS_CKKS/LS_CKKS/LBW.txt", all_X, all_y);
        cout << "Txt���Ͽ� �� " << all_X.size() << "���� ������ �����մϴ�" << endl;
    }
    catch (const exception& e) {
        cerr << "���� �߻�: " << e.what() << endl;
        return 1;
    }

    size_t num_samples = all_X.size();
    size_t num_features = all_X[0].size(); // bias ����

    // z = y*x �����ͼ� ����
    // all_X�� �����ϰ�, �� �࿡ �ش��ϴ� y���� ������(y���� 1 or -1).
    vector<vector<double>> all_Z = all_X;
    for (size_t i = 0; i < num_samples; ++i) {
        double y_val = all_y[i]; // y�� �̹� {-1, 1} ����

        for (size_t j = 0; j < num_features; ++j) {
            all_Z[i][j] *= y_val; // all_X�� �� ���ҿ� y���� ���� Z�� �ϼ�
        }
    }

    //��ü �����ͼ� Z�� �� �켱 ����(row-order)
    vector<double> Z_row_order;
    Z_row_order.reserve(num_samples * num_features); //�޸� ���� �̸� Ȯ��
    for (const auto& row : all_Z) {
        Z_row_order.insert(Z_row_order.end(), row.begin(), row.end());
    }

    //��źȭ�� Z ���͸� ���ڵ��ϰ� ��ȣȭ
    Plaintext plain_Z;
    encoder.encode(Z_row_order, scale, plain_Z);
    Ciphertext ct_Z;
    encryptor.encrypt(plain_Z, ct_Z);

    vector<double> beta_vec(num_features, 0.01); //���� �ʱ� ���� random���� ��´ٰ� �Ǿ��ֱ⿡

}

int main() {
    logistic_train();
}