#include "LS_CKKS.h" 

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// CSV 파일을 읽어 데이터(X)와 레이블(y)로 분리하는 함수
void load_data(const string& filename,
    vector<vector<double>>& X,
    vector<double>& y) {
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
        y.push_back(stod(value));

        // 나머지 값들은 X (독립 변수, features)
        vector<double> row;
        // bias 항에 해당하는 1.0을 맨 앞에 추가
        row.push_back(1.0);
        while (getline(ss, value, ',')) {
            row.push_back(stod(value));
        }
        X.push_back(row);
    }
    file.close();
}

int logistic_ckks_example()
{
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

    //추론에 사용할 입력 데이터 x
    vector<double> x_vec = all_X[0];

    //임의로 정의한 가중치 벡터 beta값들
    vector<double> beta_vec = { 0.15, -0.8, 0.5, -0.2, 1.1, -0.7, 0.3, -1.2, 0.9, -0.4, 1.3, -0.6, 0.7, -1.0, 0.4, 0.9, -1.3, 0.6, 1.0 };

    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192; 
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

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

    //Public,Secret, RelinKeys, GaloisKeys 등 필요한 키 생성

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    //sigmoid함수 다항근사  -> 여기에서는 g3(x) = 0.5 - 1.22096 * (x/8) +0.81562*(x/8)^3 을 사용함
     // 모든 샘플에 대해 추론을 반복합니다.
    for (size_t sample_idx = 0; sample_idx < all_X.size(); ++sample_idx)
    {
        vector<double> x_vec = all_X[sample_idx];
        double y_true = all_y[sample_idx]; // 실제 레이블

        cout << "\n=======================================================" << endl;
        cout << sample_idx << "번째 Sample Inference" << endl;

        //x_vec이랑 beta_vec내적
        double dot_plain = 0.0;
        for (size_t i = 0; i < x_vec.size(); i++) {
            dot_plain += x_vec[i] * beta_vec[i];
        }
        cout << "평문 내적 결과 : " << dot_plain << endl;

        //내적 값을 CKKS에 인코딩,암호화
        Plaintext plain_dot;
        encoder.encode(dot_plain, scale, plain_dot);
        Ciphertext enc_dot;
        encryptor.encrypt(plain_dot, enc_dot);

        //x^3을 계산하기 위해 x^2을 먼저 계산
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        //x^3을 구하기 위한 2번째 과정 (0.81562/8) * x
        double coef3 = 0.81562 / 512.0;
        Plaintext plain_coef3;
        encoder.encode(coef3, scale, plain_coef3);
        Ciphertext enc_dot_coef3;
        evaluator.multiply_plain(enc_dot, plain_coef3, enc_dot_coef3);
        evaluator.rescale_to_next_inplace(enc_dot_coef3);

        // (0.81562/8) * x^3 구하는 과정(앞서 구해둔 두 개를 곱하는 과정)
        Ciphertext term3;
        evaluator.multiply(enc_dot_sq, enc_dot_coef3, term3);
        evaluator.relinearize_inplace(term3, relin_keys);
        evaluator.rescale_to_next_inplace(term3);

        //1차항 계산 (-1.20096/8) * x
        double coef1 = -1.20096 / 8.0;
        Plaintext plain_coef1;
        encoder.encode(coef1, scale, plain_coef1);
        Ciphertext term1;
        evaluator.multiply_plain(enc_dot, plain_coef1, term1);
        evaluator.rescale_to_next_inplace(term1);

        //상수항 encoding
        Plaintext plain_const;
        encoder.encode(0.5, scale, plain_const);

        //term1의 레벨은 2이고 term3의 레벨은 1이어서 scale 맞추기가 필요함
        term1.scale() = pow(2.0, 40);
        term3.scale() = pow(2.0, 40);

        //덧셈을 하기 위해 parms_id 맞추기
        parms_id_type last_parms_id = term3.parms_id();
        evaluator.mod_switch_to_inplace(term1, last_parms_id);
        evaluator.mod_switch_to_inplace(plain_const, last_parms_id);

        //방금까지 준비한 term1 term3 plain_const를 합치는 과정-->최종결과
        Ciphertext sigmoid_enc;
        evaluator.add(term1, term3, sigmoid_enc);
        evaluator.add_plain_inplace(sigmoid_enc, plain_const);

        //복호화 및 디코딩
        Plaintext sigmoid_plain;
        decryptor.decrypt(sigmoid_enc, sigmoid_plain); //복호화 한 내용을 sigmoid_plain에 저장

        vector<double> sigmoid_result;
        encoder.decode(sigmoid_plain, sigmoid_result);

        // 복호화된 값 출력
        cout << "암호문 복호화 Sigmoid 근사 결과 : " << sigmoid_result[0] << endl;

        // 평문 sigmoid 근사 계산
        double plain_sigmoid = 0.5
            + (-1.22096 / 8.0) * dot_plain
            + (0.81562 / 512.0) * pow(dot_plain, 3);

        cout << "평문 Sigmoid 근사 결과 : " << plain_sigmoid << endl;
        cout << endl;

        int final_result = (sigmoid_result[0] >= 0.5) ? 1 : 0;
        string inference_label = (final_result == 1) ? "Positive(양성)입니다" : "Negative(음성)입니다";
        cout << "암호문 기반 최종 추론 결과 (0.5 기준): " << final_result << " (" << inference_label << ")" << endl;
    }
    return 0;
}


int main()
{
    logistic_ckks_example();

    return 0;
}