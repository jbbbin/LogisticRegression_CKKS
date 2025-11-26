#include "LS_Train_CKKS.h" 

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

Ciphertext logistic_train(SEALContext& context, CKKSEncoder& encoder,Evaluator& evaluator,Encryptor& encryptor,Decryptor& decryptor,RelinKeys& relin_keys,GaloisKeys& gal_keys, double scale)
{
    size_t slot_count = encoder.slot_count();

    vector<vector<double>> all_X; // 데이터셋 전체의 특징(features)
    vector<double> all_y;         // 데이터셋 전체의 결과 레이블

    load_data("LBW.txt", all_X, all_y);

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
    

    // beta_vec의 내용을 n번 만큼 beta_matrix_row_order에 이어 붙인다. row_order로 
    vector<double> beta_matrix_row_order;
    beta_matrix_row_order.reserve(num_samples * num_features);
    for (size_t i = 0; i < num_samples; ++i) {
        beta_matrix_row_order.insert(beta_matrix_row_order.end(), beta_vec.begin(), beta_vec.end());
    }

    Plaintext plain_beta;
    encoder.encode(beta_matrix_row_order, scale, plain_beta);
    Ciphertext ct_beta;
    encryptor.encrypt(plain_beta, ct_beta);

    Ciphertext ct_v;
    ct_v = ct_beta;

    Ciphertext ct_beta_next, ct_v_next;

    int max_iter = 7;
    for (int iter = 0; iter < max_iter; ++iter)
    {
        Ciphertext ct_beta_prev = ct_beta;
        //논문에서 말한 step1과정
        Ciphertext ct1;
        evaluator.multiply(ct_v, ct_Z, ct1);
        evaluator.relinearize_inplace(ct1, relin_keys);
        evaluator.rescale_to_next_inplace(ct1);

        //step2 slotwise 덧셈과 rotate를 통해 내적값 구하기
        int i = 1;
        while (i < num_features) {
            Ciphertext rotated;
            evaluator.rotate_vector(ct1, static_cast<int>(i), gal_keys, rotated);
            evaluator.add_inplace(ct1, rotated);
            i <<= 1;
        }
        Ciphertext ct2 = ct1;


        //step3 masking하는거
        vector<double> mask_firstcol(num_samples * num_features, 0.0);
        for (size_t i = 0; i < num_samples; ++i) {
            mask_firstcol[i * num_features] = 1.0; // 각 행의 첫 열만 1
        }

        Plaintext plain_mask;
        encoder.encode(mask_firstcol, scale, plain_mask);
        if (plain_mask.parms_id() != ct2.parms_id()) {
            evaluator.mod_switch_to_inplace(plain_mask, ct2.parms_id());
        }

        Ciphertext ct3;
        evaluator.multiply_plain(ct2, plain_mask, ct3);
        evaluator.rescale_to_next_inplace(ct3);

        //step4 Replicate
        i = 1;
        while (i < num_features) {
            Ciphertext rotated;
            evaluator.rotate_vector(ct3, -static_cast<int>(i), gal_keys, rotated); //내적할때랑 반대방향(오른쪽으로) rotate를 해준 후 더해줘야함
            evaluator.add_inplace(ct3, rotated);
            i <<= 1;
        }

        //step5 근사 sigmoid함수에 값 대입. g(x) = 0.5 - 1.20096*(x/8) + 0.81562*(x/8)^3
        Ciphertext enc_dot = ct3;   // inference 코드와 동일하게
        Ciphertext ct5;

        // x^2
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        // (0.81562/512) * x
        double coef3 = 0.81562 / 512.0;                 // 0.81562*(x/8)^3 == (0.81562/512)*x^3
        Plaintext plain_coef3;
        encoder.encode(coef3, enc_dot.scale(), plain_coef3);
        evaluator.mod_switch_to_inplace(plain_coef3, enc_dot.parms_id());

        Ciphertext enc_dot_coef3;
        evaluator.multiply_plain(enc_dot, plain_coef3, enc_dot_coef3);
        evaluator.rescale_to_next_inplace(enc_dot_coef3);

        // term3 = (0.81562/512)*x^3 = enc_dot_sq * enc_dot_coef3
        if (enc_dot_sq.parms_id() != enc_dot_coef3.parms_id())
            evaluator.mod_switch_to_inplace(enc_dot_sq, enc_dot_coef3.parms_id());
        Ciphertext term3;
        evaluator.multiply(enc_dot_sq, enc_dot_coef3, term3);
        evaluator.relinearize_inplace(term3, relin_keys);
        evaluator.rescale_to_next_inplace(term3);

        // term1 = (-1.20096/8)*x
        double coef1 = -1.20096 / 8.0;
        Plaintext plain_coef1;
        encoder.encode(coef1, enc_dot.scale(), plain_coef1);
        evaluator.mod_switch_to_inplace(plain_coef1, enc_dot.parms_id());

        Ciphertext term1;
        evaluator.multiply_plain(enc_dot, plain_coef1, term1);
        evaluator.rescale_to_next_inplace(term1);

        // 상수항 0.5 (term들과 scale/level 맞추기)
        Plaintext plain_const;
        encoder.encode(0.5, term3.scale(), plain_const);
        evaluator.mod_switch_to_inplace(plain_const, term3.parms_id());

        // 스케일/레벨 정렬 후 합치기
        if (term1.parms_id() != term3.parms_id())
            evaluator.mod_switch_to_inplace(term1, term3.parms_id());
        term1.scale() = term3.scale();// (스케일 근사치 맞춤)

        Ciphertext sigmoid_enc;
        evaluator.add(term1, term3, sigmoid_enc);      // term1 + term3
        evaluator.add_plain_inplace(sigmoid_enc, plain_const); // + 0.5

        ct5 = sigmoid_enc;// 최종 g(z_i^T beta)

        //step 6  step5값이랑 ct_Z 내적
        if (ct_Z.parms_id() != ct5.parms_id())
            evaluator.mod_switch_to_inplace(ct_Z, ct5.parms_id());

        Ciphertext ct6;
        evaluator.multiply(ct5, ct_Z, ct6);
        evaluator.relinearize_inplace(ct6, relin_keys);
        evaluator.rescale_to_next_inplace(ct6);

        //step 7 행 합산
        size_t N = num_samples;
        size_t total = N * num_features;

        i = num_features;
        while (i < total) {
            Ciphertext rotated;
            evaluator.rotate_vector(ct6, i, gal_keys, rotated);
            evaluator.add_inplace(ct6, rotated);
            i <<= 1;
        }
        Ciphertext ct7 = ct6;

        //step 8 beta업데이트
        double alpha_t = 10;
        double learn_rate = alpha_t / static_cast<double>(num_samples); // alpha/n

        // (α/n) 평문 준비: ct7와 scale/level 맞추기
        Plaintext pt_lr;
        encoder.encode(learn_rate, ct7.scale(), pt_lr);
        if (pt_lr.parms_id() != ct7.parms_id())
            evaluator.mod_switch_to_inplace(pt_lr, ct7.parms_id()); //scale level 맞추기

        //ct8 = (alpha/n) * ct7
        Ciphertext ct8;
        evaluator.multiply_plain(ct7, pt_lr, ct8);
        evaluator.rescale_to_next_inplace(ct8);

        // ct8 수준에 맞춰 ct_beta를 scale과 parms_id 내려줌
        if (ct_v.parms_id() != ct8.parms_id())
            evaluator.mod_switch_to_inplace(ct_v, ct8.parms_id());

        if (ct_v.scale() != ct8.scale())
            ct_v.scale() = ct8.scale();

        //beta를 새로운 beta로 업데이트
        evaluator.add(ct_v, ct8, ct_beta_next);

        //Step 9 Nasterov 방식 적용
        // v^{(t+1)} = (1 - γ_t) * β^{(t+1)} + γ_t * β^{(t)}
        double gamma_t = 0.9; //논문처럼 0 < γ_t < 1, 보통 0.9 근처를 사용

        // (1 - γ_t), γ_t 를 평문으로 인코딩
        Plaintext plain_gamma, plain_one_minus_gamma;
        encoder.encode(gamma_t, ct_beta_next.scale(), plain_gamma);
        encoder.encode(1.0 - gamma_t, ct_beta_next.scale(), plain_one_minus_gamma);

        // parms_id 맞추기
        if (plain_gamma.parms_id() != ct_beta_next.parms_id())
            evaluator.mod_switch_to_inplace(plain_gamma, ct_beta_next.parms_id());
        if (plain_one_minus_gamma.parms_id() != ct_beta_next.parms_id())
            evaluator.mod_switch_to_inplace(plain_one_minus_gamma, ct_beta_next.parms_id());

        // γ_t * β^{(t)}   → term_old_beta
        Ciphertext term_old_beta;
        evaluator.multiply_plain(ct_beta_prev, plain_gamma, term_old_beta);
        evaluator.rescale_to_next_inplace(term_old_beta);

        // (1 - γ_t) * β^{(t+1)} → term_new_beta
        Ciphertext term_new_beta;
        evaluator.multiply_plain(ct_beta_next, plain_one_minus_gamma, term_new_beta);
        evaluator.rescale_to_next_inplace(term_new_beta);

        // level / scale 정렬
        if (term_old_beta.parms_id() != term_new_beta.parms_id())
            evaluator.mod_switch_to_inplace(term_old_beta, term_new_beta.parms_id());
        term_old_beta.scale() = term_new_beta.scale();

        // v^{(t+1)} = term_old_beta + term_new_beta
        evaluator.add(term_old_beta, term_new_beta, ct_v_next);

        // 다음 iter을 위해 현재 β, v 업데이트
        ct_beta = ct_beta_next;   // β^{(t)} ← β^{(t+1)}
        ct_v = ct_v_next;      // v^{(t)} ← v^{(t+1)}
    }



    return ct_beta_next;
}