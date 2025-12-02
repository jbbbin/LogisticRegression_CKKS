#include "LS_Train_CKKS.h" 

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <cmath> // ceil, log2 사용을 위해 필요 (표준 C++)
#include <chrono> // Enc time / Learn time 측정을 위한 chrono
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace std::chrono; // high_resolution_clock, duration_cast 사용

// [데이터 로딩] Edinburgh 데이터셋 (정규화 X, 패딩 O)
void load_data(const string& filename, vector<vector<double>>& X, vector<double>& y) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("파일을 열 수 없습니다: " + filename);
    }

    string line;
    getline(file, line); // 헤더 무시

    while (getline(file, line)) {
        stringstream ss(line);
        string value;

        // 한 줄 전체를 먼저 숫자 벡터로 읽는다.
        vector<double> row_values;
        while (getline(ss, value, ',')) {
            if (!value.empty())
                row_values.push_back(stod(value));
        }
        if (row_values.empty()) continue;

        // y값 처리  (Edinburgh.txt에서는 마지막 컬럼이 y)
        double y_raw = row_values.back();
        row_values.pop_back(); // 나머지는 X로 사용
        if (y_raw == 0.0) y.push_back(-1.0);
        else              y.push_back(1.0);

        // X값 처리
        vector<double> row;
        
        // 1. Bias 항 추가 (맨 앞)
        row.push_back(1.0);

        // 2. Feature 추가 (마지막 y를 뺀 나머지 값들)
        row.insert(row.end(), row_values.begin(), row_values.end());

        // 3. 패딩 (2의 거듭제곱으로) - 속도 최적화용
        size_t current_size = row.size();
        size_t power_of_two_size = 1;
        while (power_of_two_size < current_size) {
            power_of_two_size <<= 1;
        }

        if (current_size < power_of_two_size) {
            row.resize(power_of_two_size, 0.0);
        }

        X.push_back(row);
    }
    file.close();
}

Ciphertext logistic_train(SEALContext& context, CKKSEncoder& encoder,Evaluator& evaluator,Encryptor& encryptor,Decryptor& decryptor,RelinKeys& relin_keys,GaloisKeys& gal_keys, double scale)
{
    size_t slot_count = encoder.slot_count();

    vector<vector<double>> all_X; // 데이터셋 전체의 특징(features)
    vector<double> all_y; 	      // 데이터셋 전체의 결과 레이블

    load_data("Edinburgh.txt", all_X, all_y);

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

    // ?? Enc time 측정 시작: Z, beta 인코딩 + 암호화 구간
    auto enc_start = high_resolution_clock::now();

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

    auto enc_end = high_resolution_clock::now();
    auto enc_duration = duration_cast<milliseconds>(enc_end - enc_start);
    double enc_seconds = enc_duration.count() / 1000.0;
    cout << "\n======================================" << endl;
    cout << "[Enc time] " << enc_seconds << " s" << endl;
    cout << "======================================" << endl;

    Ciphertext ct_v;
    ct_v = ct_beta;

    Ciphertext ct_beta_next, ct_v_next;

    int max_iter = 7;

    // ?? Learn time 측정 시작: HE 기반 학습 루프 전체
    auto learn_start = high_resolution_clock::now();

    for (int iter = 0; iter < max_iter; ++iter)
    {
        cout << "\n=== Iteration " << (iter + 1) << " ===" << endl;
        
        Ciphertext ct_beta_prev = ct_beta;

        // ★ 매 iteration마다 Z는 원본에서 복사해서 사용
        Ciphertext ct_Z_iter = ct_Z;
        
        if (ct_Z_iter.parms_id() != ct_v.parms_id()) {
            // ct_Z가 더 높은 레벨(Chain Index가 큼)일 것이므로 ct_v에 맞춤
            evaluator.mod_switch_to_inplace(ct_Z_iter, ct_v.parms_id());
        }
        // Scale 미세 오차로 인한 에러 방지용 수동 조정은 제거
        // ct_Z_iter.scale() = ct_v.scale();
        
        //논문에서 말한 step1과정
        cout << "Step 1..." << flush;
        Ciphertext ct1;
        evaluator.multiply(ct_v, ct_Z_iter, ct1);
        evaluator.relinearize_inplace(ct1, relin_keys);
        evaluator.rescale_to_next_inplace(ct1);
        cout << " OK" << endl;

        //step2 slotwise 덧셈과 rotate를 통해 내적값 구하기
        cout << "Step 2..." << flush;
        for (int j = 0; j < static_cast<int>(ceil(log2(num_features))); ++j) {
            int shift = (1 << j);
            Ciphertext rotated;
            evaluator.rotate_vector(ct1, shift, gal_keys, rotated);
            evaluator.add_inplace(ct1, rotated);
        }
        Ciphertext ct2 = ct1;
        cout << " OK" << endl;

        //step3 masking하는거
        cout << "Step 3..." << flush;
        vector<double> mask_firstcol(num_samples * num_features, 0.0);
        for (size_t i = 0; i < num_samples; ++i) {
            mask_firstcol[i * num_features] = 1.0;
        }

        Plaintext plain_mask;
        encoder.encode(mask_firstcol, scale, plain_mask);
        
        if (plain_mask.parms_id() != ct2.parms_id())
            evaluator.mod_switch_to_inplace(plain_mask, ct2.parms_id());

        Ciphertext ct3;
        evaluator.multiply_plain(ct2, plain_mask, ct3);
        evaluator.rescale_to_next_inplace(ct3);
        cout << " OK" << endl;

        //step4 Replicate
        cout << "Step 4..." << flush;
        int i = 1;
        while (i < num_features) {
            Ciphertext rotated;
            evaluator.rotate_vector(ct3, -static_cast<int>(i), gal_keys, rotated);
            evaluator.add_inplace(ct3, rotated);
            i <<= 1;
        }
        cout << " OK" << endl;

        // step5 근사 sigmoid 함수 (5차 근사)
        cout << "Step 5..." << flush;
        Ciphertext enc_dot = ct3;   
        
        // 1. x^2 계산
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        // 2. x^4 계산
        Ciphertext enc_dot_q4;
        evaluator.square(enc_dot_sq, enc_dot_q4);
        evaluator.relinearize_inplace(enc_dot_q4, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_q4);

        // 3. 5차항 (Term 5): -1.3511295 * (x/8)^5
        // 계수 로딩 (scale은 현재 enc_dot에 맞춤)
        double coef5 = -1.3511295 / 32768.0;
        Plaintext plain_coef5;
        encoder.encode(coef5, scale, plain_coef5);
        if (plain_coef5.parms_id() != enc_dot.parms_id()) 
            evaluator.mod_switch_to_inplace(plain_coef5, enc_dot.parms_id());

        Ciphertext term5_part;
        evaluator.multiply_plain(enc_dot, plain_coef5, term5_part);
        evaluator.rescale_to_next_inplace(term5_part);

        // [수정] q4(레벨 낮음, depth 2) vs term5_part(레벨 높음, depth 1)
        // 높은 레벨을 낮은 레벨로 내려야 합니다.
        if (term5_part.parms_id() != enc_dot_q4.parms_id()) {
            // term5_part를 enc_dot_q4의 레벨로 다운
            evaluator.mod_switch_to_inplace(term5_part, enc_dot_q4.parms_id());
        }
        term5_part.scale() = enc_dot_q4.scale(); // scale 강제 일치

        Ciphertext term5;
        evaluator.multiply(term5_part, enc_dot_q4, term5);
        evaluator.relinearize_inplace(term5, relin_keys);
        evaluator.rescale_to_next_inplace(term5);

        // 4. 3차항 (Term 3): 2.3533056 * (x/8)^3
        double coef3 = 2.3533056 / 512.0;
        Plaintext plain_coef3;
        encoder.encode(coef3, scale, plain_coef3);
        if (plain_coef3.parms_id() != enc_dot.parms_id())
            evaluator.mod_switch_to_inplace(plain_coef3, enc_dot.parms_id());

        Ciphertext term3_part;
        evaluator.multiply_plain(enc_dot, plain_coef3, term3_part);
        evaluator.rescale_to_next_inplace(term3_part);

        // [수정] x^2(레벨 낮음, depth 1보다 조금 더 진행됨) vs term3_part(x, 레벨 높음)
        // 보통 square와 mult_plain 후 rescale을 1회씩 했다면 레벨은 같을 수 있으나
        // 안전하게 확인 후 높은 쪽을 내립니다.
        if (term3_part.parms_id() != enc_dot_sq.parms_id()) {
            evaluator.mod_switch_to_inplace(term3_part, enc_dot_sq.parms_id());
        }
        term3_part.scale() = enc_dot_sq.scale();

        Ciphertext term3;
        evaluator.multiply(term3_part, enc_dot_sq, term3);
        evaluator.relinearize_inplace(term3, relin_keys);
        evaluator.rescale_to_next_inplace(term3);

        // 5. 1차항 (Term 1): -1.53048 * (x/8)
        double coef1 = -1.53048 / 8.0;
        Plaintext plain_coef1;
        encoder.encode(coef1, scale, plain_coef1);
        if (plain_coef1.parms_id() != enc_dot.parms_id())
            evaluator.mod_switch_to_inplace(plain_coef1, enc_dot.parms_id());

        Ciphertext term1;
        evaluator.multiply_plain(enc_dot, plain_coef1, term1);
        evaluator.rescale_to_next_inplace(term1);

        // 6. 전체 합산 (Term 5, Term 3, Term 1 더하기)
        // 가장 많이 연산된 Term 5가 레벨이 제일 낮습니다. 나머지를 Term 5에 맞춥니다.
        
        // Term 3 -> Term 5
        if (term3.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(term3, term5.parms_id());
        term3.scale() = term5.scale(); 

        // Term 1 -> Term 5
        if (term1.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(term1, term5.parms_id());
        term1.scale() = term5.scale();

        Plaintext plain_const;
        encoder.encode(0.5, scale, plain_const);
        if (plain_const.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(plain_const, term5.parms_id());
        plain_const.scale() = term5.scale(); 

        Ciphertext sigmoid_enc;
        evaluator.add(term5, term3, sigmoid_enc);
        evaluator.add_inplace(sigmoid_enc, term1);
        evaluator.add_plain_inplace(sigmoid_enc, plain_const);
        
        Ciphertext ct5 = sigmoid_enc;
        cout << " OK" << endl;

        //step 6
        cout << "Step 6..." << flush;
        if (ct_Z_iter.parms_id() != ct5.parms_id())
            evaluator.mod_switch_to_inplace(ct_Z_iter, ct5.parms_id());
        ct_Z_iter.scale() = ct5.scale();

        Ciphertext ct6;
        evaluator.multiply(ct5, ct_Z_iter, ct6);
        evaluator.relinearize_inplace(ct6, relin_keys);
        evaluator.rescale_to_next_inplace(ct6);
        cout << " OK" << endl;

        //step 7
        cout << "Step 7..." << flush;
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
        cout << " OK" << endl;

        //step 8
        cout << "Step 8..." << flush;
        double alpha_t = 10.0 / static_cast<double>(iter + 1); // 논문과 동일한 α_t
        double learn_rate = alpha_t / static_cast<double>(num_samples);

        Plaintext pt_lr;
        encoder.encode(learn_rate, scale, pt_lr);
        if (pt_lr.parms_id() != ct7.parms_id())
            evaluator.mod_switch_to_inplace(pt_lr, ct7.parms_id());

        Ciphertext ct8;
        evaluator.multiply_plain(ct7, pt_lr, ct8);
        evaluator.rescale_to_next_inplace(ct8);

        if (ct_v.parms_id() != ct8.parms_id())
            evaluator.mod_switch_to_inplace(ct_v, ct8.parms_id());

        ct_v.scale() = ct8.scale();
        
        evaluator.sub(ct_v, ct8, ct_beta_next);
        //evaluator.add(ct_v, ct8, ct_beta_next);
        cout << " OK" << endl;

        //Step 9
        cout << "Step 9..." << flush;
        double gamma_t = 0.9;
        
        parms_id_type target_parms = ct_beta_next.parms_id();

        if (ct_beta_prev.parms_id() != target_parms)
            evaluator.mod_switch_to_inplace(ct_beta_prev, target_parms);
        ct_beta_prev.scale() = ct_beta_next.scale();

        Plaintext plain_gamma, plain_one_minus_gamma;
        encoder.encode(gamma_t, scale, plain_gamma);
        encoder.encode(1.0 - gamma_t, scale, plain_one_minus_gamma);

        evaluator.mod_switch_to_inplace(plain_gamma, target_parms);
        evaluator.mod_switch_to_inplace(plain_one_minus_gamma, target_parms);

        Ciphertext term_old_beta;
        evaluator.multiply_plain(ct_beta_prev, plain_gamma, term_old_beta);
        evaluator.rescale_to_next_inplace(term_old_beta);

        Ciphertext term_new_beta;
        evaluator.multiply_plain(ct_beta_next, plain_one_minus_gamma, term_new_beta);
        evaluator.rescale_to_next_inplace(term_new_beta);

        if (term_old_beta.parms_id() != term_new_beta.parms_id())
            evaluator.mod_switch_to_inplace(term_old_beta, term_new_beta.parms_id());
        term_old_beta.scale() = term_new_beta.scale();

        evaluator.add(term_old_beta, term_new_beta, ct_v_next);
        cout << " OK" << endl;

        ct_beta = ct_beta_next;
        ct_v = ct_v_next;
        
        cout << "Iteration " << (iter + 1) << " completed!" << endl;
    }

    auto learn_end = high_resolution_clock::now();
    auto learn_duration = duration_cast<milliseconds>(learn_end - learn_start);
    double learn_seconds = learn_duration.count() / 1000.0;
    int learn_minutes = static_cast<int>(learn_seconds / 60.0);
    double learn_remain = learn_seconds - learn_minutes * 60.0;

    cout << "\n======================================" << endl;
    cout << "[Learn time] " << learn_minutes << "m " << learn_remain << "s" << endl;
    cout << "======================================\n" << endl;

    return ct_beta_next;
}
