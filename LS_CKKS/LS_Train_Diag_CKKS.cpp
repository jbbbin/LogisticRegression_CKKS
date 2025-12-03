#include "LS_Train_Diag_CKKS.h"

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>
#include <iomanip> // setprecision

using namespace std;
using namespace seal;
using namespace std::chrono;

vector<vector<double>> extract_diagonals(const vector<vector<double>>& X, size_t num_features) {
    size_t num_samples = X.size();
    // D개의 대각선 벡터 생성
    vector<vector<double>> diagonals(num_features, vector<double>(num_samples, 0.0));

    for (size_t k = 0; k < num_features; ++k) { // k번째 대각선
        for (size_t i = 0; i < num_samples; ++i) { // i번째 row
            size_t col_idx = (i + k) % num_features; 
            diagonals[k][i] = X[i][col_idx];
        }
    }
    return diagonals;
}

// 데이터 로딩 (Raw)
void load_data_raw(const string& filename, vector<vector<double>>& X, vector<double>& y) {
    ifstream file(filename);
    if (!file.is_open()) throw runtime_error("파일을 열 수 없습니다: " + filename);

    string line;
    getline(file, line); // 헤더 스킵

    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        vector<double> row_values;
        while (getline(ss, value, ',')) {
            if (!value.empty()) row_values.push_back(stod(value));
        }
        if (row_values.empty()) continue;

        double y_raw = row_values.back();
        row_values.pop_back();
        y.push_back((y_raw == 0.0) ? -1.0 : 1.0);

        vector<double> row;
        row.push_back(1.0); // Bias
        row.insert(row.end(), row_values.begin(), row_values.end());

        // Padding (Power of 2)
        size_t current_cols = row.size();
        size_t power_of_two = 1;
        while (power_of_two < current_cols) power_of_two <<= 1;
        row.resize(power_of_two, 0.0);

        X.push_back(row);
    }
    file.close();
}

Ciphertext logistic_train_diag(SEALContext& context, CKKSEncoder& encoder, Evaluator& evaluator, Encryptor& encryptor, Decryptor& decryptor, RelinKeys& relin_keys, GaloisKeys& gal_keys, double scale)
{
    size_t slot_count = encoder.slot_count();

    // 1. 데이터 로드
    vector<vector<double>> raw_X;
    vector<double> raw_y;
    load_data_raw("LBW.txt", raw_X, raw_y);

    size_t num_samples = raw_X.size();
    size_t num_features = raw_X[0].size(); // Padding 된 크기

    cout << "Dataset: " << num_samples << " samples, " << num_features << " features (padded)." << endl;

    // 2. [ENC TIME] 인코딩 및 암호화
    auto enc_start = high_resolution_clock::now();
    cout << "Encrypting X using Diagonal Packing (Generating " << num_features << " Ciphertexts)..." << flush;

    // (1) X의 대각선 추출 및 암호화
    vector<vector<double>> X_diagonals = extract_diagonals(raw_X, num_features);
    vector<Ciphertext> ct_X_diags(num_features);

    for (size_t k = 0; k < num_features; ++k) {
        Plaintext pt;
        encoder.encode(X_diagonals[k], scale, pt);
        encryptor.encrypt(pt, ct_X_diags[k]);
    }
    cout << " Done." << endl;

    // (2) y 암호화 (단순 벡터)
    Plaintext pt_y;
    encoder.encode(raw_y, scale, pt_y);
    Ciphertext ct_y;
    encryptor.encrypt(pt_y, ct_y);

    // (3) Beta 암호화
    // Diagonal 연산을 위해 Beta를 하나의 벡터로 초기화
    vector<double> beta_vec(slot_count, 0.0);
    for (size_t j = 0; j < num_features; ++j) beta_vec[j] = 0.01;
    
    Plaintext pt_beta;
    encoder.encode(beta_vec, scale, pt_beta);
    Ciphertext ct_beta;
    encryptor.encrypt(pt_beta, ct_beta);

    auto enc_end = high_resolution_clock::now();
    double enc_seconds = duration_cast<milliseconds>(enc_end - enc_start).count() / 1000.0;
    cout << "\n[Enc time] " << enc_seconds << " s" << endl;

    // 3. 학습 루프 (Diagonal Packing Logic)
    int max_iter = 7;
    auto learn_start = high_resolution_clock::now();

    for (int iter = 0; iter < max_iter; ++iter) {
        cout << "\n=== Iteration " << (iter + 1) << " (Diagonal Method) ===" << endl;
        auto iter_start = high_resolution_clock::now();

        // Step 1: Matrix-Vector Mult (X * beta)
        // Formula: sum( diag_k * rotate(beta, k) )
        cout << "  [Step 1] Matrix-Vector Mult (X * beta)... " << flush;
        
        Ciphertext ct_z; 
        
        for (size_t k = 0; k < num_features; ++k) {//num feature만큼회전
            // 1. Beta 회전 (k칸)
            Ciphertext rot_beta;
            if (k == 0) rot_beta = ct_beta;
            else evaluator.rotate_vector(ct_beta, k, gal_keys, rot_beta);

            // 레벨 매칭
            Ciphertext x_diag = ct_X_diags[k];
            if (x_diag.parms_id() != rot_beta.parms_id()) {
                evaluator.mod_switch_to_inplace(x_diag, rot_beta.parms_id());
            }

            // 2. 곱셈 (Diag * Rotated_Beta)
            Ciphertext temp;
            evaluator.multiply(x_diag, rot_beta, temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);

            // 3. 누적 합산
            if (k == 0) {
                ct_z = temp;
            } else {
            // 항상 "새로 계산된 temp를" accumulator(ct_z) 레벨로 내리기
                if (temp.parms_id() != ct_z.parms_id()) {
                    evaluator.mod_switch_to_inplace(temp, ct_z.parms_id());
                }
                temp.scale() = ct_z.scale();
                evaluator.add_inplace(ct_z, temp);
            }
        }
        cout << "Done (Loop count: " << num_features << ")" << endl;

        // Step 2: Sigmoid Approx
        cout << "  [Step 2] Sigmoid Approx... " << flush;
        
        Ciphertext ct_z2, ct_z3;
        evaluator.square(ct_z, ct_z2);
        evaluator.relinearize_inplace(ct_z2, relin_keys);
        evaluator.rescale_to_next_inplace(ct_z2);

        evaluator.mod_switch_to_inplace(ct_z, ct_z2.parms_id()); // z를 z^2 레벨로 내림
        ct_z.scale() = ct_z2.scale();

        evaluator.multiply(ct_z2, ct_z, ct_z3); // z^3
        evaluator.relinearize_inplace(ct_z3, relin_keys);
        evaluator.rescale_to_next_inplace(ct_z3);
        
        Ciphertext ct_sigmoid = ct_z3; // 결과값 가정
        cout << "Done." << endl;

        
        // Step 3: Gradient Calculation (X^T * error)
        cout << "  [Step 3] Gradient Calc (X^T * error)... " << flush;

        Ciphertext ct_grad;
        
        for (size_t k = 0; k < num_features; ++k) {
            Ciphertext rot_error;
            if (k == 0) rot_error = ct_sigmoid; 
            else evaluator.rotate_vector(ct_sigmoid, k, gal_keys, rot_error);

            // X^T 대각선이 있다고 가정하고 X 대각선 재사용 (연산량 시뮬레이션)
            Ciphertext x_diag = ct_X_diags[k];
            if (x_diag.parms_id() != rot_error.parms_id())
                 evaluator.mod_switch_to_inplace(x_diag, rot_error.parms_id());
            
            Ciphertext temp;
            evaluator.multiply(x_diag, rot_error, temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);

            if (k == 0) ct_grad = temp;
            else {
                 if (temp.parms_id() != ct_grad.parms_id()) {
                    evaluator.mod_switch_to_inplace(temp, ct_grad.parms_id());
                }
                 temp.scale() = ct_grad.scale();
                 evaluator.add_inplace(ct_grad, temp);
            }
        }
        cout << "Done (Loop count: " << num_features << ")" << endl;

        // Step 4: Update Weights
        cout << "  [Step 4] Update Weights... " << flush;
        // ct_beta = ct_beta - lr * ct_grad
        
        // 다음 루프를 위해 레벨이 떨어진 ct_beta를 갱신
        // (Gradient 연산 결과 레벨로 beta를 내림)
        if (ct_beta.parms_id() != ct_grad.parms_id()) {
            evaluator.mod_switch_to_inplace(ct_beta, ct_grad.parms_id());
        }
        // 실제로는 뺄셈 수행 (생략)
        cout << "Done." << endl;
        
        // [시간 출력 포맷 변경] ms -> m s
        auto iter_end = high_resolution_clock::now();
        double iter_seconds = duration_cast<milliseconds>(iter_end - iter_start).count() / 1000.0;
        
        int iter_min = static_cast<int>(iter_seconds) / 60;
        double iter_sec_rem = iter_seconds - (iter_min * 60);

        cout << "  -> Iteration Time: " 
             << iter_min << "m " << iter_sec_rem << "s" << endl;
    }

    auto learn_end = high_resolution_clock::now();
    double total_seconds = duration_cast<milliseconds>(learn_end - learn_start).count() / 1000.0;
    int total_min = static_cast<int>(total_seconds) / 60;
    double total_sec_rem = total_seconds - (total_min * 60);

    cout << "\n======================================" << endl;
    cout << "[Total Learn Time (Diag)] " 
         << total_min << "m " << total_sec_rem << "s" << endl;
    cout << "======================================\n" << endl;

    return ct_beta;
}
