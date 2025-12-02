#include "LS_Encrypted_Inference_CKKS.h" 

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void run_encrypted_inference(SEALContext& context,CKKSEncoder& encoder,Evaluator& evaluator,Encryptor& encryptor,Decryptor& decryptor,RelinKeys& relin_keys,GaloisKeys& gal_keys, Ciphertext& trained_beta, double scale)
{
    string user_input_line;
    cout << "입력할 feature들을 ','로 구분해 입력하세요: ";
    getline(cin, user_input_line);

    vector<double> x_vec;
    stringstream ss(user_input_line);
    string value;

    // bias 항에 해당하는 1.0을 맨 앞에 추가
    x_vec.push_back(1.0);
    while (getline(ss, value, ',')) {
        x_vec.push_back(stod(value));
    }

    // Sigmoid 함수 5차 근사 사용 (Train과 통일)
    // g5(x) = 0.5 - 1.53048*(x/8) + 2.3533056*(x/8)^3 - 1.3511295*(x/8)^5

    // 모든 샘플에 대해 추론을 반복 (예제에서는 1회만 수행하거나 루프 유지)
    for (size_t sample_idx = 0; sample_idx < 1; ++sample_idx) // 테스트를 위해 1회로 조정하거나 필요시 늘리세요
    {
        cout << "\n=======================================================" << endl;
        cout << "Inference Start" << endl;

        // 사용자로부터 입력받은 x_vec을 CKKS에 인코딩, 암호화
        Plaintext plain_x;
        size_t slot_count = encoder.slot_count();
        vector<double> x_padded(slot_count, 0.0);
        for (size_t i = 0; i < x_vec.size(); ++i) x_padded[i] = x_vec[i];

        encoder.encode(x_padded, scale, plain_x);

        Ciphertext ct_x;
        encryptor.encrypt(plain_x, ct_x);

        // 1. 내적 (Dot Product)
        // Element-wise 곱
        Ciphertext ct_mul;
        evaluator.multiply(ct_x, trained_beta, ct_mul);
        evaluator.relinearize_inplace(ct_mul, relin_keys);
        evaluator.rescale_to_next_inplace(ct_mul);

        Ciphertext enc_dot = ct_mul;

        // Rotate & Add로 슬롯 합산
        size_t vec_size = x_vec.size();
        if (vec_size > 1) {
            // log2(vec_size) 만큼 반복하며 합산
            int i = 1;
            // vec_size보다 작은 2의 거듭제곱까지 커버하기 위해 넉넉히 루프를 돕니다.
            // (입력 사이즈가 크다면 ceil(log2(vec_size))만큼 수행해야 안전합니다)
            while(i < slot_count / 2 && i < vec_size * 2) { 
                Ciphertext rotated;
                evaluator.rotate_vector(enc_dot, i, gal_keys, rotated);
                evaluator.add_inplace(enc_dot, rotated);
                i <<= 1;
            }
        }
        // 이제 enc_dot의 모든 슬롯에는 내적 값(z)이 들어있습니다 (엄밀히는 첫 슬롯 등).

        // 2. Sigmoid 5차 근사 계산
        // ct5 계산 로직 (Train 코드와 동일한 구조 사용)

        // 2-1. x^2
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        // 2-2. x^4
        Ciphertext enc_dot_q4;
        evaluator.square(enc_dot_sq, enc_dot_q4);
        evaluator.relinearize_inplace(enc_dot_q4, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_q4);

        // 2-3. 5차항 (Term 5): -1.3511295 * (x/8)^5
        double coef5 = -1.3511295 / 32768.0;
        Plaintext plain_coef5;
        encoder.encode(coef5, enc_dot.scale(), plain_coef5);
        if (plain_coef5.parms_id() != enc_dot.parms_id()) 
            evaluator.mod_switch_to_inplace(plain_coef5, enc_dot.parms_id());

        Ciphertext term5_part;
        evaluator.multiply_plain(enc_dot, plain_coef5, term5_part);
        evaluator.rescale_to_next_inplace(term5_part);

        if (term5_part.parms_id() != enc_dot_q4.parms_id())
            evaluator.mod_switch_to_inplace(term5_part, enc_dot_q4.parms_id());
        
        Ciphertext term5;
        evaluator.multiply(term5_part, enc_dot_q4, term5);
        evaluator.relinearize_inplace(term5, relin_keys);
        evaluator.rescale_to_next_inplace(term5);

        // 2-4. 3차항 (Term 3): 2.3533056 * (x/8)^3
        double coef3 = 2.3533056 / 512.0;
        Plaintext plain_coef3;
        encoder.encode(coef3, enc_dot.scale(), plain_coef3);
        if (plain_coef3.parms_id() != enc_dot.parms_id())
            evaluator.mod_switch_to_inplace(plain_coef3, enc_dot.parms_id());

        Ciphertext term3_part;
        evaluator.multiply_plain(enc_dot, plain_coef3, term3_part);
        evaluator.rescale_to_next_inplace(term3_part);

        if (term3_part.parms_id() != enc_dot_sq.parms_id())
            evaluator.mod_switch_to_inplace(term3_part, enc_dot_sq.parms_id());

        Ciphertext term3;
        evaluator.multiply(term3_part, enc_dot_sq, term3);
        evaluator.relinearize_inplace(term3, relin_keys);
        evaluator.rescale_to_next_inplace(term3);

        // 2-5. 1차항 (Term 1): -1.53048 * (x/8)
        double coef1 = -1.53048 / 8.0;
        Plaintext plain_coef1;
        encoder.encode(coef1, enc_dot.scale(), plain_coef1);
        if (plain_coef1.parms_id() != enc_dot.parms_id())
            evaluator.mod_switch_to_inplace(plain_coef1, enc_dot.parms_id());

        Ciphertext term1;
        evaluator.multiply_plain(enc_dot, plain_coef1, term1);
        evaluator.rescale_to_next_inplace(term1);

        // 3. 전체 합산 및 레벨/스케일 조정
        // 가장 깊은 레벨인 term5에 맞춥니다.
        
        // Term 3 -> Term 5 레벨로
        if (term3.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(term3, term5.parms_id());
        term3.scale() = term5.scale();  // 스케일 강제 동기화 (CKKS 근사성 허용)

        // Term 1 -> Term 5 레벨로
        if (term1.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(term1, term5.parms_id());
        term1.scale() = term5.scale();

        // 상수항 0.5 준비
        Plaintext plain_const;
        encoder.encode(0.5, term5.scale(), plain_const);
        if (plain_const.parms_id() != term5.parms_id())
            evaluator.mod_switch_to_inplace(plain_const, term5.parms_id());

        Ciphertext sigmoid_enc;
        evaluator.add(term5, term3, sigmoid_enc);       // 5차항 + 3차항
        evaluator.add_inplace(sigmoid_enc, term1);      // + 1차항
        evaluator.add_plain_inplace(sigmoid_enc, plain_const); // + 0.5

        // 4. 복호화 및 결과 출력
        Plaintext sigmoid_plain;
        decryptor.decrypt(sigmoid_enc, sigmoid_plain);

        vector<double> sigmoid_result;
        encoder.decode(sigmoid_plain, sigmoid_result);

        cout << "암호문 복호화 Sigmoid(5차 근사) 결과 : " << sigmoid_result[0] << endl;
        
        // 확률값으로 해석 (0.5 기준)
        if (sigmoid_result[0] >= 0.5) cout << "예측: Cancer (1)" << endl;
        else cout << "예측: Normal (0)" << endl;
    }
}