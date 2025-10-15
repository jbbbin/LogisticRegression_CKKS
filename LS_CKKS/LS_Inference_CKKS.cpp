#include "LS_Inference_CKKS.h" 

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void run_inference()
{

    //임의로 정의한 가중치 벡터 beta값들
    vector<double> beta_vec = { 0.15, -0.8, 0.5, -0.2, 1.1, -0.7, 0.3, -1.2, 0.9, -0.4, 1.3, -0.6, 0.7, -1.0, 0.4, 0.9, -1.3, 0.6, 1.0 };

    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

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

    string user_input_line;
    getline(cin, user_input_line);

    vector<double> x_vec;
    stringstream ss(user_input_line);
    string value;

    // bias 항에 해당하는 1.0을 맨 앞에 추가 (기존 로직 유지)
    x_vec.push_back(1.0);
    while (getline(ss, value, ',')) {
        x_vec.push_back(stod(value));
    }

    size_t slot_count = encoder.slot_count();
    vector<double> x_padded(slot_count, 0.0), beta_padded(slot_count, 0.0);
    for (size_t i = 0; i < x_vec.size(); ++i) x_padded[i] = x_vec[i];
    for (size_t i = 0; i < beta_vec.size(); ++i) beta_padded[i] = beta_vec[i];


    //sigmoid함수 다항근사  -> 여기에서는 g3(x) = 0.5 - 1.22096 * (x/8) +0.81562*(x/8)^3 을 사용함
     // 모든 샘플에 대해 추론을 반복합니다.
    for (size_t sample_idx = 0; sample_idx < 10; ++sample_idx)
    {
        cout << "\n=======================================================" << endl;
        cout << sample_idx << "번째 Sample Inference" << endl;

        //사용자로부터 입력받은 x_vec과 beta_vec을 CKKS에 인코딩,암호화
        Plaintext plain_x, plain_beta;

        size_t slot_count = encoder.slot_count();
        vector<double> x_padded(slot_count, 0.0), beta_padded(slot_count, 0.0);
        for (size_t i = 0; i < x_vec.size(); ++i) x_padded[i] = x_vec[i];
        for (size_t i = 0; i < beta_vec.size(); ++i) beta_padded[i] = beta_vec[i];

        encoder.encode(x_padded, scale, plain_x);
        encoder.encode(beta_padded, scale, plain_beta);

        Ciphertext ct_x, ct_beta;
        encryptor.encrypt(plain_x, ct_x);
        encryptor.encrypt(plain_beta, ct_beta);

        //암호문 상태에서 내적이 필요하므로 element-wise 곱을 진행
        Ciphertext ct_mul;
        evaluator.multiply(ct_x, ct_beta, ct_mul);
        evaluator.relinearize_inplace(ct_mul, relin_keys);
        evaluator.rescale_to_next_inplace(ct_mul);

        //rotate를 이용해 덧셈 진행
        Ciphertext enc_dot = ct_mul;

        //내적
        size_t vec_size = x_vec.size();
        parms_id_type parms = enc_dot.parms_id();

        if (vec_size > 1) {
            for (size_t i = 1; i < vec_size; i <<= 1) { //shift연산을 통해 논문 내용과 같이 log배 만큼으로 복잡도 감소시킴
                Ciphertext rotated;
                evaluator.rotate_vector(enc_dot, i, gal_keys, rotated);
                evaluator.add_inplace(enc_dot, rotated);
            }
        }

        //x^3을 계산하기 위해 x^2을 먼저 계산
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        //x^3을 구하기 위한 2번째 과정 (0.81562/8) * x
        double coef3 = 0.81562 / 512.0;
        Plaintext plain_coef3;
        encoder.encode(coef3, scale, plain_coef3);
        //곱셈 전에 평문의 레벨을 암호문에 맞춰줍니다
        evaluator.mod_switch_to_inplace(plain_coef3, enc_dot.parms_id());

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
        evaluator.mod_switch_to_inplace(plain_coef1, enc_dot.parms_id());

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

    }
}
