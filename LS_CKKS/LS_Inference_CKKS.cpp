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

    //���Ƿ� ������ ����ġ ���� beta����
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

    //Public,Secret, RelinKeys, GaloisKeys �� �ʿ��� Ű ����

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    string user_input_line;
    getline(cin, user_input_line);

    vector<double> x_vec;
    stringstream ss(user_input_line);
    string value;

    // bias �׿� �ش��ϴ� 1.0�� �� �տ� �߰� (���� ���� ����)
    x_vec.push_back(1.0);
    while (getline(ss, value, ',')) {
        x_vec.push_back(stod(value));
    }

    size_t slot_count = encoder.slot_count();
    vector<double> x_padded(slot_count, 0.0), beta_padded(slot_count, 0.0);
    for (size_t i = 0; i < x_vec.size(); ++i) x_padded[i] = x_vec[i];
    for (size_t i = 0; i < beta_vec.size(); ++i) beta_padded[i] = beta_vec[i];


    //sigmoid�Լ� ���ױٻ�  -> ���⿡���� g3(x) = 0.5 - 1.22096 * (x/8) +0.81562*(x/8)^3 �� �����
     // ��� ���ÿ� ���� �߷��� �ݺ��մϴ�.
    for (size_t sample_idx = 0; sample_idx < 10; ++sample_idx)
    {
        cout << "\n=======================================================" << endl;
        cout << sample_idx << "��° Sample Inference" << endl;

        //����ڷκ��� �Է¹��� x_vec�� beta_vec�� CKKS�� ���ڵ�,��ȣȭ
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

        //��ȣ�� ���¿��� ������ �ʿ��ϹǷ� element-wise ���� ����
        Ciphertext ct_mul;
        evaluator.multiply(ct_x, ct_beta, ct_mul);
        evaluator.relinearize_inplace(ct_mul, relin_keys);
        evaluator.rescale_to_next_inplace(ct_mul);

        //rotate�� �̿��� ���� ����
        Ciphertext enc_dot = ct_mul;

        //����
        size_t vec_size = x_vec.size();
        parms_id_type parms = enc_dot.parms_id();

        if (vec_size > 1) {
            for (size_t i = 1; i < vec_size; i <<= 1) { //shift������ ���� �� ����� ���� log�� ��ŭ���� ���⵵ ���ҽ�Ŵ
                Ciphertext rotated;
                evaluator.rotate_vector(enc_dot, i, gal_keys, rotated);
                evaluator.add_inplace(enc_dot, rotated);
            }
        }

        //x^3�� ����ϱ� ���� x^2�� ���� ���
        Ciphertext enc_dot_sq;
        evaluator.square(enc_dot, enc_dot_sq);
        evaluator.relinearize_inplace(enc_dot_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_dot_sq);

        //x^3�� ���ϱ� ���� 2��° ���� (0.81562/8) * x
        double coef3 = 0.81562 / 512.0;
        Plaintext plain_coef3;
        encoder.encode(coef3, scale, plain_coef3);
        //���� ���� ���� ������ ��ȣ���� �����ݴϴ�
        evaluator.mod_switch_to_inplace(plain_coef3, enc_dot.parms_id());

        Ciphertext enc_dot_coef3;
        evaluator.multiply_plain(enc_dot, plain_coef3, enc_dot_coef3);
        evaluator.rescale_to_next_inplace(enc_dot_coef3);

        // (0.81562/8) * x^3 ���ϴ� ����(�ռ� ���ص� �� ���� ���ϴ� ����)
        Ciphertext term3;
        evaluator.multiply(enc_dot_sq, enc_dot_coef3, term3);
        evaluator.relinearize_inplace(term3, relin_keys);
        evaluator.rescale_to_next_inplace(term3);

        //1���� ��� (-1.20096/8) * x
        double coef1 = -1.20096 / 8.0;
        Plaintext plain_coef1;
        encoder.encode(coef1, scale, plain_coef1);
        evaluator.mod_switch_to_inplace(plain_coef1, enc_dot.parms_id());

        Ciphertext term1;
        evaluator.multiply_plain(enc_dot, plain_coef1, term1);
        evaluator.rescale_to_next_inplace(term1);

        //����� encoding
        Plaintext plain_const;
        encoder.encode(0.5, scale, plain_const);

        //term1�� ������ 2�̰� term3�� ������ 1�̾ scale ���߱Ⱑ �ʿ���
        term1.scale() = pow(2.0, 40);
        term3.scale() = pow(2.0, 40);

        //������ �ϱ� ���� parms_id ���߱�
        parms_id_type last_parms_id = term3.parms_id();
        evaluator.mod_switch_to_inplace(term1, last_parms_id);
        evaluator.mod_switch_to_inplace(plain_const, last_parms_id);

        //��ݱ��� �غ��� term1 term3 plain_const�� ��ġ�� ����-->�������
        Ciphertext sigmoid_enc;
        evaluator.add(term1, term3, sigmoid_enc);
        evaluator.add_plain_inplace(sigmoid_enc, plain_const);

        //��ȣȭ �� ���ڵ�
        Plaintext sigmoid_plain;
        decryptor.decrypt(sigmoid_enc, sigmoid_plain); //��ȣȭ �� ������ sigmoid_plain�� ����

        vector<double> sigmoid_result;
        encoder.decode(sigmoid_plain, sigmoid_result);

        // ��ȣȭ�� �� ���
        cout << "��ȣ�� ��ȣȭ Sigmoid �ٻ� ��� : " << sigmoid_result[0] << endl;

    }
}
