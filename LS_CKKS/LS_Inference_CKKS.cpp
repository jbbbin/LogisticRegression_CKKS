#include "LS_Inference_CKKS.h" 

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <cmath>        // exp, pow 등
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Train에서 사용한 load_data 재사용 (정의는 LS_Train_CKKS.cpp 쪽에 있음)
void load_data_honer(const string& filename,
               vector<vector<double>>& X,
               vector<double>& y);

void run_inference(SEALContext& context,
                   CKKSEncoder& encoder,
                   Evaluator& evaluator,
                   Encryptor& encryptor,
                   Decryptor& decryptor,
                   RelinKeys& relin_keys,
                   GaloisKeys& gal_keys,
                   Ciphertext& trained_beta,
                   double scale)
{
    // 1) Train 때와 동일한 데이터셋 로드 (Edinburgh)
    vector<vector<double>> X;
    vector<double> y;
    load_data_honer("Edinburgh.txt", X, y);

    size_t num_samples  = X.size();
    if (num_samples == 0) {
        cout << "[Inference] 데이터가 비어 있습니다." << endl;
        return;
    }
    size_t num_features = X[0].size(); // bias + padding 포함

    cout << "\n=======================================================" << endl;
    cout << "[Inference] Evaluating accuracy on dataset (" 
         << num_samples << " samples)" << endl;

    // 2) 학습된 beta 암호문을 복호화해서 평문 beta 벡터로 추출
    Plaintext plain_beta;
    decryptor.decrypt(trained_beta, plain_beta);

    vector<double> beta_decoded;
    encoder.decode(plain_beta, beta_decoded);

    if (beta_decoded.size() < num_features) {
        cout << "[Inference] 디코드된 beta 크기가 예상보다 작습니다. "
             << "beta_decoded.size() = " << beta_decoded.size()
             << ", num_features = " << num_features << endl;
        return;
    }

    // logistic_train에서 beta를 row-order로
    // [β0 ... β_{d-1} | β0 ... β_{d-1} | ...] 형태로 채웠으므로
    // 첫 num_features 개만 실제 β로 사용
    vector<double> beta_vec(beta_decoded.begin(),
                            beta_decoded.begin() + num_features);

    // 3) 전체 샘플에 대해 평문 inference 수행
    //    g5(x) = 0.5 - 1.53048*(x/8) + 2.3533056*(x/8)^3 - 1.3511295*(x/8)^5
    int correct = 0;

    for (size_t i = 0; i < num_samples; ++i)
    {
        const vector<double>& x = X[i];

        // z = β^T x
        double z = 0.0;
        for (size_t j = 0; j < num_features; ++j) {
            z += beta_vec[j] * x[j];
        }

        // 5차 sigmoid 근사 (Train 때와 동일한 다항식 사용)
        double t  = z / 8.0;
        double t2 = t * t;
        double t3 = t2 * t;
        double t5 = t3 * t2;

        double prob = 0.5
                    - 1.53048   * t
                    + 2.3533056 * t3
                    - 1.3511295 * t5;

        // y는 {-1, +1} 형태이므로, 0.5 기준으로 예측 레이블을 {-1,+1}로 매핑
        int pred_label = (prob >= 0.5) ? 1 : -1;

        if (pred_label == static_cast<int>(y[i])) {
            ++correct;
        }
    }

    double acc = static_cast<double>(correct) / static_cast<double>(num_samples);

    cout << "Correct: " << correct << " / " << num_samples << endl;
    cout << "Accuracy (plain inference using HE-trained model + 5th-order sigmoid): "
         << acc * 100.0 << " %" << endl;
    cout << "=======================================================\n";
}