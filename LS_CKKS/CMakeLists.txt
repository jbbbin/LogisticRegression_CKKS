# 1. CMake 최소 버전 필수 지정
cmake_minimum_required(VERSION 3.10)

# 2. 프로젝트 이름 정의
project(LogisticRegression_CKKS)

# 3. C++ 표준 설정 (C++17 사용)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 4. SEAL 라이브러리 찾기
# 윈도우 경로(C:/...)를 지우고, 시스템이나 지정된 경로에서 찾도록 변경
find_package(SEAL REQUIRED)

# 5. 실행 파일 생성
# 주의: 파일 이름 사이의 쉼표(,)를 모두 제거하고 공백으로 구분했습니다.
add_executable(LS_CKKS 
    LS_CKKS.cpp 
    LS_CKKS.h 
    LS_Train_CKKS.cpp 
    LS_Inference_CKKS.cpp 
    LS_Inference_CKKS.h 
    LS_Train_ckks.h 
    LS_Train_Diag_CKKS.cpp
)

# 6. SEAL 라이브러리 연결
target_link_libraries(LS_CKKS SEAL::seal)

# 7. (선택사항) 디버그 레벨 설정은 리눅스에서 굳이 필요 없으므로 제거하거나 주석 처리
# 리눅스 GCC는 기본적으로 /MDd 옵션을 쓰지 않음.