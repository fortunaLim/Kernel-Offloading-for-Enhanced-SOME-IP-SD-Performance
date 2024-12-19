# CMake 최소 버전 요구사항 지정
cmake_minimum_required(VERSION 3.0)

# 프로젝트 이름 설정
project(vsomeip_test)

# C++ 표준 버전 설정 (C++11 사용)
set(CMAKE_CXX_STANDARD 11)

# 필요한 라이브러리 찾기
find_package(vsomeip3 REQUIRED)      # vsomeip 라이브러리
find_package(Threads REQUIRED)       # 스레드 라이브러리

# 서버 실행 파일 생성 설정
add_executable(server TestServer.cpp)                    # server 실행 파일 생성
target_link_libraries(server vsomeip3 Threads::Threads)  # 필요한 라이브러리 링크

# 클라이언트 실행 파일 생성 설정
add_executable(client TestClient.cpp)                    # client 실행 파일 생성
target_link_libraries(client vsomeip3 Threads::Threads)  # 필요한 라이브러리 링크
