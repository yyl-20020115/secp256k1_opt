cmake_minimum_required(VERSION 3.24)
PROJECT(secp256k1_opt)

set(SRC_FILES field.cpp group.cpp ecmult.cpp ecdsa.cpp tests.cpp)

set(USE_OPENSSL 1)
if(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    add_executable(${PROJECT_NAME}_openssl ${SRC_FILES} num_openssl.h num_openssl.cpp)
    target_compile_definitions(${PROJECT_NAME}_openssl PRIVATE -DUSE_NUM_OPENSSL)
    target_include_directories(${PROJECT_NAME}_openssl PRIVATE . ${OPENSSL_INCLUDE_DIR})
    target_link_directories(${PROJECT_NAME}_openssl PRIVATE . ${OPENSSL_LINK_DIR})
    target_link_libraries(${PROJECT_NAME}_openssl PRIVATE ${OPENSSL_LIBRARIES})
else()
    find_package(GMP REQUIRED)
    add_executable(${PROJECT_NAME}_gmp ${SRC_FILES} num_gmp.h num_gmp.cpp)
    target_compile_definitions(${PROJECT_NAME}_gmp PRIVATE -DUSE_NUM_GMP)
    target_include_directories(${PROJECT_NAME}_gmp PRIVATE .)
    target_link_libraries(${PROJECT_NAME}_gmp PRIVATE ${GMP_LIBRARIES})
endif()




