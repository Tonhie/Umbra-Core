cmake_minimum_required(VERSION 3.23)

project(Umbra-Core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(UMBRA_THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/local")

add_library(umbra_crypto
    src/crypto/rsa_engine.cpp
    src/crypto/elgamal_engine.cpp
    src/crypto/crypto_engine.cpp
)

target_include_directories(umbra_crypto
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${UMBRA_THIRD_PARTY_DIR}/include"
)

target_link_libraries(umbra_crypto
    PUBLIC
        umbra_hash
        "${UMBRA_THIRD_PARTY_DIR}/lib/libntl.a"
        "${UMBRA_THIRD_PARTY_DIR}/lib/libgmpxx.a"
        "${UMBRA_THIRD_PARTY_DIR}/lib/libgmp.a"
)

add_library(umbra_hash
    src/hash/sha_256.cpp
)

target_include_directories(umbra_hash
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
# Certificate
add_library(umbra_certificate
    src/certificate/certificate.cpp
    src/certificate/trusted_authority.cpp
    src/certificate/certificate_authority.cpp
    src/certificate/certificate_library.cpp
    src/pki/pki_user.cpp
)

target_include_directories(umbra_certificate
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(umbra_certificate
    PUBLIC
        umbra_crypto
)

# Secure Mail
add_library(umbra_mail
    src/mail/secure_mail.cpp
)

target_include_directories(umbra_mail
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(umbra_mail
    PUBLIC
        umbra_certificate
)

# Test
enable_testing()

# RSA-Engine
add_executable(umbra_crypto_rsa_engine_test
    tests/crypto/rsa_engine_test.cpp
)

target_link_libraries(umbra_crypto_rsa_engine_test
    PRIVATE
        umbra_crypto
)

target_compile_definitions(umbra_crypto_rsa_engine_test
    PRIVATE
        UMBRA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
        UMBRA_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
)

add_test(NAME crypto.rsa_engine COMMAND umbra_crypto_rsa_engine_test)

# SHA-256 TEST

add_executable(umbra_hash_sha_256_test
    tests/hash/sha_256_test.cpp
)

target_link_libraries(umbra_hash_sha_256_test
    PRIVATE
        umbra_hash
)

add_test(NAME hash.sha_256 COMMAND umbra_hash_sha_256_test)

# Elgamal Engine

add_executable(umbra_crypto_elgamal_engine_test
    tests/crypto/elgamal_engine_test.cpp
)

target_link_libraries(umbra_crypto_elgamal_engine_test
    PRIVATE
        umbra_crypto
)

target_compile_definitions(umbra_crypto_elgamal_engine_test
    PRIVATE
        UMBRA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
        UMBRA_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
)

add_test(NAME crypto.elgamal_engine COMMAND umbra_crypto_elgamal_engine_test)

# Certificate Test

add_executable(umbra_certificate_test
    tests/certificate/certificate_test.cpp
)

target_link_libraries(umbra_certificate_test
    PRIVATE umbra_certificate
)

add_test(NAME certificate.certificate COMMAND umbra_certificate_test)

# Trusted Authority Test

add_executable(umbra_trusted_authority_test
    tests/certificate/trusted_authority_test.cpp
)

target_link_libraries(umbra_trusted_authority_test
    PRIVATE umbra_certificate
)

add_test(NAME certificate.trusted_authority COMMAND umbra_trusted_authority_test)

# Certificate Authority Test

add_executable(umbra_certificate_authority_test
    tests/certificate/certificate_authority_test.cpp
)

target_link_libraries(umbra_certificate_authority_test
    PRIVATE umbra_certificate
)

add_test(NAME certificate.certificate_authority COMMAND umbra_certificate_authority_test)

# Certificate Library Test

add_executable(umbra_certificate_library_test
    tests/certificate/certificate_library_test.cpp
)

target_link_libraries(umbra_certificate_library_test
    PRIVATE umbra_certificate
)

add_test(NAME certificate.certificate_library COMMAND umbra_certificate_library_test)

# Pki User Test

add_executable(umbra_pki_user_test
    tests/pki/pki_user_test.cpp
)

target_link_libraries(umbra_pki_user_test
    PRIVATE umbra_certificate
)

add_test(NAME pki.pki_user COMMAND umbra_pki_user_test)

# Secure Mail Test

add_executable(umbra_secure_mail_test
    tests/mail/secure_mail_test.cpp
)

target_link_libraries(umbra_secure_mail_test
    PRIVATE umbra_mail
)

add_test(NAME mail.secure_mail COMMAND umbra_secure_mail_test)

# Demo

add_executable(umbra_demo
    src/demo/umbra_demo.cpp
)

target_link_libraries(umbra_demo
    PRIVATE umbra_mail
)
