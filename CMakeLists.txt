cmake_minimum_required(VERSION 3.23)
project(UmbraCore VERSION 1.0.0 LANGUAGES CXX)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectOptions)
include(Dependencies)
find_package(Threads REQUIRED)

# MinGW executables can either carry their compiler runtimes statically or
# deploy DLLs next to the executable.  Static linkage is the default for the
# demo so a first-time Windows user can launch it from PowerShell without
# editing PATH.  Set UMBRA_MINGW_STATIC_RUNTIME=OFF to use DLL deployment.
if(MINGW)
  get_filename_component(UMBRA_MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
  option(UMBRA_MINGW_STATIC_RUNTIME "Statically link MinGW compiler runtimes" ON)
  function(umbra_deploy_mingw_runtime target)
    foreach(runtime_dll IN ITEMS libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${UMBRA_MINGW_BIN_DIR}/${runtime_dll}"
          "$<TARGET_FILE_DIR:${target}>"
        VERBATIM)

    endforeach()
  endfunction()
  if(UMBRA_MINGW_STATIC_RUNTIME)
    add_link_options(-static-libgcc -static-libstdc++ -static)
  endif()
endif()

add_library(umbra_hash src/hash/sha_256.cpp)
target_include_directories(umbra_hash PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> $<INSTALL_INTERFACE:include>)
add_library(umbra_crypto src/crypto/rsa_engine.cpp src/crypto/elgamal_engine.cpp src/crypto/crypto_engine.cpp)
target_include_directories(umbra_crypto PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> $<INSTALL_INTERFACE:include>)
target_link_libraries(umbra_crypto PUBLIC umbra_hash NTL::NTL GMP::GMPXX)
add_library(umbra_certificate src/certificate/certificate.cpp src/certificate/trusted_authority.cpp src/certificate/certificate_authority.cpp src/certificate/certificate_library.cpp src/pki/pki_user.cpp)
target_include_directories(umbra_certificate PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> $<INSTALL_INTERFACE:include>)
target_link_libraries(umbra_certificate PUBLIC umbra_crypto)
add_library(umbra_mail src/mail/secure_mail.cpp)
target_include_directories(umbra_mail PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> $<INSTALL_INTERFACE:include>)
target_link_libraries(umbra_mail PUBLIC umbra_certificate)

enable_testing()
function(umbra_add_test target source name link)
  add_executable(${target} ${source})
  target_link_libraries(${target} PRIVATE ${link})
  add_test(NAME ${name} COMMAND ${target})
endfunction()
umbra_add_test(umbra_crypto_rsa_engine_test tests/crypto/rsa_engine_test.cpp crypto.rsa_engine umbra_crypto)
target_compile_definitions(umbra_crypto_rsa_engine_test PRIVATE UMBRA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}" UMBRA_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")
umbra_add_test(umbra_hash_sha_256_test tests/hash/sha_256_test.cpp hash.sha_256 umbra_hash)
umbra_add_test(umbra_crypto_elgamal_engine_test tests/crypto/elgamal_engine_test.cpp crypto.elgamal_engine umbra_crypto)
target_compile_definitions(umbra_crypto_elgamal_engine_test PRIVATE UMBRA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}" UMBRA_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")
umbra_add_test(umbra_certificate_test tests/certificate/certificate_test.cpp certificate.certificate umbra_certificate)
umbra_add_test(umbra_trusted_authority_test tests/certificate/trusted_authority_test.cpp certificate.trusted_authority umbra_certificate)
umbra_add_test(umbra_certificate_authority_test tests/certificate/certificate_authority_test.cpp certificate.certificate_authority umbra_certificate)
umbra_add_test(umbra_certificate_library_test tests/certificate/certificate_library_test.cpp certificate.certificate_library umbra_certificate)
umbra_add_test(umbra_pki_user_test tests/pki/pki_user_test.cpp pki.pki_user umbra_certificate)
umbra_add_test(umbra_secure_mail_test tests/mail/secure_mail_test.cpp mail.secure_mail umbra_mail)
add_executable(umbra_demo src/demo/umbra_demo.cpp)
target_link_libraries(umbra_demo PRIVATE umbra_mail Threads::Threads)
if(MINGW AND NOT UMBRA_MINGW_STATIC_RUNTIME)
  umbra_deploy_mingw_runtime(umbra_demo)
endif()

include(GNUInstallDirs)
install(TARGETS umbra_hash umbra_crypto umbra_certificate umbra_mail EXPORT UmbraCoreTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY src/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")
install(EXPORT UmbraCoreTargets NAMESPACE UmbraCore:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/UmbraCore)
