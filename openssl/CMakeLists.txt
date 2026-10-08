cmake_minimum_required(VERSION 3.20)
project(PESignAnalyzerOpenSSL VERSION 0.2.2 LANGUAGES CXX)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(CURL 7.68 REQUIRED)

add_library(pesign_openssl STATIC
    src/pe_reader.cpp
    src/pkcs7_parser.cpp
    src/report.cpp
    src/digest.cpp
    src/catalog.cpp
    src/verification.cpp
    src/trust.cpp
    src/network.cpp
)
add_library(pesign::openssl ALIAS pesign_openssl)
target_compile_features(pesign_openssl PUBLIC cxx_std_17)
target_include_directories(pesign_openssl
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(pesign_openssl PUBLIC OpenSSL::Crypto CURL::libcurl)
if(WIN32)
    target_link_libraries(pesign_openssl PUBLIC Crypt32)
elseif(APPLE)
    find_library(PESIGN_SECURITY Security REQUIRED)
    find_library(PESIGN_COREFOUNDATION CoreFoundation REQUIRED)
    target_link_libraries(pesign_openssl PUBLIC ${PESIGN_SECURITY} ${PESIGN_COREFOUNDATION})
endif()

add_executable(PESignAnalyzerOpenSSL src/main.cpp)
target_link_libraries(PESignAnalyzerOpenSSL PRIVATE pesign_openssl)
if(MINGW)
    target_link_options(PESignAnalyzerOpenSSL PRIVATE -municode)
endif()

function(pesign_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()
pesign_warnings(pesign_openssl)
pesign_warnings(PESignAnalyzerOpenSSL)

include(CTest)
if(BUILD_TESTING)
    add_executable(pesign_pe_tests tests/pe_reader_tests.cpp)
    target_link_libraries(pesign_pe_tests PRIVATE pesign_openssl)
    pesign_warnings(pesign_pe_tests)
    add_test(NAME pe_reader COMMAND pesign_pe_tests)

    add_executable(pesign_pkcs7_tests tests/pkcs7_tests.cpp)
    target_include_directories(pesign_pkcs7_tests PRIVATE src)
    target_link_libraries(pesign_pkcs7_tests PRIVATE pesign_openssl)
    pesign_warnings(pesign_pkcs7_tests)
    add_test(NAME pkcs7_parser COMMAND pesign_pkcs7_tests)

    add_executable(pesign_verification_tests tests/verification_tests.cpp)
    target_include_directories(pesign_verification_tests PRIVATE src)
    target_link_libraries(pesign_verification_tests PRIVATE pesign_openssl)
    if(MINGW)
        target_link_options(pesign_verification_tests PRIVATE -municode)
    endif()
    pesign_warnings(pesign_verification_tests)
    add_test(NAME authenticode_verification COMMAND pesign_verification_tests)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME online_verification
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/online_verification_tests.py
                --fixture-tool $<TARGET_FILE:pesign_verification_tests>
                --analyzer $<TARGET_FILE:PESignAnalyzerOpenSSL>)
        set_tests_properties(online_verification PROPERTIES TIMEOUT 150)
    endif()

    add_test(NAME cli_help COMMAND PESignAnalyzerOpenSSL --help)
    add_test(NAME cli_version COMMAND PESignAnalyzerOpenSSL --version)
    add_test(NAME cli_errors
        COMMAND ${CMAKE_COMMAND}
            -DEXECUTABLE=$<TARGET_FILE:PESignAnalyzerOpenSSL>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_errors.cmake)
endif()

include(GNUInstallDirs)
install(TARGETS pesign_openssl PESignAnalyzerOpenSSL
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
