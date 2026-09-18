cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)

project(PESignAnalyzer VERSION 1.3.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "PESignAnalyzer requires the Windows SDK.")
endif()

set(PESIGNANALYZER_CORE_SOURCES
    src/analyzer.cpp
    src/asn1.cpp
    src/authenticode.cpp
    src/catalog.cpp
    src/certificate_info.cpp
    src/signature_parser.cpp
)

add_library(PESignAnalyzerCore STATIC ${PESIGNANALYZER_CORE_SOURCES})
target_compile_features(PESignAnalyzerCore PUBLIC cxx_std_11)
target_include_directories(PESignAnalyzerCore
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_definitions(PESignAnalyzerCore PUBLIC UNICODE _UNICODE)
target_link_libraries(PESignAnalyzerCore PUBLIC Crypt32 Advapi32)

add_executable(PESignAnalyzer src/main.cpp)
target_include_directories(PESignAnalyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(PESignAnalyzer PRIVATE PESignAnalyzerCore)

if(MSVC)
    target_compile_options(PESignAnalyzerCore PRIVATE /W3)
    target_compile_options(PESignAnalyzer PRIVATE /W3)
    set_property(TARGET PESignAnalyzerCore PESignAnalyzer PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CTest)
if(BUILD_TESTING)
    find_program(PESIGN_POWERSHELL NAMES pwsh.exe powershell.exe)
    if(NOT PESIGN_POWERSHELL)
        message(FATAL_ERROR "PowerShell is required to run the smoke tests.")
    endif()
    add_test(
        NAME smoke
        COMMAND ${PESIGN_POWERSHELL} -NoProfile -ExecutionPolicy Bypass
            -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.ps1
            -Executable $<TARGET_FILE:PESignAnalyzer>
    )
endif()

install(
    TARGETS PESignAnalyzer PESignAnalyzerCore
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
)
install(DIRECTORY include/ DESTINATION include)
