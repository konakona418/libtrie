cmake_minimum_required(VERSION 3.23)

project(libtrie VERSION 0.1.0 LANGUAGES CXX)

add_library(trie INTERFACE)
add_library(trie::trie ALIAS trie)

target_compile_features(trie INTERFACE cxx_std_26)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
        message(FATAL_ERROR
            "libtrie needs GCC 16 or newer for C++26 reflection (P2996). "
            "Found GCC ${CMAKE_CXX_COMPILER_VERSION}.")
    endif()
    target_compile_options(trie INTERFACE -freflection)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Only the experimental P2996 Clang builds provide this flag; stock Clang
    # does not implement reflection yet.
    target_compile_options(trie INTERFACE -freflection-latest)
else()
    message(FATAL_ERROR "libtrie requires a compiler with C++26 reflection support")
endif()

target_include_directories(trie INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/nlohmann>
    $<INSTALL_INTERFACE:include>
)

option(TRIE_BUILD_TESTS "Build libtrie tests" ${PROJECT_IS_TOP_LEVEL})
option(TRIE_BUILD_EXAMPLES "Build libtrie examples" ${PROJECT_IS_TOP_LEVEL})

if(TRIE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TRIE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
