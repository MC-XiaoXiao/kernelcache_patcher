cmake_minimum_required(VERSION 3.10.0)
project(kernelcache_patcher VERSION 0.1.0 LANGUAGES C CXX)

include_directories(include)

include(CTest)
enable_testing()

add_executable(kernelcache_patcher main.cpp Macho.cpp KernelMacho.cpp KextMacho.cpp Kext.cpp CppAnalyzer.cpp Resolver.cpp StructorRebase.cpp Patcher.cpp Plist.cpp)

target_compile_features(kernelcache_patcher PRIVATE cxx_std_17)

target_link_libraries(kernelcache_patcher PUBLIC tinyxml2 capstone keystone)

if(BUILD_TESTING)
    add_executable(resolver_tests tests/ResolverTests.cpp Macho.cpp Resolver.cpp)
    target_compile_features(resolver_tests PRIVATE cxx_std_17)
    add_test(NAME resolver_tests COMMAND resolver_tests)

    add_executable(cpp_analyzer_tests tests/CppAnalyzerTests.cpp Macho.cpp CppAnalyzer.cpp)
    target_compile_features(cpp_analyzer_tests PRIVATE cxx_std_17)
    target_link_libraries(cpp_analyzer_tests PRIVATE capstone)
    add_test(NAME cpp_analyzer_tests COMMAND cpp_analyzer_tests)

    add_executable(structor_rebase_tests tests/StructorRebaseTests.cpp StructorRebase.cpp)
    target_compile_features(structor_rebase_tests PRIVATE cxx_std_17)
    add_test(NAME structor_rebase_tests COMMAND structor_rebase_tests)
endif()

if(CMAKE_BUILD_TYPE  AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    target_compile_definitions(kernelcache_patcher PUBLIC DEBUG=1)
else()
    target_compile_definitions(kernelcache_patcher PUBLIC DEBUG=0)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
