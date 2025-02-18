cmake_minimum_required(VERSION 3.5.0)
project(kernelcache_patcher VERSION 0.1.0 LANGUAGES C CXX)

include_directories(include)

include(CTest)
enable_testing()

add_executable(kernelcache_patcher main.cpp Macho.cpp KernelMacho.cpp KextMacho.cpp Kext.cpp Patcher.cpp Plist.cpp)

target_link_libraries(kernelcache_patcher PUBLIC plist++-2.0 tinyxml2 capstone keystone)

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    target_compile_definitions(kernelcache_patcher PUBLIC DEBUG=1)
else()
    target_compile_definitions(kernelcache_patcher PUBLIC DEBUG=0)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
