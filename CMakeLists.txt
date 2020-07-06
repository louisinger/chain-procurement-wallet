 
cmake_minimum_required(VERSION 3.10)

# set the project name
project(ChainProcurementWallet VERSION 1.0)

include_directories(${CMAKE_SOURCE_DIR}/include)

# find_library(SECP256K1 "secp256k1" "/usr/local/lib" "usr/lib")
# find_library(WALLYCORE "wallycore" "/usr/lib" "usr/local/lib")

file(GLOB SOURCES src/*.cpp)

# add the executable
add_executable(Main ${SOURCES})
add_definitions(-DBUILD_ELEMENTS)

configure_file(Config.h.in Config.h)

target_link_libraries(Main ${CMAKE_SOURCE_DIR}/lib/libwallycore.a)
target_link_libraries(Main ${CMAKE_SOURCE_DIR}/lib/libsecp256k1.a)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
