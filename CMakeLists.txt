cmake_minimum_required(VERSION 3.10)

# set the project name
project(ChainProcurementWallet VERSION 1.0)

# add the executable
add_executable(Main src/main.cpp)

configure_file(Config.h.in Config.h)

target_link_libraries(Main ${CMAKE_SOURCE_DIR}/lib/libwallycore.a)
target_link_libraries(Main ${CMAKE_SOURCE_DIR}/lib/libsecp256k1.a)


# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
