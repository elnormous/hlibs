cmake_minimum_required(VERSION 3.13)
project(Hlibs VERSION 0.0.1)

include(CTest)

add_subdirectory(external/Catch2)
add_subdirectory(test)
