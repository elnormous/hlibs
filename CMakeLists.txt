cmake_minimum_required(VERSION 3.13)
project(Hlibs VERSION 0.0.1)

add_subdirectory(test)

add_library(hlibs INTERFACE)
target_include_directories(hlibs INTERFACE include/)