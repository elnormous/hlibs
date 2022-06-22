include_directories("${Hlibs_SOURCE_DIR}/include")

set(hlibs_test_sources
    main.cpp
    tests.cpp
)

source_group("src" FILES ${hlibs_test_sources})

add_executable(hlibs-test ${hlibs_test_sources})
target_compile_features(hlibs-test PRIVATE cxx_std_17)
target_link_libraries(hlibs-test Catch2::Catch2)

add_test(NAME hlibs-test COMMAND hlibs-test)