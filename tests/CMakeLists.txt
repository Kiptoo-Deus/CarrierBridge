add_executable(test_core test_core.cpp)
target_link_libraries(test_core PRIVATE carrierbridge)
add_test(NAME CoreTests COMMAND test_core)
