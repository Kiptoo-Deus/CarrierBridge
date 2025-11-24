#include "carrierbridge.h"
#include <iostream>

int main() {
    cb_init();
    cb_register("unit_test");
    cb_send_message("Kiptoo", "Unit test message");
    cb_shutdown();
    std::cout << "[TEST] Passed" << std::endl;
    return 0;
}
