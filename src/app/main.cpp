#include "carrierbridge.h"
#include <iostream>

int main() {
    cb_init();
    cb_register("test_user");
    cb_send_message("Joel", "Hello from CarrierBridge!");
    cb_shutdown();
    return 0;
}
