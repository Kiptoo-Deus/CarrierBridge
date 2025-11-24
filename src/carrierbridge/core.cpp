#include "carrierbridge.h"
#include <iostream>
#include <string>

void cb_init() {
    std::cout << "[CarrierBridge] Initialized" << std::endl;
}

void cb_shutdown() {
    std::cout << "[CarrierBridge] Shutdown" << std::endl;
}

void cb_register(const char* username) {
    std::cout << "[CarrierBridge] Registering user: " << username << std::endl;
}

void cb_send_message(const char* to, const char* message) {
    std::cout << "[CarrierBridge] Sending message to " << to << ": " << message << std::endl;
}
