#pragma once

#ifdef _WIN32
#define CB_API __declspec(dllexport)
#else
#define CB_API
#endif

extern "C" {
    CB_API void cb_init();
    CB_API void cb_shutdown();
    CB_API void cb_register(const char* username);
    CB_API void cb_send_message(const char* to, const char* message);
}
