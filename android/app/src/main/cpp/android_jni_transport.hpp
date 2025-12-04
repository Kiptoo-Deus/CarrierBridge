#pragma once

#include "transport.hpp"
#include <jni.h>
#include <mutex>

namespace securecomm {

class AndroidJNITransport : public Transport {
public:
    AndroidJNITransport(JavaVM* vm);
    ~AndroidJNITransport() override;

    void start() override;
    void stop() override;
    void send(const std::vector<uint8_t>& bytes) override;
    void set_on_message(OnMessageCb cb) override;

    // Called from JNI when WebSocket receives data
    void on_websocket_data(const std::vector<uint8_t>& data);

private:
    JavaVM* jvm_;
    JNIEnv* env_;
    jobject ws_obj_;  // NativeWebSocket instance
    jmethodID send_method_;
    OnMessageCb on_message_cb_;
    std::mutex mutex_;
};

} // namespace securecomm
