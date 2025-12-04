#include "android_jni_transport.hpp"
#include <android/log.h>

#define LOG_TAG "AndroidJNITransport"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace securecomm {

AndroidJNITransport::AndroidJNITransport(JavaVM* vm)
    : jvm_(vm), env_(nullptr), ws_obj_(nullptr), send_method_(nullptr) {
    if (vm) {
        vm->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6);
    }
}

AndroidJNITransport::~AndroidJNITransport() {
    if (env_ && ws_obj_) {
        env_->DeleteGlobalRef(ws_obj_);
    }
}

void AndroidJNITransport::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    ALOGI("AndroidJNITransport::start");
    // WebSocket connect is triggered by JNI/Kotlin side
}

void AndroidJNITransport::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    ALOGI("AndroidJNITransport::stop");
    if (env_ && ws_obj_) {
        // Call close on WebSocket
        jclass cls = env_->GetObjectClass(ws_obj_);
        jmethodID close_method = env_->GetMethodID(cls, "close", "()V");
        if (close_method) {
            env_->CallVoidMethod(ws_obj_, close_method);
        }
    }
}

void AndroidJNITransport::send(const std::vector<uint8_t>& bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!env_ || !ws_obj_ || !send_method_) {
        ALOGE("send: env=%p ws_obj=%p send_method=%p", env_, ws_obj_, send_method_);
        return;
    }

    jbyteArray data = env_->NewByteArray(bytes.size());
    if (data) {
        env_->SetByteArrayRegion(data, 0, bytes.size(),
                                  reinterpret_cast<const jbyte*>(bytes.data()));
        env_->CallVoidMethod(ws_obj_, send_method_, data);
        env_->DeleteLocalRef(data);
    }
}

void AndroidJNITransport::set_on_message(OnMessageCb cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_message_cb_ = cb;
}

void AndroidJNITransport::on_websocket_data(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (on_message_cb_) {
        on_message_cb_(data);
    }
}

} // namespace securecomm
