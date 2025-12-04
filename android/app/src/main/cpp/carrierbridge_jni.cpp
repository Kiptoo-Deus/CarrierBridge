#include <jni.h>
#include <android/log.h>
#include <string>
#include <memory>
#include <map>
#include <mutex>
#include <vector>

// Minimal JNI bridge without libsecurecomm dependency
// In production, this would link against the full dispatcher

static JavaVM* g_vm = nullptr;
static jobject g_callback = nullptr;
static jmethodID g_onMessageMethod = nullptr;
static std::mutex g_mutex;

// Simple handle management
struct NativeState {
    std::string device_id;
    std::vector<uint8_t> session_key;
};

static std::map<jlong, std::shared_ptr<NativeState>> g_states;
static jlong g_next_handle = 1;

#define LOG_TAG "carrierbridge_jni"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_vm = vm;
    ALOGI("JNI_OnLoad: vm=%p", vm);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_registerCallback(JNIEnv* env, jclass cls, jobject callback) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_callback != nullptr) {
        env->DeleteGlobalRef(g_callback);
        g_callback = nullptr;
        g_onMessageMethod = nullptr;
    }
    if (callback == nullptr) return;

    g_callback = env->NewGlobalRef(callback);
    jclass cbCls = env->GetObjectClass(callback);
    g_onMessageMethod = env->GetMethodID(cbCls, "onMessage", "([B)V");
    ALOGI("Registered Java callback: %p", (void*)g_callback);
}

extern "C" JNIEXPORT jlong JNICALL Java_org_carrierbridge_NativeBridge_nativeInit(JNIEnv* env, jclass cls) {
    std::lock_guard<std::mutex> lock(g_mutex);
    ALOGI("nativeInit called");

    auto state = std::make_shared<NativeState>();
    jlong handle = g_next_handle++;
    g_states[handle] = state;

    ALOGI("Dispatcher initialized: handle=%lld", (long long)handle);
    return handle;
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeClose(JNIEnv* env, jclass cls, jlong handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    ALOGI("nativeClose handle=%lld", (long long)handle);

    auto it = g_states.find(handle);
    if (it != g_states.end()) {
        g_states.erase(it);
    }
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeOnSocketData(JNIEnv* env, jclass cls, jlong handle, jbyteArray data) {
    std::lock_guard<std::mutex> lock(g_mutex);
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    ALOGI("nativeOnSocketData handle=%lld len=%d", (long long)handle, (int)len);

    // In MVP: just log and echo back via callback
    if (g_callback != nullptr && g_onMessageMethod != nullptr) {
        env->CallVoidMethod(g_callback, g_onMessageMethod, data);
    }

    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeSend(JNIEnv* env, jclass cls, jlong handle, jbyteArray data) {
    std::lock_guard<std::mutex> lock(g_mutex);
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    ALOGI("nativeSend handle=%lld len=%d", (long long)handle, (int)len);

    // In MVP: data will be sent via OkHttp WebSocket in Kotlin layer

    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeRegisterDevice(JNIEnv* env, jclass cls, jlong handle, jstring device_id) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const char* id_str = env->GetStringUTFChars(device_id, nullptr);
    ALOGI("nativeRegisterDevice handle=%lld id=%s", (long long)handle, id_str);

    auto it = g_states.find(handle);
    if (it != g_states.end()) {
        it->second->device_id = id_str;
    }

    env->ReleaseStringUTFChars(device_id, id_str);
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeCreateSession(JNIEnv* env, jclass cls, jlong handle, jstring remote_id, jbyteArray root_key) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const char* id_str = env->GetStringUTFChars(remote_id, nullptr);
    jsize key_len = env->GetArrayLength(root_key);
    jbyte* key_buf = env->GetByteArrayElements(root_key, nullptr);
    ALOGI("nativeCreateSession handle=%lld remote_id=%s key_len=%d", (long long)handle, id_str, (int)key_len);

    auto it = g_states.find(handle);
    if (it != g_states.end()) {
        it->second->session_key.assign(key_buf, key_buf + key_len);
    }

    env->ReleaseByteArrayElements(root_key, key_buf, JNI_ABORT);
    env->ReleaseStringUTFChars(remote_id, id_str);
}

extern "C" JNIEXPORT void JNICALL Java_org_carrierbridge_NativeBridge_nativeOnDestroy(JNIEnv* env, jclass cls) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_callback != nullptr) {
        env->DeleteGlobalRef(g_callback);
        g_callback = nullptr;
        g_onMessageMethod = nullptr;
    }
    g_states.clear();
    ALOGI("nativeOnDestroy cleaned up globals");
}

