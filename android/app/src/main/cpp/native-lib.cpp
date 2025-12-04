/* Minimal JNI stub implementations for CarrierBridgeNative
 * - Self-contained single source to avoid pulling in repo-level C++ code
 * - Implements the native methods declared in `CarrierBridgeNative.kt` as safe stubs
 * - Returns simple defaults so the app can run in degraded mode without full native backend
 */

#include <jni.h>
#include <string>
#include <android/log.h>

static const char* TAG = "carrierbridge_jni_stub";

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_initDispatcher(JNIEnv* env, jclass clazz, jstring deviceId) {
    LOGI("initDispatcher called (stub)");
    // Return a non-zero fake handle to indicate 'initialized'
    return 1;
}

JNIEXPORT jboolean JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_createSession(JNIEnv* env, jclass clazz, jstring remoteDeviceId) {
    LOGI("createSession called (stub)");
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_sendMessage(JNIEnv* env, jclass clazz, jstring recipientId, jbyteArray plaintext) {
    LOGI("sendMessage called (stub)");
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_setInboundCallback(JNIEnv* env, jclass clazz, jobject callback) {
    LOGI("setInboundCallback called (stub) - not storing callback in stub");
}

JNIEXPORT void JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_stopDispatcher(JNIEnv* env, jclass clazz) {
    LOGI("stopDispatcher called (stub)");
}

JNIEXPORT jstring JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_getVersion(JNIEnv* env, jclass clazz) {
    const char* v = "0.0.0-mvp";
    return env->NewStringUTF(v);
}

JNIEXPORT jboolean JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_dispatcherIsInitialized(JNIEnv* env, jclass clazz) {
    LOGI("dispatcherIsInitialized called (stub)");
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_ratchetGetState(JNIEnv* env, jclass clazz) {
    LOGI("ratchetGetState called (stub)");
    return nullptr;
}

JNIEXPORT jboolean JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_transportConnect(JNIEnv* env, jclass clazz, jstring url) {
    LOGI("transportConnect called (stub)");
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_meshStartDiscovery(JNIEnv* env, jclass clazz) {
    LOGI("meshStartDiscovery called (stub)");
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_queueGetPendingCount(JNIEnv* env, jclass clazz) {
    LOGI("queueGetPendingCount called (stub)");
    return 0;
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_carrierbridge_jni_CarrierBridgeNative_testEncrypt(JNIEnv* env, jclass clazz, jbyteArray data) {
    LOGI("testEncrypt called (stub) - echoing input if present");
    if (data == nullptr) return nullptr;
    jsize len = env->GetArrayLength(data);
    jbyteArray out = env->NewByteArray(len);
    if (out) {
        jbyte* buffer = env->GetByteArrayElements(data, NULL);
        env->SetByteArrayRegion(out, 0, len, buffer);
        env->ReleaseByteArrayElements(data, buffer, JNI_ABORT);
    }
    return out;
}

}
