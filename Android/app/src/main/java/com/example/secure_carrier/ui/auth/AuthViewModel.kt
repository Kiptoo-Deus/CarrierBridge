package com.example.secure_carrier.ui.auth

import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import com.example.secure_carrier.net.NetworkClient
import com.example.secure_carrier.net.WebSocketManager
import org.json.JSONObject

class AuthViewModel : ViewModel() {
    var phone by mutableStateOf("")
    var displayName by mutableStateOf("")
    var otp by mutableStateOf("")
    var userId by mutableStateOf<String?>(null)
    var token by mutableStateOf<String?>(null)
    var status by mutableStateOf<String?>(null)

    private val mainHandler = Handler(Looper.getMainLooper())

    private fun postMain(action: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) action() else mainHandler.post { action() }
    }

    fun requestOtp() {
        postMain { status = "requesting..." }
        Thread {
            try {
                Log.d("AuthVM", "Requesting OTP for $phone")
                val obj = JSONObject()
                obj.put("phone", phone)
                obj.put("display_name", displayName)
                val resp = NetworkClient.postJson("/api/auth/register/phone", obj)
                Log.d("AuthVM", "Response: $resp")
                if (resp != null && resp.optString("status") == "ok") {
                    val otpFromServer = resp.optString("otp", "")
                    Log.d("AuthVM", "Got OTP from server: $otpFromServer")
                    postMain {
                        otp = otpFromServer
                        status = "otp_sent: $otpFromServer"
                    }
                } else {
                    postMain { status = "failed: ${resp?.toString()}" }
                }
            } catch (e: Exception) {
                Log.e("AuthVM", "Error requesting OTP", e)
                postMain { status = "error: ${e.message}" }
            }
        }.start()
    }

    fun verifyOtp(onSuccess: (String, String) -> Unit) {
        postMain { status = "verifying..." }
        Thread {
            try {
                Log.d("AuthVM", "Verifying OTP for $phone")
                val obj = JSONObject()
                obj.put("phone", phone)
                obj.put("otp", otp)
                obj.put("display_name", displayName)
                val resp = NetworkClient.postJson("/api/auth/verify/phone", obj)
                Log.d("AuthVM", "Verify response: $resp")
                if (resp != null && resp.optString("status") == "ok") {
                    val u = resp.optString("user_id")
                    val t = resp.optString("auth_token")
                    postMain {
                        userId = u
                        token = t
                        status = "ok"
                        Log.d("AuthVM", "Auth success: $u")
                        onSuccess(u, t)
                    }
                } else {
                    postMain { status = "invalid: ${resp?.toString()}" }
                }
            } catch (e: Exception) {
                Log.e("AuthVM", "Error verifying OTP", e)
                postMain { status = "error: ${e.message}" }
            }
        }.start()
    }

    fun startWebSocket() {
        token?.let {
            WebSocketManager.connect(it) {}
        }
    }

    fun sendRaw(text: String) {
        WebSocketManager.send(text)
    }
}
