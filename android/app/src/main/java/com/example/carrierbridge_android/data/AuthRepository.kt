package com.example.carrierbridge_android.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.util.UUID
import javax.net.ssl.HttpsURLConnection

class AuthRepository(private val context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
    
    companion object {
        const val KEY_USER_ID = "user_id"
        const val KEY_PHONE = "phone"
        const val KEY_EMAIL = "email"
        const val KEY_AUTH_TOKEN = "auth_token"
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_DISPLAY_NAME = "display_name"
        const val KEY_IS_LOGGED_IN = "is_logged_in"
        

        const val SERVER_URL = "http:

    }

    fun isLoggedIn(): Boolean {
        return prefs.getBoolean(KEY_IS_LOGGED_IN, false) && !getAuthToken().isNullOrEmpty()
    }

    fun getUserId(): String? {
        return if (!isLoggedIn()) null else prefs.getString(KEY_USER_ID, null)
    }

    fun getAuthToken(): String? {
        return prefs.getString(KEY_AUTH_TOKEN, null)
    }

    fun getPhone(): String? {
        return prefs.getString(KEY_PHONE, null)
    }

    fun getEmail(): String? {
        return prefs.getString(KEY_EMAIL, null)
    }

    fun getDeviceId(): String {
        var deviceId = prefs.getString(KEY_DEVICE_ID, null)
        if (deviceId == null) {
            deviceId = UUID.randomUUID().toString()
            prefs.edit().putString(KEY_DEVICE_ID, deviceId).apply()
        }
        return deviceId
    }

    fun getDisplayName(): String? {
        return prefs.getString(KEY_DISPLAY_NAME, null)
    }

    suspend fun registerPhone(phone: String, displayName: String = ""): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = """{"phone":"$phone","display_name":"$displayName"}"""
                val response = makeHttpRequest(
                    "$SERVER_URL/api/auth/register/phone",
                    "POST",
                    requestBody
                )
                
                if (response != null) {
                    Result.success("otp_sent")
                } else {
                    Result.failure(Exception("Failed to send OTP"))
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun verifyPhoneOtp(phone: String, otp: String, displayName: String = ""): Result<AuthResponse> {
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = """{"phone":"$phone","otp":"$otp","display_name":"$displayName"}"""
                val response = makeHttpRequest(
                    "$SERVER_URL/api/auth/verify/phone",
                    "POST",
                    requestBody
                )
                
                if (response != null) {
                    val authResponse = parseAuthResponse(response)
                    if (authResponse != null) {
                        saveAuthResponse(authResponse)
                        Result.success(authResponse)
                    } else {
                        Result.failure(Exception("Failed to parse auth response"))
                    }
                } else {
                    Result.failure(Exception("OTP verification failed"))
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun registerEmail(email: String, displayName: String = ""): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = """{"email":"$email","display_name":"$displayName"}"""
                val response = makeHttpRequest(
                    "$SERVER_URL/api/auth/register/email",
                    "POST",
                    requestBody
                )
                
                if (response != null) {
                    Result.success("email_sent")
                } else {
                    Result.failure(Exception("Failed to send verification email"))
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun verifyEmailToken(email: String, token: String, displayName: String = ""): Result<AuthResponse> {
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = """{"email":"$email","token":"$token","display_name":"$displayName"}"""
                val response = makeHttpRequest(
                    "$SERVER_URL/api/auth/verify/email",
                    "POST",
                    requestBody
                )
                
                if (response != null) {
                    val authResponse = parseAuthResponse(response)
                    if (authResponse != null) {
                        saveAuthResponse(authResponse)
                        Result.success(authResponse)
                    } else {
                        Result.failure(Exception("Failed to parse auth response"))
                    }
                } else {
                    Result.failure(Exception("Email verification failed"))
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    fun saveAuthResponse(response: AuthResponse) {
        prefs.edit().apply {
            putString(KEY_USER_ID, response.userId)
            putString(KEY_AUTH_TOKEN, response.authToken)
            putString(KEY_PHONE, response.phone)
            putString(KEY_EMAIL, response.email)
            putString(KEY_DISPLAY_NAME, response.displayName)
            putBoolean(KEY_IS_LOGGED_IN, true)
            apply()
        }
    }

    fun logout() {
        prefs.edit().apply {
            remove(KEY_USER_ID)
            remove(KEY_AUTH_TOKEN)
            remove(KEY_PHONE)
            remove(KEY_EMAIL)
            remove(KEY_DISPLAY_NAME)
            putBoolean(KEY_IS_LOGGED_IN, false)
            apply()
        }
    }

    fun clearAll() {
        prefs.edit().clear().apply()
    }

    private fun makeHttpRequest(urlString: String, method: String, body: String = ""): String? {
        return try {
            val url = URL(urlString)
            val conn = url.openConnection() as? HttpsURLConnection ?: 
                       (url.openConnection() as? java.net.HttpURLConnection) ?: return null
            
            conn.requestMethod = method
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.connectTimeout = 10000
            conn.readTimeout = 10000

            if (body.isNotEmpty()) {
                conn.outputStream.use { output ->
                    output.write(body.toByteArray())
                    output.flush()
                }
            }

            val statusCode = conn.responseCode
            if (statusCode in 200..299) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun parseAuthResponse(json: String): AuthResponse? {
        return try {

            val userId = extractJsonString(json, "user_id") ?: return null
            val authToken = extractJsonString(json, "auth_token") ?: return null
            val phone = extractJsonString(json, "phone")
            val email = extractJsonString(json, "email")
            val displayName = extractJsonString(json, "display_name") ?: "User"

            AuthResponse(userId, authToken, phone, email, displayName)
        } catch (e: Exception) {
            null
        }
    }

    private fun extractJsonString(json: String, key: String): String? {
        val pattern = "\"$key\"\\s*:\\s*\"([^\"]*)\""
        val regex = Regex(pattern)
        return regex.find(json)?.groupValues?.get(1)
    }
}

data class AuthResponse(
    val userId: String,
    val authToken: String,
    val phone: String? = null,
    val email: String? = null,
    val displayName: String = ""
)
