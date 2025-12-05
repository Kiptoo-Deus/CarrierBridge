package com.example.secure_carrier.net

import android.util.Log
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object NetworkClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()
    var baseUrl: String? = null
        get() {
            if (field == null) {
                field = ServerDiscovery.discoverServer()
                Log.d("NetworkClient", "Initialized baseUrl: $field")
            }
            return field
        }

    fun postJson(path: String, json: JSONObject): JSONObject? {
        return try {
            val url = baseUrl?.let { it + path } ?: run {
                Log.e("NetworkClient", "baseUrl is null; server discovery failed")
                return null
            }
            Log.d("NetworkClient", "POST to $url with body: $json")
            val body = json.toString().toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
            val req = Request.Builder().url(url).post(body).build()
            val resp = client.newCall(req).execute()
            Log.d("NetworkClient", "Response code: ${resp.code}")
            if (!resp.isSuccessful) {
                Log.e("NetworkClient", "HTTP ${resp.code}: ${resp.message}")
                resp.close()
                return null
            }
            val bodyString = resp.body?.string()
            resp.close()
            Log.d("NetworkClient", "Response body: $bodyString")
            if (bodyString == null) {
                Log.e("NetworkClient", "Response body is null")
                return null
            }
            JSONObject(bodyString)
        } catch (e: Exception) {
            Log.e("NetworkClient", "postJson error", e)
            null
        }
    }

    fun resetDiscovery() {
        ServerDiscovery.clearCache()
        baseUrl = null
        Log.d("NetworkClient", "Discovery reset; will re-scan on next request")
    }
}
