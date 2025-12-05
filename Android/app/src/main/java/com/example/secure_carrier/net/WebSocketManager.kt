package com.example.secure_carrier.net

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.Response

class WSListener(private val onMessage: (String) -> Unit) : WebSocketListener() {
    override fun onMessage(webSocket: WebSocket, text: String) {
        onMessage(text)
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {}

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {}

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {}
}

object WebSocketManager {
    private val client = OkHttpClient()
    private var socket: WebSocket? = null

    fun connect(token: String, onMessage: (String) -> Unit) {
        val baseUrl = NetworkClient.baseUrl
        if (baseUrl == null) {
            throw IllegalStateException("Server not discovered; cannot connect WebSocket")
        }
        val url = baseUrl.replaceFirst("http", "ws") + "/ws?token=" + token
        val req = Request.Builder().url(url).build()
        val listener = WSListener(onMessage)
        socket = client.newWebSocket(req, listener)
    }

    fun send(text: String) {
        socket?.send(text)
    }

    fun close() {
        socket?.close(1000, "bye")
    }
}
