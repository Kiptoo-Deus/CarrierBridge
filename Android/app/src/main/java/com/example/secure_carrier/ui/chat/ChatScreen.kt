package com.example.secure_carrier.ui.chat

import android.content.Context
import android.util.Base64
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.secure_carrier.net.WebSocketManager
import org.json.JSONObject

@Composable
fun ChatScreen(authViewModel: com.example.secure_carrier.ui.auth.AuthViewModel) {
    val ctx = LocalContext.current
    val prefs = ctx.getSharedPreferences("secure_carrier", Context.MODE_PRIVATE)
    val token = prefs.getString("auth_token", null)
    var recipient by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    val messages = remember { mutableStateListOf<String>() }

    LaunchedEffect(token) {
        token?.let {
            WebSocketManager.connect(it) { msg ->
                messages.add(msg)
            }
        }
    }

    Column(modifier = Modifier.padding(16.dp)) {
        Box(modifier = Modifier.fillMaxHeight(0.8f)) {
            LazyColumn {
                items(messages) { m ->
                    Text(m)
                }
            }
        }
        OutlinedTextField(value = recipient, onValueChange = { recipient = it }, label = { Text("Recipient ID") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = message, onValueChange = { message = it }, label = { Text("Message") }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        Button(onClick = {
            val userId = prefs.getString("user_id", "") ?: ""
            val obj = JSONObject()
            obj.put("type", "chat")
            obj.put("message_id", System.currentTimeMillis().toString())
            obj.put("sender_id", userId)
            obj.put("recipient", recipient)
            val payload = Base64.encodeToString(message.toByteArray(), Base64.NO_WRAP)
            obj.put("payload", payload)
            WebSocketManager.send(obj.toString())
            messages.add("me → $recipient: $message")
            message = ""
        }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Send")
        }
    }
}
