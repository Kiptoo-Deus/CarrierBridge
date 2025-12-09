@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
package com.example.secure_carrier.ui.chat

import android.content.Context
import android.util.Base64
import androidx.navigation.NavController
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.sp
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
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults

@Composable
fun ChatScreen(authViewModel: com.example.secure_carrier.ui.auth.AuthViewModel, navController: NavController) {
    val ctx = LocalContext.current
    val prefs = ctx.getSharedPreferences("secure_carrier", Context.MODE_PRIVATE)
    val userId = prefs.getString("user_id", null)
    var displayName = prefs.getString("display_name", null)
    if (displayName.isNullOrBlank()) {
        val randomDigits = (1000..9999).random()
        displayName = "User$randomDigits"
        prefs.edit().putString("display_name", displayName).apply()
    }
    val random = (1..8).map { ('a'..'f') + ('0'..'9') }.flatten().shuffled().take(8).joinToString("")
    val wsToken = if (userId != null && displayName != null) "$userId:$displayName:$random" else null
    var recipient by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    data class ChatMessage(val text: String, val isSent: Boolean, val timestamp: Long, val senderName: String)
    val messages = remember { mutableStateListOf<ChatMessage>() }
    data class OnlineUser(val userId: String, val displayName: String)
    val onlineUsers = remember { mutableStateListOf<OnlineUser>() }
    var expanded by remember { mutableStateOf(false) }

    // Custom colors and typography
    val primaryColor = androidx.compose.material3.MaterialTheme.colorScheme.primary
    val surfaceColor = androidx.compose.material3.MaterialTheme.colorScheme.surface
    val onSurface = androidx.compose.material3.MaterialTheme.colorScheme.onSurface
    val bubbleSent = androidx.compose.material3.MaterialTheme.colorScheme.primaryContainer
    val bubbleReceived = androidx.compose.material3.MaterialTheme.colorScheme.secondaryContainer
    val bubbleTextSent = androidx.compose.material3.MaterialTheme.colorScheme.onPrimaryContainer
    val bubbleTextReceived = androidx.compose.material3.MaterialTheme.colorScheme.onSecondaryContainer
    val chatFont = androidx.compose.material3.MaterialTheme.typography.bodyLarge

    LaunchedEffect(wsToken) {
        wsToken?.let {
            WebSocketManager.connect(it) { msg ->
                try {
                    val obj = JSONObject(msg)
                    if (obj.optString("type") == "online_users") {
                        onlineUsers.clear()
                        val arr = obj.optJSONArray("users")
                        if (arr != null) {
                            for (i in 0 until arr.length()) {
                                val userObj = arr.getJSONObject(i)
                                val userId = userObj.optString("userId")
                                val displayName = userObj.optString("displayName")
                                onlineUsers.add(OnlineUser(userId, displayName))
                            }
                        }
                    } else if (obj.optString("type") == "chat") {
                        val sender = obj.optString("sender_id", "")
                        val senderName = obj.optString("sender_name", sender)
                        val payload = obj.optString("payload", "")
                        val text = String(Base64.decode(payload, Base64.NO_WRAP))
                        val ts = obj.optLong("timestamp", System.currentTimeMillis())
                        val isSent = sender == userId
                        messages.add(ChatMessage(text, isSent, ts, senderName))
                    } else {
                        messages.add(ChatMessage(msg, false, System.currentTimeMillis(), "Server"))
                    }
                } catch (e: Exception) {
                    messages.add(ChatMessage(msg, false, System.currentTimeMillis(), "Server"))
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .padding(0.dp)
            .fillMaxSize()
            .background(surfaceColor),
        verticalArrangement = Arrangement.Top,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        androidx.compose.material3.TopAppBar(
            title = { Text("SecureComm", style = androidx.compose.material3.MaterialTheme.typography.titleLarge) },
            colors = androidx.compose.material3.TopAppBarDefaults.topAppBarColors(containerColor = primaryColor)
        )
        Box(modifier = Modifier.weight(1f).fillMaxWidth().background(surfaceColor)) {
            LazyColumn(
                modifier = Modifier.padding(8.dp)
            ) {
                items(messages) { msg ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = if (msg.isSent) Arrangement.End else Arrangement.Start
                    ) {
                        if (!msg.isSent) {
                            // Avatar placeholder for received messages
                            androidx.compose.material3.Surface(
                                shape = androidx.compose.foundation.shape.CircleShape,
                                color = bubbleReceived,
                                modifier = Modifier.size(32.dp)
                            ) {
                                Text(
                                    msg.senderName.take(1).uppercase(),
                                    modifier = Modifier.align(Alignment.CenterVertically).padding(8.dp),
                                    style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                                    color = bubbleTextReceived
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Column(
                            horizontalAlignment = if (msg.isSent) Alignment.End else Alignment.Start
                        ) {
                            Box(
                                modifier = Modifier
                                    .background(
                                        if (msg.isSent) bubbleSent else bubbleReceived,
                                        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp)
                                    )
                                    .shadow(2.dp, shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp))
                                    .padding(12.dp)
                            ) {
                                Text(
                                    msg.text,
                                    style = chatFont,
                                    color = if (msg.isSent) bubbleTextSent else bubbleTextReceived
                                )
                            }
                            Text(
                                "${msg.senderName} • " + java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date(msg.timestamp)),
                                style = androidx.compose.material3.MaterialTheme.typography.labelSmall,
                                color = onSurface,
                                modifier = Modifier.padding(top = 2.dp, start = 4.dp, end = 4.dp)
                            )
                        }
                        if (msg.isSent) {
                            Spacer(modifier = Modifier.width(8.dp))
                            // Avatar placeholder for sent messages
                            androidx.compose.material3.Surface(
                                shape = androidx.compose.foundation.shape.CircleShape,
                                color = bubbleSent,
                                modifier = Modifier.size(32.dp)
                            ) {
                                Text(
                                    displayName?.take(1)?.uppercase() ?: "M",
                                    modifier = Modifier.align(Alignment.CenterVertically).padding(8.dp),
                                    style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                                    color = bubbleTextSent
                                )
                            }
                        }
                    }
                }
            }
        }
        Text("Online Users:", modifier = Modifier.align(Alignment.Start).padding(start = 16.dp, top = 8.dp), style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded }
        ) {
            OutlinedTextField(
                value = recipient,
                onValueChange = { recipient = it },
                label = { Text("Recipient ID") },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                readOnly = false,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) }
            )
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                onlineUsers.forEach { user ->
                    DropdownMenuItem(
                        text = { Text("${user.displayName} (${user.userId})") },
                        onClick = {
                            recipient = user.userId
                            expanded = false
                        }
                    )
                }
            }
        }
        OutlinedTextField(
            value = message,
            onValueChange = { message = it },
            label = { Text("Message") },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)
        )
        Button(
            onClick = {
                val userId = prefs.getString("user_id", "") ?: ""
                val obj = JSONObject()
                obj.put("type", "chat")
                obj.put("message_id", System.currentTimeMillis().toString())
                obj.put("sender_id", userId)
                obj.put("sender_name", displayName ?: "Me")
                obj.put("recipient", recipient)
                obj.put("timestamp", System.currentTimeMillis())
                val payload = Base64.encodeToString(message.toByteArray(), Base64.NO_WRAP)
                obj.put("payload", payload)
                WebSocketManager.send(obj.toString())
                messages.add(ChatMessage(message, true, System.currentTimeMillis(), displayName ?: "Me"))
                message = ""
            },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            Text("Send", style = androidx.compose.material3.MaterialTheme.typography.labelLarge)
        }
        Spacer(modifier = Modifier.height(16.dp))
    }
}
