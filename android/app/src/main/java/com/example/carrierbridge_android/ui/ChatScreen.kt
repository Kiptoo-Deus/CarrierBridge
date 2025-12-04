package com.example.carrierbridge_android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Done
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.carrierbridge.jni.CarrierBridgeClient
import com.example.carrierbridge_android.ui.theme.BrandBlue
import com.example.carrierbridge_android.ui.theme.SurfaceLight
import com.example.carrierbridge_android.ui.theme.TextPrimary
import com.example.carrierbridge_android.ui.theme.TextSecondary
import kotlinx.coroutines.launch
import android.content.Context
import android.provider.ContactsContract
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.produceState

// Message states for delivery tracking
enum class MessageState {
    PENDING, SENT, DELIVERED, FAILED
}

data class ChatMessage(
    val id: String,
    val text: String,
    val isMe: Boolean,
    val time: Long = System.currentTimeMillis(),
    val state: MessageState = if (isMe) MessageState.PENDING else MessageState.DELIVERED
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    deviceId: String = "alice",
    recipientId: String = "bob",
    carrierClient: CarrierBridgeClient? = null,
    onRecipientChange: () -> Unit = {},
    readContactsGranted: Boolean = false,
    onRequestContactsPermission: () -> Unit = {}
) {
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()

    var input by remember { mutableStateOf("") }
    var messages by remember { mutableStateOf(sampleMessages()) }
    var isLoading by remember { mutableStateOf(false) }
    var currentRecipient by remember { mutableStateOf(recipientId) }
    var showRecipientPicker by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("CarrierBridge", fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
                        Text(
                            "with: $currentRecipient",
                            fontSize = 12.sp,
                            color = Color.White.copy(alpha = 0.8f)
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { showRecipientPicker = true }) {
                        Icon(Icons.Default.Check, "Change recipient", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = BrandBlue,
                    titleContentColor = Color.White
                )
            )
        },
        containerColor = SurfaceLight
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Message list
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(8.dp),
                state = listState,
                reverseLayout = true
            ) {
                items(messages) { msg ->
                    MessageBubbleWithState(msg)
                    Spacer(modifier = Modifier.height(6.dp))
                }
            }

            Divider(color = Color.LightGray, thickness = 1.dp)

            // Input area
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = { Text("Write a message...") },
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp),
                    maxLines = 4,
                    enabled = !isLoading
                )

                IconButton(
                    onClick = {
                        if (input.isNotBlank() && !isLoading) {
                            isLoading = true
                            val id = "m_${System.currentTimeMillis()}"
                            val newMsg = ChatMessage(
                                id = id,
                                text = input.trim(),
                                isMe = true,
                                state = MessageState.PENDING
                            )
                            messages = listOf(newMsg) + messages
                            input = ""

                            // Send via native encryption
                            coroutineScope.launch {
                                try {
                                    if (carrierClient != null) {
                                        // Create session if needed
                                        carrierClient.createSession(currentRecipient)
                                        
                                        // Send encrypted message
                                        val success = carrierClient.sendMessage(
                                            currentRecipient,
                                            newMsg.text
                                        )

                                        // Update message state
                                        messages = messages.map {
                                            if (it.id == id) {
                                                it.copy(
                                                    state = if (success) MessageState.SENT else MessageState.FAILED
                                                )
                                            } else it
                                        }
                                    } else {
                                        // Fallback: just mark as sent without native send
                                        messages = messages.map {
                                            if (it.id == id) it.copy(state = MessageState.SENT) else it
                                        }
                                    }
                                } catch (e: Exception) {
                                    android.util.Log.e("ChatScreen", "Send error: ${e.message}", e)
                                    messages = messages.map {
                                        if (it.id == id) it.copy(state = MessageState.FAILED) else it
                                    }
                                } finally {
                                    isLoading = false
                                    coroutineScope.launch { listState.animateScrollToItem(0) }
                                }
                            }
                        }
                    },
                    enabled = input.isNotBlank() && !isLoading
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Default.Send,
                        contentDescription = "Send",
                        tint = if (input.isNotBlank() && !isLoading) BrandBlue else Color.LightGray
                    )
                }
            }
        }

        // Recipient picker dialog
        if (showRecipientPicker) {
            // Load contacts when permission is granted
            val context = LocalContext.current
            val contactsState = produceState(initialValue = emptyList<ContactInfo>(), key1 = readContactsGranted) {
                if (readContactsGranted) {
                    value = loadContacts(context)
                }
            }

            RecipientPickerDialog(
                currentRecipient = currentRecipient,
                contacts = contactsState.value,
                readContactsGranted = readContactsGranted,
                onRequestContactsPermission = onRequestContactsPermission,
                onRecipientSelected = { recipient ->
                    currentRecipient = recipient
                    showRecipientPicker = false
                },
                onDismiss = { showRecipientPicker = false }
            )
        }
    }
}

@Composable
fun MessageBubbleWithState(msg: ChatMessage) {
    val alignment = if (msg.isMe) Alignment.End else Alignment.Start
    val bubbleColor = if (msg.isMe) BrandBlue else Color.White
    val textColor = if (msg.isMe) Color.White else TextPrimary
    val shape = RoundedCornerShape(16.dp)

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (msg.isMe) Arrangement.End else Arrangement.Start
    ) {
        Box(
            modifier = Modifier
                .widthIn(max = 260.dp)
                .clip(shape)
                .background(bubbleColor)
                .padding(12.dp)
        ) {
            Column {
                Text(
                    text = msg.text,
                    color = textColor,
                    style = TextStyle(fontSize = 16.sp)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = formatTime(msg.time),
                        color = TextSecondary,
                        style = TextStyle(fontSize = 10.sp)
                    )
                    // State indicator (only show for sent messages)
                    if (msg.isMe) {
                        when (msg.state) {
                            MessageState.PENDING -> Icon(
                                Icons.Default.Check,
                                contentDescription = "Pending",
                                modifier = Modifier.size(12.dp),
                                tint = Color.Gray
                            )
                            MessageState.SENT -> Icon(
                                Icons.Default.Done,
                                contentDescription = "Sent",
                                modifier = Modifier.size(12.dp),
                                tint = Color.White.copy(alpha = 0.7f)
                            )
                            MessageState.DELIVERED -> Icon(
                                Icons.Default.Check,
                                contentDescription = "Delivered",
                                modifier = Modifier.size(12.dp),
                                tint = Color.White
                            )
                            MessageState.FAILED -> Icon(
                                Icons.Default.Close,
                                contentDescription = "Failed",
                                modifier = Modifier.size(12.dp),
                                tint = Color(0xFFFF6B6B)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun RecipientPickerDialog(
    currentRecipient: String,
    onRecipientSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    // Legacy stub — this compose function is now replaced below by an overload.
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Select Recipient") },
        text = { Text("No contacts available") },
        confirmButton = {
            Button(onClick = onDismiss) { Text("Done") }
        }
    )
}

data class ContactInfo(val id: String, val name: String, val phone: String)

@Composable
fun RecipientPickerDialog(
    currentRecipient: String,
    contacts: List<ContactInfo>,
    readContactsGranted: Boolean,
    onRequestContactsPermission: () -> Unit,
    onRecipientSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Select Recipient") },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                if (!readContactsGranted) {
                    Text("This app needs access to your contacts to select real recipients.")
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = onRequestContactsPermission) { Text("Grant contacts access") }
                } else if (contacts.isEmpty()) {
                    Text("No contacts found on device.")
                } else {
                    contacts.forEach { contact ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val recipientId = contact.phone
                            RadioButton(
                                selected = recipientId == currentRecipient,
                                onClick = { onRecipientSelected(recipientId) }
                            )
                            Column(modifier = Modifier.padding(start = 8.dp)) {
                                Text(contact.name)
                                Text(contact.phone, style = TextStyle(fontSize = 12.sp), color = TextSecondary)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) { Text("Done") }
        }
    )
}

private fun loadContacts(context: Context): List<ContactInfo> {
    val resolver = context.contentResolver
    val uri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI
    val projection = arrayOf(
        ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
        ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
        ContactsContract.CommonDataKinds.Phone.NUMBER
    )

    val results = mutableListOf<ContactInfo>()
    val seen = mutableSetOf<String>()

    val cursor = resolver.query(uri, projection, null, null, "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} ASC")
    cursor?.use {
        val idIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.CONTACT_ID)
        val nameIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
        val numIdx = it.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)

        while (it.moveToNext()) {
            val id = if (idIdx >= 0) it.getString(idIdx) ?: "" else ""
            val name = if (nameIdx >= 0) it.getString(nameIdx) ?: "" else ""
            val rawNumber = if (numIdx >= 0) it.getString(numIdx) ?: "" else ""
            val number = rawNumber.replace(Regex("\\s+"), "")

            if (number.isNotBlank() && number !in seen) {
                seen.add(number)
                results.add(ContactInfo(id = id, name = name.ifBlank { number }, phone = number))
            }
        }
    }

    return results
}

private fun formatTime(ms: Long): String {
    val totalSecs = ms / 1000
    val minutes = (totalSecs / 60) % 60
    val hours = (totalSecs / 3600) % 24
    return String.format("%02d:%02d", hours, minutes)
}

private fun sampleMessages(): List<ChatMessage> {
    return listOf(
        ChatMessage(
            id = "1",
            text = "Welcome to CarrierBridge! E2EE messaging.",
            isMe = false,
            state = MessageState.DELIVERED
        ),
        ChatMessage(
            id = "2",
            text = "All messages encrypted end-to-end. Tap the icon above to change recipient.",
            isMe = false,
            state = MessageState.DELIVERED
        )
    )
}
