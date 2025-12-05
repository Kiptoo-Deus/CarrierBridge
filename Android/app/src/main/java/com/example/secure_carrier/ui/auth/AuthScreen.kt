package com.example.secure_carrier.ui.auth

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@Composable
fun AuthScreen(viewModel: AuthViewModel, onAuthSuccess: () -> Unit) {
    val ctx = LocalContext.current
    Column(modifier = Modifier.padding(16.dp)) {
        OutlinedTextField(value = viewModel.phone, onValueChange = { viewModel.phone = it }, label = { Text("Phone") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = viewModel.displayName, onValueChange = { viewModel.displayName = it }, label = { Text("Display name") }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        Button(onClick = { viewModel.requestOtp() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Request OTP")
        }
        OutlinedTextField(value = viewModel.otp, onValueChange = { viewModel.otp = it }, label = { Text("OTP (auto-filled after request)") }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        Button(onClick = {
            viewModel.verifyOtp { userId, token ->
                saveAuth(ctx, userId, token)
                onAuthSuccess()
            }
        }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Verify OTP")
        }
        val status = viewModel.status
        if (status != null) {
            Text(text = status, modifier = Modifier.padding(top = 8.dp))
        }
    }
}

fun saveAuth(ctx: Context, userId: String, token: String) {
    val prefs = ctx.getSharedPreferences("secure_carrier", Context.MODE_PRIVATE)
    prefs.edit().putString("auth_token", token).putString("user_id", userId).apply()
}
