package com.example.carrierbridge_android.ui.auth

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import com.example.carrierbridge_android.data.AuthRepository
import kotlinx.coroutines.launch

@Composable
fun PhoneSignupScreen(
    onSignupSuccess: (userId: String, token: String) -> Unit,
    onBackToStart: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val authRepository = remember { AuthRepository(context) }
    val coroutineScope = rememberCoroutineScope()
    var phone by remember { mutableStateOf("") }
    var displayName by remember { mutableStateOf("") }
    var step by remember { mutableStateOf(SignupStep.ENTER_PHONE) }
    var otp by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color.White)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "CarrierBridge",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFF0066FF),
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Text(
            "Secure Messaging",
            fontSize = 14.sp,
            color = Color.Gray,
            modifier = Modifier.padding(bottom = 32.dp)
        )

        when (step) {
            SignupStep.ENTER_PHONE -> {
                PhoneInputSection(
                    phone = phone,
                    displayName = displayName,
                    onPhoneChange = { phone = it },
                    onDisplayNameChange = { displayName = it },
                    isLoading = isLoading,
                    errorMessage = errorMessage,
                    onContinue = {
                        isLoading = true
                        errorMessage = null
                        coroutineScope.launch {
                            val result = authRepository.registerPhone(phone, displayName)
                            isLoading = false
                            result.onSuccess {
                                step = SignupStep.VERIFY_OTP
                            }
                            result.onFailure {
                                errorMessage = it.message ?: "Failed to send OTP"
                            }
                        }
                    },
                    onBackClick = onBackToStart
                )
            }
            SignupStep.VERIFY_OTP -> {
                OtpVerifySection(
                    phone = phone,
                    displayName = displayName,
                    otp = otp,
                    onOtpChange = { otp = it },
                    isLoading = isLoading,
                    errorMessage = errorMessage,
                    onVerify = {
                        isLoading = true
                        errorMessage = null
                        coroutineScope.launch {
                            val result = authRepository.verifyPhoneOtp(phone, otp, displayName)
                            isLoading = false
                            result.onSuccess { authResponse ->
                                onSignupSuccess(authResponse.userId, authResponse.authToken)
                            }
                            result.onFailure {
                                errorMessage = it.message ?: "OTP verification failed"
                            }
                        }
                    },
                    onBackClick = { step = SignupStep.ENTER_PHONE }
                )
            }
        }
    }
}

@Composable
private fun PhoneInputSection(
    phone: String,
    displayName: String,
    onPhoneChange: (String) -> Unit,
    onDisplayNameChange: (String) -> Unit,
    isLoading: Boolean,
    errorMessage: String?,
    onContinue: () -> Unit,
    onBackClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            "Sign up with your phone number",
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(bottom = 24.dp)
        )

        OutlinedTextField(
            value = phone,
            onValueChange = onPhoneChange,
            label = { Text("Phone number") },
            placeholder = { Text("+1 (555) 123-4567") },
            leadingIcon = {
                Icon(Icons.Default.Phone, contentDescription = null)
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            enabled = !isLoading
        )

        OutlinedTextField(
            value = displayName,
            onValueChange = onDisplayNameChange,
            label = { Text("Display name (optional)") },
            placeholder = { Text("Your name") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            enabled = !isLoading
        )

        if (errorMessage != null) {
            Text(
                errorMessage,
                color = Color.Red,
                fontSize = 12.sp,
                modifier = Modifier
                    .padding(12.dp)
                    .fillMaxWidth()
            )
        }

        Button(
            onClick = onContinue,
            enabled = phone.isNotEmpty() && !isLoading,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            } else {
                Text("Continue")
            }
        }

        TextButton(
            onClick = onBackClick,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text("Back")
        }
    }
}

@Composable
@Composable
private fun OtpVerifySection(
    phone: String,
    displayName: String,
    otp: String,
    onOtpChange: (String) -> Unit,
    isLoading: Boolean,
    errorMessage: String?,
    onVerify: () -> Unit,
    onBackClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            "Enter the code we sent to",
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Text(
            phone,
            fontSize = 14.sp,
            color = Color.Gray,
            modifier = Modifier.padding(bottom = 24.dp)
        )

        OutlinedTextField(
            value = otp,
            onValueChange = { onOtpChange(it.take(6)) },
            label = { Text("6-digit code") },
            placeholder = { Text("000000") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 12.dp),
            enabled = !isLoading
        )

        if (errorMessage != null) {
            Text(
                errorMessage,
                color = Color.Red,
                fontSize = 12.sp,
                modifier = Modifier
                    .padding(12.dp)
                    .fillMaxWidth()
            )
        }

        Button(
            onClick = onVerify,
            enabled = otp.length == 6 && !isLoading,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            } else {
                Text("Verify")
            }
        }

        TextButton(
            onClick = onBackClick,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text("Back")
        }
    }
}

enum class SignupStep {
    ENTER_PHONE,
    VERIFY_OTP
}
