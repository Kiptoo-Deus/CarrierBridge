package com.example.carrierbridge_android.ui.auth

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.carrierbridge_android.data.AuthRepository
import kotlinx.coroutines.launch

enum class EmailSignupStep {
    ENTER_EMAIL,
    VERIFY_TOKEN
}

data class EmailSignupState(
    val email: String = "",
    val displayName: String = "",
    val verificationToken: String = "",
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val step: EmailSignupStep = EmailSignupStep.ENTER_EMAIL
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmailSignupScreen(
    onSignupSuccess: (userId: String, email: String) -> Unit = { _, _ -> },
    onBackToStart: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val authRepository = remember { AuthRepository(context) }
    var state by remember { mutableStateOf(EmailSignupState()) }
    val coroutineScope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Email Signup") },
                navigationIcon = {
                    IconButton(onClick = onBackToStart) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        },
        modifier = modifier.fillMaxSize()
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Top
        ) {

            StepIndicator(
                step = state.step,
                totalSteps = 2,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 32.dp)
            )

            when (state.step) {
                EmailSignupStep.ENTER_EMAIL -> {
                    EmailInputSection(
                        email = state.email,
                        displayName = state.displayName,
                        isLoading = state.isLoading,
                        errorMessage = state.errorMessage,
                        onEmailChanged = { state = state.copy(email = it) },
                        onDisplayNameChanged = { state = state.copy(displayName = it) },
                        onContinue = {
                            if (isValidEmail(state.email) && state.displayName.isNotBlank()) {
                                state = state.copy(
                                    isLoading = true,
                                    errorMessage = null
                                )

                                coroutineScope.launch {

                                    val result = authRepository.registerEmail(state.email, state.displayName)
                                    result.onSuccess {
                                        state = state.copy(
                                            isLoading = false,
                                            step = EmailSignupStep.VERIFY_TOKEN
                                        )
                                    }
                                    result.onFailure {
                                        state = state.copy(
                                            isLoading = false,
                                            errorMessage = it.message ?: "Failed to send email"
                                        )
                                    }
                                }
                            } else {
                                state = state.copy(
                                    errorMessage = when {
                                        state.email.isBlank() -> "Email is required"
                                        !isValidEmail(state.email) -> "Invalid email format"
                                        state.displayName.isBlank() -> "Display name is required"
                                        else -> "Invalid input"
                                    }
                                )
                            }
                        }
                    )
                }

                EmailSignupStep.VERIFY_TOKEN -> {
                    VerificationTokenSection(
                        verificationToken = state.verificationToken,
                        isLoading = state.isLoading,
                        errorMessage = state.errorMessage,
                        onTokenChanged = { state = state.copy(verificationToken = it) },
                        onVerify = {
                            if (state.verificationToken.length >= 6) {
                                state = state.copy(
                                    isLoading = true,
                                    errorMessage = null
                                )

                                coroutineScope.launch {

                                    val result = authRepository.verifyEmailToken(state.email, state.verificationToken, state.displayName)
                                    result.onSuccess { authResponse ->
                                        state = state.copy(isLoading = false)
                                        onSignupSuccess(authResponse.userId, authResponse.email ?: state.email)
                                    }
                                    result.onFailure {
                                        state = state.copy(
                                            isLoading = false,
                                            errorMessage = it.message ?: "Email verification failed"
                                        )
                                    }
                                }
                            } else {
                                state = state.copy(
                                    errorMessage = "Verification token must be at least 6 characters"
                                )
                            }
                        },
                        onBackToEmail = {
                            state = state.copy(
                                step = EmailSignupStep.ENTER_EMAIL,
                                errorMessage = null
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun EmailInputSection(
    email: String,
    displayName: String,
    isLoading: Boolean,
    errorMessage: String?,
    onEmailChanged: (String) -> Unit,
    onDisplayNameChanged: (String) -> Unit,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Enter your email address",
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
            color = Color.Black,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        OutlinedTextField(
            value = email,
            onValueChange = onEmailChanged,
            label = { Text("Email Address") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            isError = errorMessage != null && (email.isBlank() || !isValidEmail(email))
        )

        OutlinedTextField(
            value = displayName,
            onValueChange = onDisplayNameChanged,
            label = { Text("Display Name") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            isError = errorMessage != null && displayName.isBlank()
        )

        if (errorMessage != null) {
            Text(
                errorMessage,
                color = Color.Red,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onContinue,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            enabled = !isLoading
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
    }
}

@Composable
private fun VerificationTokenSection(
    verificationToken: String,
    isLoading: Boolean,
    errorMessage: String?,
    onTokenChanged: (String) -> Unit,
    onVerify: () -> Unit,
    onBackToEmail: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            "Enter verification token",
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
            color = Color.Black,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Text(
            "A verification link has been sent to your email. Enter the token from the link:",
            fontSize = 14.sp,
            color = Color.Gray,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        OutlinedTextField(
            value = verificationToken,
            onValueChange = onTokenChanged,
            label = { Text("Verification Token") },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            singleLine = true,
            isError = errorMessage != null && verificationToken.length < 6
        )

        if (errorMessage != null) {
            Text(
                errorMessage,
                color = Color.Red,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = onVerify,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            enabled = !isLoading
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            } else {
                Text("Verify Email")
            }
        }

        TextButton(
            onClick = onBackToEmail,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Back to Email")
        }
    }
}

@Composable
private fun StepIndicator(
    step: EmailSignupStep,
    totalSteps: Int,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        repeat(totalSteps) { index ->
            val isActive = index < (if (step == EmailSignupStep.ENTER_EMAIL) 1 else 2)
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(4.dp)
                    .background(
                        color = if (isActive) Color(0xFF0066FF) else Color.LightGray,
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(2.dp)
                    )
            )
        }
    }
}

private fun isValidEmail(email: String): Boolean {
    return email.contains("@") && email.contains(".") && email.length > 5
}
