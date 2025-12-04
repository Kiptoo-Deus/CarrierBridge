package com.example.carrierbridge_android.ui.auth

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class AuthStartStep {
    CHOOSE_METHOD,
    PHONE_SIGNUP,
    EMAIL_SIGNUP
}

@Composable
fun AuthStartScreen(
    onSignupSuccess: (userId: String, contact: String) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier
) {
    var step by remember { mutableStateOf(AuthStartStep.CHOOSE_METHOD) }

    when (step) {
        AuthStartStep.CHOOSE_METHOD -> {
            ChooseSignupMethodScreen(
                onPhoneSignup = { step = AuthStartStep.PHONE_SIGNUP },
                onEmailSignup = { step = AuthStartStep.EMAIL_SIGNUP },
                modifier = modifier
            )
        }

        AuthStartStep.PHONE_SIGNUP -> {
            PhoneSignupScreen(
                onSignupSuccess = onSignupSuccess,
                onBackToStart = { step = AuthStartStep.CHOOSE_METHOD },
                modifier = modifier
            )
        }

        AuthStartStep.EMAIL_SIGNUP -> {
            EmailSignupScreen(
                onSignupSuccess = onSignupSuccess,
                onBackToStart = { step = AuthStartStep.CHOOSE_METHOD },
                modifier = modifier
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChooseSignupMethodScreen(
    onPhoneSignup: () -> Unit = {},
    onEmailSignup: () -> Unit = {},
    modifier: Modifier = Modifier
) {
    Scaffold(
        modifier = modifier.fillMaxSize()
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                "CarrierBridge",
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF0066FF),
                modifier = Modifier.padding(bottom = 48.dp)
            )

            Text(
                "Secure Messaging",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.Black,
                modifier = Modifier.padding(bottom = 32.dp)
            )

            Text(
                "Choose how you'd like to sign up",
                fontSize = 14.sp,
                color = Color.Gray,
                modifier = Modifier.padding(bottom = 48.dp)
            )

            Button(
                onClick = onPhoneSignup,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .padding(bottom = 16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF0066FF)
                )
            ) {
                Text(
                    "Sign up with Phone",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            OutlinedButton(
                onClick = onEmailSignup,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                border = ButtonDefaults.outlinedButtonBorder
            ) {
                Text(
                    "Sign up with Email",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFF0066FF)
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            Text(
                "E2E encrypted messaging\nBased on the Double Ratchet Algorithm",
                fontSize = 12.sp,
                color = Color.Gray,
                modifier = Modifier.padding(top = 24.dp)
            )
        }
    }
}
