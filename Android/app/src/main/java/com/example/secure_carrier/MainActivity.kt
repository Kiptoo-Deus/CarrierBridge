package com.example.secure_carrier

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.example.secure_carrier.ui.auth.AuthScreen
import com.example.secure_carrier.ui.chat.ChatScreen
import com.example.secure_carrier.ui.theme.Secure_CarrierTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Secure_CarrierTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    val navController = rememberNavController()
                    NavHost(navController = navController, startDestination = "auth") {
                        composable("auth") {
                            val vm: com.example.secure_carrier.ui.auth.AuthViewModel = viewModel()
                            AuthScreen(viewModel = vm, onAuthSuccess = { navController.navigate("chat") })
                        }
                        composable("chat") {
                            val vm: com.example.secure_carrier.ui.auth.AuthViewModel = viewModel()
                            ChatScreen(authViewModel = vm)
                        }
                    }
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun PreviewMain() {
    Secure_CarrierTheme {
        GreetingPreview()
    }
}

@Composable
fun GreetingPreview() {}