package com.sentinelpass

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.sentinelpass.ui.screens.LockScreen
import com.sentinelpass.ui.screens.SetupScreen
import com.sentinelpass.ui.screens.MainScreen
import com.sentinelpass.ui.theme.SentinelPassTheme
import com.sentinelpass.data.VaultState

/**
 * Main Activity for SentinelPass
 * Handles navigation between lock/setup/main screens
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SentinelPassTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SentinelPassApp()
                }
            }
        }
    }
}

@Composable
fun SentinelPassApp(
    vaultState: VaultState = VaultState.current,
    navController: NavHostController = rememberNavController()
) {
    val uiState by vaultState.uiState.collectAsState()

    NavHost(
        navController = navController,
        startDestination = when {
            !uiState.hasVault -> "setup"
            !uiState.isUnlocked -> "lock"
            else -> "main"
        }
    ) {
        composable("setup") {
            SetupScreen(
                vaultState = vaultState,
                onNavigateToLock = {
                    navController.navigate("lock") {
                        popUpTo("setup") { inclusive = true }
                    }
                }
            )
        }

        composable("lock") {
            LockScreen(
                onUnlockSuccess = {
                    navController.navigate("main") {
                        popUpTo("lock") { inclusive = true }
                    }
                }
            )
        }

        composable("main") {
            MainScreen(
                onLock = {
                    vaultState.lockVault()
                    navController.navigate("lock") {
                        popUpTo("main") { inclusive = true }
                    }
                }
            )
        }
    }
}
