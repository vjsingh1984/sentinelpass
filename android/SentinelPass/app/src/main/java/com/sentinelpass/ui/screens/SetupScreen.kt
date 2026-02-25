package com.sentinelpass.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Face
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.sentinelpass.PasswordAnalysis
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.launch

/**
 * Setup Screen - Create new vault
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupScreen(
    vaultState: VaultState = VaultState.current,
    onNavigateToLock: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()
    val uiState by vaultState.uiState.collectAsState()

    var masterPassword by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var passwordStrength by remember { mutableStateOf<PasswordAnalysis?>(null) }
    var passwordMatches by remember { mutableStateOf(false) }

    // Navigate to lock screen after creation
    LaunchedEffect(uiState.hasVault) {
        if (uiState.hasVault) {
            onNavigateToLock()
        }
    }

    // Check password strength
    LaunchedEffect(masterPassword) {
        if (masterPassword.isNotEmpty()) {
            passwordStrength = vaultState.checkPasswordStrength(masterPassword)
            passwordMatches = masterPassword == confirmPassword && confirmPassword.isNotEmpty()
        } else {
            passwordStrength = null
            passwordMatches = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create Your Vault") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            // Logo
            Icon(
                imageVector = Icons.Default.Face,
                contentDescription = null,
                modifier = Modifier.size(100.dp),
                tint = MaterialTheme.colorScheme.primary
            )

            Text(
                text = "Create Your Vault",
                style = MaterialTheme.typography.headlineMedium
            )

            Text(
                text = "Choose a strong master password to protect your credentials",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Master Password Field
            OutlinedTextField(
                value = masterPassword,
                onValueChange = { masterPassword = it },
                label = { Text("Master Password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = !uiState.isLoading
            )

            // Password Strength Indicator
            if (passwordStrength != null) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Strength bars
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        repeat(4) { index ->
                            val active = index < (passwordStrength?.score ?: 0)
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .height(8.dp)
                                    .then(
                                        if (active) {
                                            Modifier.then(
                                                when (passwordStrength?.score ?: 0) {
                                                    0, 1 -> Modifier.background(Color.Red)
                                                    2 -> Modifier.background(Color(0xFFFFA500))
                                                    3 -> Modifier.background(Color(0xFFFFFF00))
                                                    else -> Modifier.background(Color(0xFF00FF00))
                                                }
                                            )
                                        } else {
                                            Modifier.background(Color.Gray.copy(alpha = 0.3f))
                                        }
                                    )
                            )
                        }
                    }

                    Text(
                        text = passwordStrength?.strengthText ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        color = when (passwordStrength?.score ?: 0) {
                            0, 1 -> Color.Red
                            2 -> Color(0xFFFFA500)
                            3 -> Color(0xFFFFFF00)
                            else -> Color(0xFF00FF00)
                        }
                    )
                }
            }

            // Confirm Password Field
            OutlinedTextField(
                value = confirmPassword,
                onValueChange = { confirmPassword = it },
                label = { Text("Confirm Password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                trailingIcon = {
                    if (confirmPassword.isNotEmpty()) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = if (passwordMatches) Color.Green else Color.Gray
                        )
                    }
                },
                enabled = !uiState.isLoading
            )

            // Password Requirements
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Password Requirements:",
                        style = MaterialTheme.typography.titleSmall
                    )
                    PasswordRequirement("At least 12 characters", masterPassword.length >= 12)
                    PasswordRequirement("Contains uppercase letter", masterPassword.any { it.isUpperCase() })
                    PasswordRequirement("Contains lowercase letter", masterPassword.any { it.isLowerCase() })
                    PasswordRequirement("Contains number", masterPassword.any { it.isDigit() })
                    PasswordRequirement("Contains symbol", masterPassword.any { !it.isLetterOrDigit() })
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // Create Button
            Button(
                onClick = {
                    vaultState.createVault(masterPassword)
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = passwordMatches && (passwordStrength?.score ?: 0) >= 3 && !uiState.isLoading
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Create Vault")
                }
            }

            // Error Message
            if (uiState.error != null) {
                Text(
                    text = uiState.error ?: "",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
fun PasswordRequirement(text: String, met: Boolean) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            tint = if (met) Color.Green else Color.Gray,
            modifier = Modifier.size(16.dp)
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = if (met) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
