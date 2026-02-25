package com.sentinelpass.ui.screens.generator

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentinelpass.PasswordAnalysis
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.launch

/**
 * Password Generator Screen
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorScreen(
    vaultState: VaultState = VaultState.current,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var generatedPassword by remember { mutableStateOf("") }
    var length by remember { mutableStateOf(20) }
    var includeSymbols by remember { mutableStateOf(true) }
    var passwordStrength by remember { mutableStateOf<PasswordAnalysis?>(null) }
    var copied by remember { mutableStateOf(false) }

    suspend fun generatePassword() {
        vaultState.generatePassword(length, includeSymbols)?.let {
            generatedPassword = it
            passwordStrength = vaultState.checkPasswordStrength(it)
        }
    }

    LaunchedEffect(Unit) {
        generatePassword()
    }

    fun copyPassword() {
        val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        clipboardManager?.let {
            val clipData = ClipData.newPlainText("Password", generatedPassword)
            it.setPrimaryClip(clipData)
            copied = true
            scope.launch {
                kotlinx.coroutines.delay(2000)
                copied = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Generate Password") }
            )
        }
    ) { padding ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Generated Password Display
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        text = if (generatedPassword.isEmpty()) "Tap Generate to create a password" else generatedPassword,
                        style = MaterialTheme.typography.headlineSmall,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = if (generatedPassword.isEmpty()) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        }
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        FilledTonalButton(
                            onClick = {
                                scope.launch { generatePassword() }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Casino, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Generate")
                        }

                        if (generatedPassword.isNotEmpty()) {
                            OutlinedButton(
                                onClick = { copyPassword() },
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    if (copied) Icons.Default.Check else Icons.Default.ContentCopy,
                                    contentDescription = null
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(if (copied) "Copied!" else "Copy")
                            }
                        }
                    }
                }
            }

            // Password Strength
            if (passwordStrength != null) {
                Card(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "Password Strength",
                            style = MaterialTheme.typography.titleMedium
                        )

                        // Strength bars
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            repeat(4) { index ->
                                val active = index < (passwordStrength?.score ?: 0)
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(12.dp)
                                        .clip(CircleShape)
                                        .background(
                                            if (active) {
                                                when (passwordStrength?.score ?: 0) {
                                                    0, 1 -> Color.Red
                                                    2 -> Color(0xFFFFA500)
                                                    3 -> Color(0xFFFFFF00)
                                                    else -> Color(0xFF00FF00)
                                                }
                                            } else {
                                                MaterialTheme.colorScheme.surfaceVariant
                                            }
                                        )
                                )
                            }
                        }

                        Text(
                            text = passwordStrength?.strengthText ?: "",
                            style = MaterialTheme.typography.bodyLarge,
                            color = when (passwordStrength?.score ?: 0) {
                                0, 1 -> Color.Red
                                2 -> Color(0xFFFFA500)
                                3 -> Color(0xFFFFFF00)
                                else -> Color(0xFF00FF00)
                            }
                        )
                    }
                }
            }

            // Options
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        text = "Options",
                        style = MaterialTheme.typography.titleMedium
                    )

                    // Length Slider
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("Length")
                            Text(
                                text = "$length",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }

                        Slider(
                            value = length.toFloat(),
                            onValueChange = {
                                length = it.toInt()
                                scope.launch { generatePassword() }
                            },
                            valueRange = 8f..64f,
                            steps = 56
                        )
                    }

                    Divider()

                    // Include Symbols Toggle
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Include Symbols")
                                Text(
                                    text = "!@#$%^&*()",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = includeSymbols,
                                onCheckedChange = {
                                    includeSymbols = it
                                    scope.launch { generatePassword() }
                                }
                            )
                        }
                    }
                }
            }

            // Info Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    Column(
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = "Security Tip",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        Text(
                            text = "Use longer passwords for better security. 20+ characters is recommended.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                }
            }
        }
    }
}
