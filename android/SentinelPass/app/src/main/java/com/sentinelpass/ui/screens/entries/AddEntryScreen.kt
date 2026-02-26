package com.sentinelpass.ui.screens.entries

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.sentinelpass.PasswordAnalysis
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.launch

/**
 * Add Entry Screen - Add a new password entry
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddEntryScreen(
    vaultState: VaultState,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    val uiState by vaultState.uiState.collectAsState()

    var title by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var showGenerator by remember { mutableStateOf(false) }
    var passwordStrength by remember { mutableStateOf<PasswordAnalysis?>(null) }

    LaunchedEffect(password) {
        if (password.isNotEmpty()) {
            passwordStrength = vaultState.checkPasswordStrength(password)
        } else {
            passwordStrength = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add Entry") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            scope.launch {
                                vaultState.addEntry(title, username, password, url, notes)
                                if (uiState.error == null) {
                                    onBack()
                                }
                            }
                        },
                        enabled = title.isNotEmpty() && username.isNotEmpty() && password.isNotEmpty() && !uiState.isLoading
                    ) {
                        Text("Save")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Title
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Title") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = !uiState.isLoading
            )

            // Username
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username / Email") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = {
                    Icon(Icons.Default.Person, contentDescription = null)
                },
                enabled = !uiState.isLoading
            )

            // Password
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = {
                    Icon(Icons.Default.Lock, contentDescription = null)
                },
                trailingIcon = {
                    Row {
                        IconButton(onClick = { showPassword = !showPassword }) {
                            Icon(
                                if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = if (showPassword) "Hide password" else "Show password"
                            )
                        }
                        IconButton(onClick = { showGenerator = true }) {
                            Icon(Icons.Default.Casino, contentDescription = "Generate")
                        }
                    }
                },
                enabled = !uiState.isLoading
            )

            // Password Strength
            if (passwordStrength != null) {
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
                                        .drawBehind {
                                            val color = if (active) {
                                                when (passwordStrength?.score ?: 0) {
                                                    0, 1 -> Color.Red
                                                    2 -> Color(0xFFFFA500)
                                                    3 -> Color(0xFFFFFF00)
                                                    else -> Color(0xFF00FF00)
                                                }
                                            } else {
                                                Color.Gray.copy(alpha = 0.3f)
                                            }
                                            drawRect(color)
                                        }
                                )
                            }
                        }
                        Text(
                            text = passwordStrength?.strengthText ?: "",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            // URL
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("Website URL") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = {
                    Icon(Icons.Default.Public, contentDescription = null)
                },
                enabled = !uiState.isLoading
            )

            // Notes
            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Notes") },
                minLines = 3,
                maxLines = 6,
                modifier = Modifier.fillMaxWidth(),
                leadingIcon = {
                    Icon(Icons.Default.Notes, contentDescription = null)
                },
                enabled = !uiState.isLoading
            )

            // Error message
            if (uiState.error != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(
                        text = uiState.error ?: "",
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }
    }

    if (showGenerator) {
        PasswordGeneratorDialog(
            onPasswordGenerated = { generatedPassword ->
                password = generatedPassword
                showGenerator = false
            },
            onDismiss = { showGenerator = false }
        )
    }
}

@Composable
fun PasswordGeneratorDialog(
    vaultState: VaultState = VaultState.current,
    onPasswordGenerated: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var length by remember { mutableStateOf(20) }
    var includeSymbols by remember { mutableStateOf(true) }
    var generatedPassword by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    suspend fun generatePassword() {
        vaultState.generatePassword(length, includeSymbols)?.let {
            generatedPassword = it
        }
    }

    LaunchedEffect(Unit) {
        generatePassword()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate Password") },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Generated password display
                OutlinedTextField(
                    value = generatedPassword,
                    onValueChange = {},
                    readOnly = true,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                // Length slider
                Column {
                    Text("Length: $length")
                    Slider(
                        value = length.toFloat(),
                        onValueChange = { length = it.toInt() },
                        valueRange = 8f..64f,
                        steps = 56
                    )
                }

                // Include symbols toggle
                Row(
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Include symbols")
                    Switch(
                        checked = includeSymbols,
                        onCheckedChange = { includeSymbols = it }
                    )
                }

                // Regenerate button
                OutlinedButton(
                    onClick = {
                        scope.launch { generatePassword() }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Casino, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Regenerate")
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onPasswordGenerated(generatedPassword) }
            ) {
                Text("Use Password")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}
