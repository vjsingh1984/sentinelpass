package com.sentinelpass.ui.screens.totp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.sentinelpass.EntrySummary
import com.sentinelpass.TotpCode
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * TOTP List Screen - Display TOTP codes with auto-refresh
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TotpListScreen(
    vaultState: VaultState,
    modifier: Modifier = Modifier
) {
    val entries by vaultState.entries.collectAsState()
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    var totpCodes by remember { mutableStateOf<Map<String, TotpCode>>(emptyMap()) }
    var copiedCode by remember { mutableStateOf<String?>(null) }
    var currentTime by remember { mutableStateOf(System.currentTimeMillis()) }

    suspend fun refreshAllCodes() {
        entries.forEach { entry ->
            vaultState.generateTotp(entry.id)?.let { code ->
                totpCodes = totpCodes.toMutableMap().apply { put(entry.id, code) }
            }
        }
    }

    // Refresh timer
    LaunchedEffect(Unit) {
        while (true) {
            currentTime = System.currentTimeMillis()
            val secondsInCycle = (currentTime / 1000 % 30).toInt()
            if (secondsInCycle == 0) {
                // Refresh codes at start of cycle
                refreshAllCodes()
            }
            delay(1000)
        }
    }

    // Load codes on screen appear
    LaunchedEffect(entries) {
        refreshAllCodes()
    }

    val secondsRemaining = 30 - (currentTime / 1000 % 30).toInt()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TOTP Codes") },
                actions = {
                    IconButton(onClick = {
                        scope.launch { refreshAllCodes() }
                    }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                }
            )
        }
    ) { padding ->
        Box(
            modifier = modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            if (totpCodes.isEmpty()) {
                // Empty state
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.AccessTime,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "No TOTP Codes",
                        style = MaterialTheme.typography.titleLarge
                    )
                    Text(
                        text = "Add entries with TOTP secrets to generate verification codes",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Timer indicator
                    item {
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
                                    text = "Refreshing in $secondsRemaining seconds",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                LinearProgressIndicator(
                                    progress = secondsRemaining / 30f,
                                    modifier = Modifier.fillMaxWidth(),
                                    color = when {
                                        secondsRemaining <= 5 -> Color.Red
                                        secondsRemaining <= 10 -> Color(0xFFFFA500)
                                        else -> Color(0xFF00FF00)
                                    }
                                )
                            }
                        }
                    }

                    items(entries.filter { totpCodes.containsKey(it.id) }, key = { it.id }) { entry ->
                        TotpCodeCard(
                            entry = entry,
                            totpCode = totpCodes[entry.id],
                            secondsRemaining = secondsRemaining,
                            onCopy = { code ->
                                copyToClipboard(context, code, "TOTP Code")
                                copiedCode = code
                                scope.launch {
                                    delay(2000)
                                    copiedCode = null
                                }
                            }
                        )
                    }
                }
            }

            // Copy confirmation
            if (copiedCode != null) {
                Snackbar(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(16.dp)
                ) {
                    Text("TOTP code copied!")
                }
            }
        }
    }
}

@Composable
fun TotpCodeCard(
    entry: EntrySummary,
    totpCode: TotpCode?,
    secondsRemaining: Int,
    onCopy: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icon
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.AccessTime,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
            }

            // Title and username
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = entry.title,
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = entry.username,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // TOTP Code
            Column(
                horizontalAlignment = Alignment.End
            ) {
                totpCode?.let { code ->
                    Text(
                        text = formatTotpCode(code.code),
                        style = MaterialTheme.typography.titleLarge,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    )

                    // Progress bar for code validity
                    Box(
                        modifier = Modifier
                            .width(80.dp)
                            .height(4.dp)
                            .background(
                                MaterialTheme.colorScheme.surfaceVariant,
                                CircleShape
                            )
                    ) {
                        Box(
                            modifier = Modifier
                                .width((80.dp * (code.secondsRemaining.toFloat() / 30)))
                                .height(4.dp)
                                .background(
                                    when {
                                        code.secondsRemaining <= 5u -> Color.Red
                                        code.secondsRemaining <= 10u -> Color(0xFFFFA500)
                                        else -> Color(0xFF00FF00)
                                    },
                                    CircleShape
                                )
                            )
                    }

                    Text(
                        text = "${code.secondsRemaining}s",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Copy button
            IconButton(onClick = { onCopy(totpCode?.code ?: "") }) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy"
                )
            }
        }
    }
}

fun formatTotpCode(code: String): String {
    return if (code.length == 6) {
        "${code.substring(0, 3)} ${code.substring(3)}"
    } else {
        code
    }
}

fun copyToClipboard(context: Context, text: String, label: String): Boolean {
    val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    return clipboardManager?.let {
        val clipData = ClipData.newPlainText(label, text)
        it.setPrimaryClip(clipData)
        true
    } ?: false
}
