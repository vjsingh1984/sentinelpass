package com.sentinelpass.ui.screens.entries

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.sentinelpass.Entry
import com.sentinelpass.data.VaultState
import kotlinx.coroutines.launch

/**
 * Entry Detail Screen - View entry details
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryDetailScreen(
    entryId: String,
    vaultState: VaultState,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scope = rememberCoroutineScope()
    var entry by remember { mutableStateOf<Entry?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    var copiedField by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    LaunchedEffect(entryId) {
        entry = vaultState.getEntry(entryId)
        isLoading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(entry?.title ?: "Entry") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onEdit) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit")
                    }
                }
            )
        }
    ) { padding ->
        if (isLoading) {
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator()
            }
        } else if (entry == null) {
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text("Entry not found")
            }
        } else {
            Column(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
            ) {
                // Account Info Card
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "Account",
                            style = MaterialTheme.typography.titleMedium
                        )

                        // Title with favorite
                        DetailRow(
                            label = "Title",
                            value = entry!!.title,
                            trailing = if (entry!!.favorite) {
                                {
                                    Icon(
                                        Icons.Default.Star,
                                        contentDescription = "Favorite",
                                        tint = MaterialTheme.colorScheme.tertiary
                                    )
                                }
                            } else null
                        )

                        DetailRow(
                            label = "Username",
                            value = entry!!.username,
                            canCopy = true,
                            onCopy = { copyToClipboard(context, entry!!.username, "Username") }
                        )
                    }
                }

                // Password Card
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "Password",
                            style = MaterialTheme.typography.titleMedium
                        )

                        DetailRow(
                            label = "Password",
                            value = "••••••••",
                            canCopy = true,
                            showCopyIcon = true,
                            onCopy = { copyToClipboard(context, entry!!.password, "Password") }
                        )
                    }
                }

                // Website Card
                if (!entry!!.url.isNullOrEmpty()) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            Text(
                                text = "Website",
                                style = MaterialTheme.typography.titleMedium
                            )

                            DetailRow(
                                label = "URL",
                                value = entry!!.url ?: "",
                                canCopy = true,
                                onCopy = { copyToClipboard(context, entry!!.url ?: "", "URL") }
                            )
                        }
                    }
                }

                // Notes Card
                if (!entry!!.notes.isNullOrEmpty()) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            Text(
                                text = "Notes",
                                style = MaterialTheme.typography.titleMedium
                            )

                            Text(
                                text = entry!!.notes ?: "",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }

                // Metadata Card
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "Metadata",
                            style = MaterialTheme.typography.titleMedium
                        )

                        entry!!.createdAt?.let {
                            DetailRow(
                                label = "Created",
                                value = it
                            )
                        }

                        entry!!.modifiedAt?.let {
                            DetailRow(
                                label = "Modified",
                                value = it
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }

        // Copy confirmation toast
        if (copiedField != null) {
            Snackbar(
                modifier = Modifier.padding(16.dp)
            ) {
                Text("$copiedField copied!")
            }
            LaunchedEffect(copiedField) {
                kotlinx.coroutines.delay(2000)
                copiedField = null
            }
        }
    }
}

@Composable
fun DetailRow(
    label: String,
    value: String,
    canCopy: Boolean = false,
    showCopyIcon: Boolean = false,
    trailing: @Composable (() -> Unit)? = null,
    onCopy: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodyMedium
            )
        }

        if (trailing != null) {
            trailing()
        }

        if (canCopy && onCopy != null) {
            IconButton(onClick = onCopy) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy",
                    tint = MaterialTheme.colorScheme.primary
                )
            }
        }
    }
}

fun copyToClipboard(context: Context, text: String, fieldName: String): Boolean {
    val clipboardManager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    return clipboardManager?.let {
        val clipData = ClipData.newPlainText(fieldName, text)
        it.setPrimaryClip(clipData)
        true
    } ?: false
}
