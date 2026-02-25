package com.sentinelpass.ui.screens.entries

import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sentinelpass.EntrySummary
import com.sentinelpass.data.VaultState

/**
 * Entries List Screen - Display all password entries
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntriesListScreen(
    vaultState: VaultState,
    onEntryClick: (String) -> Unit,
    onAddEntry: () -> Unit,
    modifier: Modifier = Modifier
) {
    val entries by vaultState.entries.collectAsState()
    var searchText by remember { mutableStateOf("") }
    var searchResults by remember { mutableStateOf<List<EntrySummary>>(emptyList()) }
    var isSearching by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Search functionality
    LaunchedEffect(searchText) {
        if (searchText.isNotEmpty()) {
            isSearching = true
            searchResults = vaultState.searchEntries(searchText)
            isSearching = false
        } else {
            searchResults = emptyList()
        }
    }

    val displayEntries = if (searchText.isNotEmpty()) searchResults else entries

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Passwords") },
                actions = {
                    IconButton(onClick = onAddEntry) {
                        Icon(Icons.Default.Add, contentDescription = "Add Entry")
                    }
                }
            )
        }
    ) { padding ->
        if (displayEntries.isEmpty()) {
            // Empty state
            Box(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Key,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = if (searchText.isNotEmpty()) "No entries found" else "No passwords yet",
                        style = MaterialTheme.typography.titleLarge
                    )
                    Text(
                        text = if (searchText.isNotEmpty()) "Try a different search term" else "Tap the + button to add your first password",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (searchText.isEmpty()) {
                        FilledTonalButton(onClick = onAddEntry) {
                            Text("Add Entry")
                        }
                    }
                }
            }
        } else {
            Column(
                modifier = modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                // Search bar
                OutlinedTextField(
                    value = searchText,
                    onValueChange = { searchText = it },
                    label = { Text("Search entries...") },
                    leadingIcon = {
                        Icon(Icons.Default.Search, contentDescription = null)
                    },
                    trailingIcon = {
                        if (searchText.isNotEmpty()) {
                            IconButton(onClick = { searchText = "" }) {
                                Icon(Icons.Default.Clear, contentDescription = "Clear")
                            }
                        }
                    },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                )

                // Entries list
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Favorites first
                    val favorites = displayEntries.filter { it.favorite }
                    val others = displayEntries.filter { !it.favorite }

                    if (favorites.isNotEmpty()) {
                        item {
                            Text(
                                text = "Favorites",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                        }
                        items(favorites, key = { it.id }) { entry ->
                            EntryListItem(
                                entry = entry,
                                onClick = { onEntryClick(entry.id) },
                                onDelete = {
                                    // Show confirmation dialog
                                }
                            )
                        }
                    }

                    if (others.isNotEmpty()) {
                        if (favorites.isNotEmpty()) {
                            item {
                                Text(
                                    text = "All Entries",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(vertical = 8.dp)
                                )
                            }
                        }
                        items(others, key = { it.id }) { entry ->
                            EntryListItem(
                                entry = entry,
                                onClick = { onEntryClick(entry.id) },
                                onDelete = {
                                    // Show confirmation dialog
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun EntryListItem(
    entry: EntrySummary,
    onClick: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showDeleteDialog by remember { mutableStateOf(false) }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete Entry") },
            text = { Text("Are you sure you want to delete \"${entry.title}\"?") },
            confirmButton = {
                TextButton(onClick = {
                    onDelete()
                    showDeleteDialog = false
                }) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
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
                    .clip(CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Key,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.primary
                )
            }

            // Title and Username
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = entry.title,
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (entry.favorite) {
                        Icon(
                            imageVector = Icons.Default.Star,
                            contentDescription = "Favorite",
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.tertiary
                        )
                    }
                }
                Text(
                    text = entry.username,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            // Arrow
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
