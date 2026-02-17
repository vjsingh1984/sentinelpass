/**
 * SentinelPass Desktop UI — entry CRUD & list management.
 *
 * Handles loading, creating, saving, deleting, filtering, and rendering
 * vault entries.  All backend calls go through the Tauri `invoke` bridge.
 */
import { invoke, confirm, currentEntry, setCurrentEntry, entries, setEntries, setCurrentTotpMetadata, currentFilter, entriesRefreshInFlight, setEntriesRefreshInFlight, vaultScreen, entryList, searchInput, noSelection, entryDetail } from './state.js';
import { showToast, escapeHtml, formatDate } from './utils.js';
import { updateTotpAvailability, setTotpButtonState } from './totp.js';
/**
 * Load all vault entries from the backend, preserving the current selection.
 *
 * Convenience wrapper around {@link loadEntriesWithOptions} with default
 * options.
 */
export async function loadEntries() {
    return loadEntriesWithOptions({
        preserveSelection: true,
        silent: false,
        selectionMissingToast: false
    });
}
/**
 * Filter the in-memory entry list by the active filter ("all" or "favorites")
 * and the search query, then render the result.
 */
export function applyEntryFilters() {
    let filtered = [...entries];
    if (currentFilter === 'favorites') {
        filtered = filtered.filter(entry => entry.favorite);
    }
    const query = (searchInput?.value || '').trim().toLowerCase();
    if (query) {
        filtered = filtered.filter(entry => entry.title.toLowerCase().includes(query) ||
            entry.username.toLowerCase().includes(query));
    }
    renderEntryList(filtered);
}
/**
 * Core entry-loading routine with fine-grained control over behaviour.
 *
 * Guards against concurrent refreshes via the `entriesRefreshInFlight` flag.
 *
 * @param options
 * @param options.preserveSelection - Keep the currently-selected entry
 *   highlighted if it still exists after reload (default `true`).
 * @param options.silent - Suppress error toasts on failure (default `false`).
 * @param options.selectionMissingToast - Show a warning toast when the
 *   previously-selected entry no longer exists (default `false`).
 */
export async function loadEntriesWithOptions({ preserveSelection = true, silent = false, selectionMissingToast = false } = {}) {
    if (entriesRefreshInFlight) {
        return;
    }
    setEntriesRefreshInFlight(true);
    try {
        const selectedEntryId = preserveSelection ? currentEntry?.entry_id : null;
        setEntries(await invoke('list_entries'));
        if (selectedEntryId && !entries.some(entry => entry.entry_id === selectedEntryId)) {
            setCurrentEntry(null);
            setCurrentTotpMetadata(null);
            setTotpButtonState(false, false);
            noSelection.classList.remove('hidden');
            entryDetail.classList.add('hidden');
            if (selectionMissingToast) {
                showToast('Selected entry is no longer available', 'warning');
            }
        }
        applyEntryFilters();
        document.getElementById('entry-count').textContent = `${entries.length} entries`;
    }
    catch (error) {
        if (!silent) {
            showToast(error, 'error');
        }
    }
    finally {
        setEntriesRefreshInFlight(false);
    }
}
/**
 * Silently refresh the entry list in the background when the vault screen
 * is visible.  Called on a 10-second interval and on window-focus events.
 */
export async function backgroundRefreshEntries() {
    if (vaultScreen.classList.contains('hidden')) {
        return;
    }
    await loadEntriesWithOptions({
        preserveSelection: true,
        silent: true,
        selectionMissingToast: false
    });
}
/**
 * User-initiated manual refresh of the entry list with loading-spinner
 * feedback on the refresh button and a success toast.
 */
export async function refreshEntriesNow() {
    if (vaultScreen.classList.contains('hidden')) {
        return;
    }
    const refreshBtn = document.getElementById('refresh-entries-btn');
    if (refreshBtn) {
        refreshBtn.classList.add('loading');
        refreshBtn.disabled = true;
    }
    try {
        await loadEntriesWithOptions({
            preserveSelection: true,
            silent: false,
            selectionMissingToast: true
        });
        showToast('Entries refreshed', 'success');
    }
    finally {
        if (refreshBtn) {
            refreshBtn.classList.remove('loading');
            refreshBtn.disabled = false;
        }
    }
}
/**
 * Render a list of entries into the sidebar DOM and attach click handlers
 * that load the selected entry into the detail pane.
 *
 * @param filteredEntries - The entries to display, or `null` to use the
 *   full unfiltered list.
 */
export function renderEntryList(filteredEntries = null) {
    const listToRender = filteredEntries || entries;
    if (listToRender.length === 0) {
        entryList.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--color-text-muted)">No entries found</div>';
        return;
    }
    entryList.innerHTML = listToRender.map(entry => `
        <div class="entry-item ${currentEntry?.entry_id === entry.entry_id ? 'active' : ''}" data-id="${entry.entry_id}">
            <div class="entry-item-title">${escapeHtml(entry.title)}</div>
            <div class="entry-item-username">${escapeHtml(entry.username)}</div>
        </div>
    `).join('');
    // Add click listeners
    document.querySelectorAll('.entry-item').forEach(item => {
        item.addEventListener('click', () => loadEntry(parseInt(item.dataset.id)));
    });
}
/**
 * Fetch a single entry by ID from the backend and populate the detail pane.
 *
 * Updates the sidebar active state, fills the form fields (title, username,
 * password, URL, notes), refreshes favourite state, metadata timestamps, and
 * TOTP availability.
 *
 * @param entryId - The numeric entry ID to load.
 */
export async function loadEntry(entryId) {
    try {
        const entry = await invoke('get_entry', { entryId });
        setCurrentEntry(entry);
        // Update active state in list
        document.querySelectorAll('.entry-item').forEach(item => {
            item.classList.toggle('active', parseInt(item.dataset.id) === entryId);
        });
        // Show entry detail
        noSelection.classList.add('hidden');
        entryDetail.classList.remove('hidden');
        // Populate form
        document.getElementById('detail-title').value = entry.title;
        document.getElementById('detail-username').value = entry.username;
        document.getElementById('detail-password').value = entry.password;
        document.getElementById('detail-url').value = entry.url || '';
        document.getElementById('detail-notes').value = entry.notes || '';
        // Notify app.ts to update URL button state
        document.getElementById('detail-url').dispatchEvent(new Event('input'));
        // Update favorite button
        const favBtn = document.getElementById('detail-favorite');
        favBtn.classList.toggle('active', entry.favorite);
        // Update metadata
        document.getElementById('detail-created').textContent = `Created: ${formatDate(entry.created_at)}`;
        document.getElementById('detail-modified').textContent = `Modified: ${formatDate(entry.modified_at)}`;
        await updateTotpAvailability(entry.entry_id);
    }
    catch (error) {
        showToast(error, 'error');
    }
}
/**
 * Clear the detail pane and prepare it for creating a new entry.
 *
 * Deselects any active list item, blanks all form fields, resets favourite
 * state, and disables TOTP buttons.
 */
export function createNewEntry() {
    setCurrentEntry(null);
    setCurrentTotpMetadata(null);
    // Clear active state in list
    document.querySelectorAll('.entry-item').forEach(item => item.classList.remove('active'));
    // Show entry detail
    noSelection.classList.add('hidden');
    entryDetail.classList.remove('hidden');
    // Clear form
    document.getElementById('detail-title').value = '';
    document.getElementById('detail-username').value = '';
    document.getElementById('detail-password').value = '';
    document.getElementById('detail-url').value = '';
    document.getElementById('detail-notes').value = '';
    // Notify app.ts to update URL button state
    document.getElementById('detail-url').dispatchEvent(new Event('input'));
    // Reset favorite button
    document.getElementById('detail-favorite').classList.remove('active');
    // Clear metadata
    document.getElementById('detail-created').textContent = '';
    document.getElementById('detail-modified').textContent = '';
    setTotpButtonState(false, false);
    document.getElementById('detail-title').focus();
}
/**
 * Persist the current detail-pane contents as a new or updated entry.
 *
 * Validates required fields (title, username, password), then calls
 * `add_entry` or `update_entry` as appropriate.  Refreshes the entry list
 * and re-selects the saved entry on success.
 */
export async function saveEntry() {
    const entry = {
        entry_id: currentEntry?.entry_id || null,
        title: document.getElementById('detail-title').value,
        username: document.getElementById('detail-username').value,
        password: document.getElementById('detail-password').value,
        url: document.getElementById('detail-url').value || null,
        notes: document.getElementById('detail-notes').value || null,
        favorite: document.getElementById('detail-favorite').classList.contains('active'),
        created_at: currentEntry?.created_at || new Date().toISOString(),
        modified_at: new Date().toISOString()
    };
    if (!entry.title || !entry.username || !entry.password) {
        showToast('Please fill in all required fields', 'warning');
        return;
    }
    try {
        if (currentEntry) {
            await invoke('update_entry', { entryId: currentEntry.entry_id, entry });
            showToast('Entry updated successfully!', 'success');
        }
        else {
            const entryId = await invoke('add_entry', { entry });
            entry.entry_id = entryId;
            showToast('Entry created successfully!', 'success');
        }
        setCurrentEntry(entry);
        await loadEntries();
        loadEntry(entry.entry_id);
    }
    catch (error) {
        showToast(error, 'error');
    }
}
/**
 * Delete the currently-selected entry after user confirmation.
 *
 * Clears the detail pane and refreshes the entry list on success.
 */
export async function deleteEntry() {
    if (!currentEntry)
        return;
    const confirmed = await confirm(`Are you sure you want to delete "${currentEntry.title}"?`, {
        title: 'Delete Entry',
        kind: 'warning'
    });
    if (!confirmed)
        return;
    try {
        await invoke('delete_entry', { entryId: currentEntry.entry_id });
        showToast('Entry deleted successfully!', 'success');
        setCurrentEntry(null);
        setCurrentTotpMetadata(null);
        setTotpButtonState(false, false);
        await loadEntries();
        noSelection.classList.remove('hidden');
        entryDetail.classList.add('hidden');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
