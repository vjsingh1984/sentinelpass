// Import Tauri API
const { invoke } = window.__TAURI__.core;
const { confirm } = window.__TAURI__.dialog;
const { writeText, readText } = window.__TAURI__.clipboardManager;

// Application State
let currentEntry = null;
let entries = [];
let isCreateVault = false;
let currentFilter = 'all';

// DOM Elements
const welcomeScreen = document.getElementById('welcome-screen');
const vaultScreen = document.getElementById('vault-screen');
const vaultActions = document.getElementById('vault-actions');
const passwordForm = document.getElementById('password-form');
const masterPasswordInput = document.getElementById('master-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const confirmPasswordGroup = document.getElementById('confirm-password-group');
const formTitle = document.getElementById('form-title');
const submitPasswordBtn = document.getElementById('submit-password');
const strengthMeter = document.getElementById('strength-meter');
const strengthFill = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');
const entryList = document.getElementById('entry-list');
const searchInput = document.getElementById('search-input');
const noSelection = document.getElementById('no-selection');
const entryDetail = document.getElementById('entry-detail');

// Initialize Application
async function init() {
    setupEventListeners();
    checkVaultUnlocked();
}

function setupEventListeners() {
    // Welcome Screen
    document.getElementById('create-vault-btn').addEventListener('click', () => showCreateVault());
    document.getElementById('unlock-vault-btn').addEventListener('click', () => showUnlockVault());
    document.getElementById('cancel-password').addEventListener('click', () => hidePasswordForm());
    passwordForm.addEventListener('submit', handlePasswordSubmit);
    masterPasswordInput.addEventListener('input', handlePasswordInput);

    // Vault Screen
    document.getElementById('lock-btn').addEventListener('click', lockVault);
    document.getElementById('add-entry-btn').addEventListener('click', createNewEntry);
    searchInput.addEventListener('input', handleSearch);

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => handleFilter(e.target.dataset.filter));
    });

    // Entry Detail
    document.getElementById('save-entry').addEventListener('click', saveEntry);
    document.getElementById('delete-entry').addEventListener('click', deleteEntry);
    document.getElementById('detail-favorite').addEventListener('click', toggleFavorite);
    document.getElementById('toggle-detail-password').addEventListener('click', () => togglePasswordVisibility('detail-password'));
    document.getElementById('generate-password-btn').addEventListener('click', generatePasswordForEntry);
    document.getElementById('copy-username').addEventListener('click', () => copyToClipboard(document.getElementById('detail-username').value, 'Username'));
    document.getElementById('copy-password').addEventListener('click', () => copyToClipboard(document.getElementById('detail-password').value, 'Password'));

    // Toggle password visibility in welcome screen
    document.getElementById('toggle-password').addEventListener('click', () => togglePasswordVisibility('master-password'));
}

async function checkVaultUnlocked() {
    try {
        const unlocked = await invoke('is_unlocked');
        if (unlocked) {
            showVaultScreen();
            loadEntries();
        }
    } catch (error) {
        console.error('Error checking vault status:', error);
    }
}

// Vault Creation/Unlock
function showCreateVault() {
    isCreateVault = true;
    vaultActions.classList.add('hidden');
    passwordForm.classList.remove('hidden');
    confirmPasswordGroup.classList.remove('hidden');
    formTitle.textContent = 'Create New Vault';
    submitPasswordBtn.textContent = 'Create Vault';
    masterPasswordInput.focus();
}

function showUnlockVault() {
    isCreateVault = false;
    vaultActions.classList.add('hidden');
    passwordForm.classList.remove('hidden');
    confirmPasswordGroup.classList.add('hidden');
    formTitle.textContent = 'Unlock Vault';
    submitPasswordBtn.textContent = 'Unlock';
    masterPasswordInput.focus();
}

function hidePasswordForm() {
    passwordForm.classList.add('hidden');
    confirmPasswordGroup.classList.add('hidden');
    vaultActions.classList.remove('hidden');
    masterPasswordInput.value = '';
    confirmPasswordInput.value = '';
    strengthMeter.classList.add('hidden');
}

async function handlePasswordInput(e) {
    const password = e.target.value;
    if (password.length > 0) {
        strengthMeter.classList.remove('hidden');
        const analysis = await invoke('check_password_strength', { password });
        updateStrengthMeter(analysis);
    } else {
        strengthMeter.classList.add('hidden');
    }
}

function updateStrengthMeter(analysis) {
    const { strength, score, entropy_bits, crack_time_human } = analysis;

    strengthFill.style.width = `${(score / 5) * 100}%`;

    // Color based on strength
    const colors = {
        'Very Weak': '#ef4444',
        'Weak': '#f59e0b',
        'Fair': '#f59e0b',
        'Strong': '#10b981',
        'Very Strong': '#059669'
    };

    strengthFill.style.backgroundColor = colors[strength] || '#6366f1';
    strengthText.textContent = `${strength} (${entropy_bits.toFixed(1)} bits) - ${crack_time_human}`;
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    const password = masterPasswordInput.value;

    if (isCreateVault) {
        const confirmPassword = confirmPasswordInput.value;
        if (password !== confirmPassword) {
            showToast('Passwords do not match', 'error');
            return;
        }

        try {
            await invoke('create_vault', { masterPassword: password });
            showToast('Vault created successfully!', 'success');
            showVaultScreen();
        } catch (error) {
            showToast(error, 'error');
        }
    } else {
        try {
            await invoke('unlock_vault', { masterPassword: password });
            showToast('Vault unlocked successfully!', 'success');
            showVaultScreen();
            loadEntries();
        } catch (error) {
            showToast(error, 'error');
        }
    }
}

async function lockVault() {
    try {
        await invoke('lock_vault');
        hidePasswordForm();
        welcomeScreen.classList.remove('hidden');
        vaultScreen.classList.add('hidden');
        currentEntry = null;
        entries = [];
        showToast('Vault locked', 'success');
    } catch (error) {
        showToast(error, 'error');
    }
}

function showVaultScreen() {
    welcomeScreen.classList.add('hidden');
    vaultScreen.classList.remove('hidden');
    hidePasswordForm();
}

// Entry Management
async function loadEntries() {
    try {
        entries = await invoke('list_entries');
        renderEntryList();
        document.getElementById('entry-count').textContent = `${entries.length} entries`;
    } catch (error) {
        showToast(error, 'error');
    }
}

function renderEntryList(filteredEntries = null) {
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

async function loadEntry(entryId) {
    try {
        const entry = await invoke('get_entry', { entryId });
        currentEntry = entry;

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

        // Update favorite button
        const favBtn = document.getElementById('detail-favorite');
        favBtn.classList.toggle('active', entry.favorite);

        // Update metadata
        document.getElementById('detail-created').textContent = `Created: ${formatDate(entry.created_at)}`;
        document.getElementById('detail-modified').textContent = `Modified: ${formatDate(entry.modified_at)}`;
    } catch (error) {
        showToast(error, 'error');
    }
}

function createNewEntry() {
    currentEntry = null;

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

    // Reset favorite button
    document.getElementById('detail-favorite').classList.remove('active');

    // Clear metadata
    document.getElementById('detail-created').textContent = '';
    document.getElementById('detail-modified').textContent = '';

    document.getElementById('detail-title').focus();
}

async function saveEntry() {
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
        } else {
            const entryId = await invoke('add_entry', { entry });
            entry.entry_id = entryId;
            showToast('Entry created successfully!', 'success');
        }

        currentEntry = entry;
        await loadEntries();
        loadEntry(entry.entry_id);
    } catch (error) {
        showToast(error, 'error');
    }
}

async function deleteEntry() {
    if (!currentEntry) return;

    const confirmed = await confirm(`Are you sure you want to delete "${currentEntry.title}"?`, {
        title: 'Delete Entry',
        kind: 'warning'
    });

    if (!confirmed) return;

    try {
        await invoke('delete_entry', { entryId: currentEntry.entry_id });
        showToast('Entry deleted successfully!', 'success');
        currentEntry = null;
        await loadEntries();
        noSelection.classList.remove('hidden');
        entryDetail.classList.add('hidden');
    } catch (error) {
        showToast(error, 'error');
    }
}

function toggleFavorite() {
    document.getElementById('detail-favorite').classList.toggle('active');
}

// Search & Filter
function handleSearch(e) {
    const query = e.target.value.toLowerCase();
    const filtered = entries.filter(entry =>
        entry.title.toLowerCase().includes(query) ||
        entry.username.toLowerCase().includes(query)
    );
    renderEntryList(filtered);
}

function handleFilter(filter) {
    currentFilter = filter;

    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    if (filter === 'all') {
        renderEntryList();
    } else if (filter === 'favorites') {
        const filtered = entries.filter(e => e.favorite);
        renderEntryList(filtered);
    }
}

// Password Generation
async function generatePasswordForEntry() {
    try {
        const password = await invoke('generate_password', {
            length: 16,
            includeSymbols: true
        });
        document.getElementById('detail-password').value = password;
        showToast('Password generated!', 'success');
    } catch (error) {
        showToast(error, 'error');
    }
}

// Utility Functions
async function copyToClipboard(text, label) {
    if (!text) {
        showToast('Nothing to copy', 'warning');
        return;
    }

    try {
        await writeText(text);
        showToast(`${label} copied to clipboard!`, 'success');

        // Auto-clear after 30 seconds
        setTimeout(async () => {
            const clipboard = await readText();
            if (clipboard === text) {
                // Note: We can't programmatically clear clipboard for security reasons
                // But we can show a notification
                showToast('Clipboard still contains copied data', 'warning');
            }
        }, 30000);
    } catch (error) {
        showToast(error, 'error');
    }
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling || input.parentElement.querySelector('.btn-icon');

    if (input.type === 'password') {
        input.type = 'text';
        if (button) button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/></svg>`;
    } else {
        input.type = 'password';
        if (button) button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Initialize on load
init();
