// Popup script for Password Manager extension
let currentDomain = '';

document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentDomain = new URL(tab.url).hostname;
    // Initialize popup
    setupEventListeners();
    checkVaultStatus();
});
function setupEventListeners() {
    document.getElementById('lockBtn').addEventListener('click', lockVault);
    document.getElementById('settingsBtn').addEventListener('click', openSettings);
    document.getElementById('searchInput').addEventListener('input', handleSearch);
}
async function checkVaultStatus() {
    showLoading();
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'check_vault_status'
        });
        if (response.unlocked) {
            showUnlockedView();
            loadCredentials();
        }
        else {
            showLockedView();
        }
    }
    catch (error) {
        console.error('Failed to check vault status:', error);
        showLockedView();
    }
}
async function loadCredentials() {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'get_credential',
            domain: currentDomain,
            request_id: generateUUID()
        });
        const credentialsList = document.getElementById('credentialsList');
        if (response.success && response.data) {
            credentialsList.innerHTML = `
        <div class="credential-item">
          <div class="credential-info">
            <div class="credential-username">${escapeHtml(response.data.username)}</div>
            <div class="credential-domain">${escapeHtml(currentDomain)}</div>
          </div>
          <button class="btn-copy" data-username="${escapeHtml(response.data.username)}" data-password="${escapeHtml(response.data.password)}">
            Copy
          </button>
        </div>
      `;
            // Add copy button listeners
            credentialsList.querySelector('.btn-copy').addEventListener('click', (e) => {
                const username = e.target.dataset.username;
                const password = e.target.dataset.password;
                copyToClipboard(username, password);
            });
        }
        else {
            credentialsList.innerHTML = `
        <div class="empty-state">
          <p>No credentials found for <strong>${escapeHtml(currentDomain)}</strong></p>
          <p class="hint">Use the search above to find credentials for other sites</p>
        </div>
      `;
        }
    }
    catch (error) {
        console.error('Failed to load credentials:', error);
        document.getElementById('credentialsList').innerHTML = `
      <div class="error-state">
        <p>Failed to load credentials</p>
      </div>
    `;
    }
}

function handleSearch() {
    const searchInput = document.getElementById('searchInput');
    const searchTerm = searchInput.value.trim().toLowerCase();
    const credentialsList = document.getElementById('credentialsList');

    if (!searchTerm) {
        // Clear search and show current domain credentials
        loadCredentials();
        return;
    }

    // Calculate base domain (e.g., mail.google.com → google.com)
    const baseDomain = extractBaseDomain(currentDomain);

    // Show searching state
    credentialsList.innerHTML = '<div class="searching-state"><p>Searching...</p></div>';

    // Request domain-scoped credentials from background script
    chrome.runtime.sendMessage({
        type: 'list_domain_credentials',
        domain: baseDomain,
        request_id: generateUUID()
    }, (response) => {
        if (response && response.success && response.credentials && response.credentials.length > 0) {
            // Filter results by search term
            const filtered = response.credentials.filter(cred =>
                cred.title.toLowerCase().includes(searchTerm) ||
                cred.username.toLowerCase().includes(searchTerm)
            );
            displaySearchResults(filtered, baseDomain);
        } else {
            credentialsList.innerHTML = `
                <div class="empty-state">
                    <p>No credentials found for <strong>${escapeHtml(baseDomain)}</strong> domains</p>
                    <p class="hint">Search matches: ${escapeHtml(searchTerm)}</p>
                </div>
            `;
        }
    });
}

// Extract base domain from hostname (e.g., mail.google.com → google.com)
function extractBaseDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) {
        return hostname;
    }
    // For domains like co.uk, com.au, etc., keep the last 3 parts
    // For simple domains like mail.google.com, keep the last 2 parts
    const commonTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'co.in', 'com.sg', 'co.za'];
    const lastTwo = parts.slice(-2).join('.');
    const lastThree = parts.slice(-3).join('.');

    if (commonTlds.includes(lastTwo)) {
        return parts.slice(-3).join('.');
    }
    if (commonTlds.includes(lastThree)) {
        return parts.slice(-4).join('.');
    }
    return parts.slice(-2).join('.');
}

function displaySearchResults(credentials, baseDomain) {
    const credentialsList = document.getElementById('credentialsList');

    if (credentials.length === 0) {
        credentialsList.innerHTML = `
            <div class="empty-state">
                <p>No credentials found</p>
            </div>
        `;
        return;
    }

    credentialsList.innerHTML = credentials.map(cred => `
        <div class="credential-item">
            <div class="credential-info">
                <div class="credential-username">${escapeHtml(cred.username)}</div>
                <div class="credential-domain">${escapeHtml(cred.title || cred.url || baseDomain)}</div>
            </div>
            <button class="btn-copy" data-username="${escapeHtml(cred.username)}" data-domain="${escapeHtml(cred.url || baseDomain)}" data-request-id="${generateUUID()}">
                Get Password
            </button>
        </div>
    `).join('');

    // Add button listeners for "Get Password" buttons
    credentialsList.querySelectorAll('.btn-copy').forEach(button => {
        button.addEventListener('click', (e) => {
            const username = e.target.dataset.username;
            const domain = e.target.dataset.domain;
            const requestId = e.target.dataset.requestId;

            // Request full credential including password
            chrome.runtime.sendMessage({
                type: 'get_credential',
                domain: domain,
                request_id: requestId
            }, (response) => {
                if (response && response.success && response.data) {
                    copyToClipboard(response.data.username, response.data.password);
                } else {
                    showNotification('Failed to get password', 'error');
                }
            });
        });
    });
}

function showLockedView() {
    hideAllViews();
    document.getElementById('lockedView').classList.remove('hidden');
    updateVaultStatus(false);
}
function showUnlockedView() {
    hideAllViews();
    document.getElementById('unlockedView').classList.remove('hidden');
    updateVaultStatus(true);
}
function showLoading() {
    hideAllViews();
    document.getElementById('loadingView').classList.remove('hidden');
}
function hideAllViews() {
    document.querySelectorAll('.view').forEach(view => {
        view.classList.add('hidden');
    });
}
function updateVaultStatus(unlocked) {
    const statusIndicator = document.getElementById('vaultStatus');
    const dot = statusIndicator.querySelector('.status-dot');
    const text = statusIndicator.querySelector('.status-text');
    if (unlocked) {
        dot.classList.add('unlocked');
        dot.classList.remove('locked');
        text.textContent = 'Unlocked';
    }
    else {
        dot.classList.add('locked');
        dot.classList.remove('unlocked');
        text.textContent = 'Locked';
    }
}
async function lockVault() {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'lock_vault'
        });
        if (response && response.success && response.unlocked === false) {
            showLockedView();
            showNotification('Vault locked');
        }
        else {
            showNotification(response?.error || 'Failed to lock vault', 'error');
        }
    }
    catch (error) {
        console.error('Failed to lock vault:', error);
        showNotification('Failed to lock vault', 'error');
    }
}
function openSettings() {
    // Open extension options page
    if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
    } else {
        showNotification('Settings page coming soon', 'info');
    }
}
async function copyToClipboard(username, password) {
    try {
        await navigator.clipboard.writeText(password);
        showNotification('Password copied to clipboard');
        // Auto-clear after 30 seconds
        setTimeout(async () => {
            try {
                const current = await navigator.clipboard.readText();
                if (current === password) {
                    await navigator.clipboard.writeText('');
                }
            }
            catch (e) {
                // Clipboard read may fail if focus changed
            }
        }, 30000);
    }
    catch (error) {
        console.error('Failed to copy:', error);
        showNotification('Failed to copy password', 'error');
    }
}
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}
