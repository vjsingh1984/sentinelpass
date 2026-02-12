// Popup script for Password Manager extension

let currentDomain = '';

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentDomain = new URL(tab.url).hostname;

  // Initialize popup
  checkVaultStatus();
  setupEventListeners();
});

function setupEventListeners() {
  document.getElementById('lockBtn').addEventListener('click', lockVault);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
  document.getElementById('searchInput').addEventListener('input', handleSearch);
  document.getElementById('addCredentialBtn').addEventListener('click', addCredential);
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
    } else {
      showLockedView();
    }
  } catch (error) {
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
    } else {
      credentialsList.innerHTML = `
        <div class="empty-state">
          <p>No credentials found for <strong>${escapeHtml(currentDomain)}</strong></p>
          <button id="addCredentialBtn" class="btn btn-primary">Add Credential</button>
        </div>
      `;
      document.getElementById('addCredentialBtn').addEventListener('click', addCredential);
    }
  } catch (error) {
    console.error('Failed to load credentials:', error);
    document.getElementById('credentialsList').innerHTML = `
      <div class="error-state">
        <p>Failed to load credentials</p>
      </div>
    `;
  }
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
  } else {
    dot.classList.add('locked');
    dot.classList.remove('unlocked');
    text.textContent = 'Locked';
  }
}

async function lockVault() {
  try {
    await chrome.runtime.sendMessage({
      type: 'lock_vault'
    });

    showLockedView();
    showNotification('Vault locked');
  } catch (error) {
    console.error('Failed to lock vault:', error);
    showNotification('Failed to lock vault', 'error');
  }
}

function openSettings() {
  chrome.tabs.create({
    url: chrome.runtime.getURL('settings.html')
  });
}

function handleSearch(e) {
  // Search functionality - to be implemented
  console.log('Search:', e.target.value);
}

function addCredential() {
  // Open add credential dialog - to be implemented
  showNotification('Add credential feature coming soon', 'info');
}

async function copyToClipboard(username, password) {
  try {
    await navigator.clipboard.writeText(password);
    showNotification('Password copied to clipboard');
  } catch (error) {
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
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
