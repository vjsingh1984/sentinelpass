// Background service worker for Password Manager Extension
// Native messaging host configuration
const HOST_NAME = 'com.passwordmanager.host';
console.log('[SentinelPass Background] ========== VERSION 0.1.0 - REMOVED ICON URL ==========');
console.log('[SentinelPass Background] Service worker loaded');
console.log('[SentinelPass Background] Host name:', HOST_NAME);
// ========================================
// Helper Functions
// ========================================
const SENSITIVE_LOG_KEYS = new Set(['password', 'secret', 'token', 'passphrase', 'totp_code']);
const NEVER_SAVE_DOMAINS_KEY = 'neverSaveDomains';
function redactForLog(value) {
    if (!value || typeof value !== 'object') {
        return value;
    }
    if (Array.isArray(value)) {
        return value.map(redactForLog);
    }
    const redacted = {};
    for (const [key, item] of Object.entries(value)) {
        if (SENSITIVE_LOG_KEYS.has(key.toLowerCase())) {
            redacted[key] = '[REDACTED]';
        }
        else if (item && typeof item === 'object') {
            redacted[key] = redactForLog(item);
        }
        else {
            redacted[key] = item;
        }
    }
    return redacted;
}
function normalizeDomainForPolicy(value) {
    if (!value || typeof value !== 'string') {
        return null;
    }
    let normalized = value.trim().toLowerCase();
    if (!normalized) {
        return null;
    }
    if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
        try {
            normalized = new URL(normalized).hostname.toLowerCase();
        }
        catch (_error) {
            // Keep original value if URL parsing fails.
        }
    }
    normalized = normalized.replace(/^\.+|\.+$/g, '');
    if (normalized.startsWith('www.')) {
        normalized = normalized.slice(4);
    }
    return normalized || null;
}
function domainMatchesPolicy(domain, policyDomain) {
    return domain === policyDomain || domain.endsWith(`.${policyDomain}`);
}
function getNeverSaveDomains() {
    return new Promise((resolve) => {
        chrome.storage.local.get([NEVER_SAVE_DOMAINS_KEY], (result) => {
            if (chrome.runtime.lastError) {
                console.error('[SentinelPass Background] Failed reading never-save domains:', chrome.runtime.lastError.message);
                resolve({});
                return;
            }
            resolve(result[NEVER_SAVE_DOMAINS_KEY] || {});
        });
    });
}
function setNeverSaveDomains(domains) {
    return new Promise((resolve, reject) => {
        chrome.storage.local.set({ [NEVER_SAVE_DOMAINS_KEY]: domains }, () => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            }
            else {
                resolve();
            }
        });
    });
}
async function shouldSuppressSavePrompt(domainOrUrl) {
    const normalized = normalizeDomainForPolicy(domainOrUrl);
    if (!normalized) {
        return false;
    }
    const domains = await getNeverSaveDomains();
    return Object.keys(domains).some((policyDomain) => domainMatchesPolicy(normalized, policyDomain));
}
async function addNeverSaveDomain(domainOrUrl) {
    const normalized = normalizeDomainForPolicy(domainOrUrl);
    if (!normalized) {
        return false;
    }
    const domains = await getNeverSaveDomains();
    domains[normalized] = { createdAt: Date.now() };
    await setNeverSaveDomains(domains);
    return true;
}
// Handle get_credential request
async function handleGetCredential(domain, requestId) {
    console.log('[SentinelPass Background] handleGetCredential called for domain:', domain);
    try {
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'get_credential',
            domain: domain,
            request_id: requestId
        });
        console.log('[SentinelPass Background] Got credential response from native host:', redactForLog(response));
        return response;
    }
    catch (error) {
        console.error('[SentinelPass Background] Error getting credential:', error);
        return {
            success: false,
            error: error.message
        };
    }
}
// Handle get_totp_code request
async function handleGetTotpCode(domain, requestId) {
    console.log('[SentinelPass Background] handleGetTotpCode called for domain:', domain);
    try {
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'get_totp_code',
            domain: domain,
            request_id: requestId
        });
        console.log('[SentinelPass Background] Got TOTP response from native host:', redactForLog(response));
        return response;
    }
    catch (error) {
        console.error('[SentinelPass Background] Error getting TOTP code:', error);
        return {
            success: false,
            error: error.message
        };
    }
}
// Handle save_credential request
async function handleSaveCredential(data) {
    console.log('[SentinelPass Background] handleSaveCredential called');
    console.log('[SentinelPass Background] Save request payload:', redactForLog(data));
    try {
        // Send to native host for saving
        console.log('[SentinelPass Background] Sending save request to native host...');
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'save_credential',
            domain: data.domain,
            data: {
                username: data.username,
                password: data.password,
                title: data.domain || data.url || 'Unknown', // Backward compatibility
                url: data.url || null
            }
        });
        console.log('[SentinelPass Background] Native host response:', redactForLog(response));
        if (response && response.success) {
            console.log('[SentinelPass Background] Credential saved successfully');
            return { success: true };
        }
        else {
            console.error('[SentinelPass Background] Failed to save credential:', redactForLog(response));
            return { success: false, error: response?.error || 'Unknown error' };
        }
    }
    catch (error) {
        console.error('[SentinelPass Background] Error in handleSaveCredential:', error);
        // Create a notification to inform the user about the error
        await chrome.notifications.create('save-error-' + Date.now(), {
            type: 'basic',
            title: 'SentinelPass Error',
            message: 'Failed to save password. Is the daemon running?',
            requireInteraction: false
        });
        return { success: false, error: error.message };
    }
}
// Handle check_credential_exists request
async function handleCheckCredentialExists(domain) {
    console.log('[SentinelPass Background] handleCheckCredentialExists called for domain:', domain);
    try {
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'check_credential_exists',
            domain: domain
        });
        console.log('[SentinelPass Background] Credential exists check result:', redactForLog(response));
        return response.exists || false;
    }
    catch (error) {
        console.error('[SentinelPass Background] Error checking credential exists:', error);
        return false;
    }
}
// Handle check_vault_status request
async function handleCheckVaultStatus() {
    console.log('[SentinelPass Background] handleCheckVaultStatus called');
    try {
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'check_vault_status'
        });
        console.log('[SentinelPass Background] Vault status:', redactForLog(response));
        return {
            success: response?.success === true,
            unlocked: response?.unlocked === true
        };
    }
    catch (error) {
        console.error('[SentinelPass Background] Error checking vault status:', error);
        return {
            success: false,
            unlocked: false,
            error: error.message
        };
    }
}
// Handle lock_vault request
async function handleLockVault() {
    console.log('[SentinelPass Background] handleLockVault called');
    try {
        const response = await chrome.runtime.sendNativeMessage(HOST_NAME, {
            type: 'lock_vault'
        });
        return {
            success: response?.success === true,
            unlocked: response?.unlocked === true
        };
    }
    catch (error) {
        console.error('[SentinelPass Background] Error locking vault:', error);
        return {
            success: false,
            unlocked: true,
            error: error.message
        };
    }
}
// Handle save notification request from content script
async function handleSaveNotification(data) {
    console.log('[SentinelPass Background] ========== HANDLE SAVE NOTIFICATION ==========');
    console.log('[SentinelPass Background] Notification payload:', redactForLog(data));
    try {
        const suppressPrompt = await shouldSuppressSavePrompt(data?.domain || data?.url || '');
        if (suppressPrompt) {
            console.log('[SentinelPass Background] Skipping save notification due to never-save policy');
            return true;
        }
        // Create notification to ask user to save
        const notificationId = 'save-password-' + Date.now();
        // Store the credential data temporarily for the notification button click
        chrome.storage.session.set({ 'pendingSaveCredential': data }, () => {
            console.log('[SentinelPass Background] Stored pending save credential');
        });
        // Create the notification
        await chrome.notifications.create(notificationId, {
            type: 'basic',
            title: 'SentinelPass - Save Password?',
            message: `Do you want to save the password for ${data.domain}?`,
            buttons: [
                { title: 'Save' },
                { title: 'Never for this site' }
            ],
            requireInteraction: true,
            silent: false
        });
        console.log('[SentinelPass Background] ========== SAVE NOTIFICATION CREATED ==========');
        console.log('[SentinelPass Background] Notification ID:', notificationId);
        return true;
    }
    catch (error) {
        console.error('[SentinelPass Background] ========== ERROR IN HANDLE SAVE NOTIFICATION ==========');
        console.error('[SentinelPass Background] Error:', error);
        throw error;
    }
}
// ========================================
// Event Listeners
// ========================================
// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('[SentinelPass Background] Received message:', request.type);
    console.log('[SentinelPass Background] Request details:', redactForLog(request));
    if (request.type === 'get_credential') {
        console.log('[SentinelPass Background] Handling get_credential for domain:', request.domain);
        handleGetCredential(request.domain, request.request_id)
            .then(response => {
            console.log('[SentinelPass Background] Get credential response:', redactForLog(response));
            sendResponse(response);
        })
            .catch(error => {
            console.error('[SentinelPass Background] Get credential error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        });
        return true; // Keep message channel open for async response
    }
    if (request.type === 'get_totp_code') {
        console.log('[SentinelPass Background] Handling get_totp_code for domain:', request.domain);
        handleGetTotpCode(request.domain, request.request_id)
            .then(response => {
            console.log('[SentinelPass Background] Get TOTP response:', redactForLog(response));
            sendResponse(response);
        })
            .catch(error => {
            console.error('[SentinelPass Background] Get TOTP error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        });
        return true;
    }
    if (request.type === 'save_credential') {
        console.log('[SentinelPass Background] Handling save_credential');
        console.log('[SentinelPass Background] Domain:', request.data?.domain);
        console.log('[SentinelPass Background] URL:', request.data?.url);
        handleSaveCredential(request.data)
            .then(response => {
            console.log('[SentinelPass Background] Save credential response:', redactForLog(response));
            sendResponse(response);
        })
            .catch(error => {
            console.error('[SentinelPass Background] Save credential error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        });
        return true;
    }
    if (request.type === 'check_credential_exists') {
        console.log('[SentinelPass Background] Handling check_credential_exists for domain:', request.domain);
        handleCheckCredentialExists(request.domain)
            .then(exists => {
            console.log('[SentinelPass Background] Credential exists:', exists);
            sendResponse({ exists: exists });
        })
            .catch(error => {
            console.error('[SentinelPass Background] Check credential exists error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        });
        return true;
    }
    if (request.type === 'check_vault_status') {
        console.log('[SentinelPass Background] Handling check_vault_status');
        handleCheckVaultStatus()
            .then(statusResponse => {
            console.log('[SentinelPass Background] Vault status:', redactForLog(statusResponse));
            sendResponse(statusResponse);
        })
            .catch(error => {
            console.error('[SentinelPass Background] Check vault status error:', error);
            sendResponse({
                success: false,
                unlocked: false,
                error: error.message
            });
        });
        return true;
    }
    if (request.type === 'lock_vault') {
        console.log('[SentinelPass Background] Handling lock_vault');
        handleLockVault()
            .then(response => {
            console.log('[SentinelPass Background] Lock vault response:', redactForLog(response));
            sendResponse(response);
        })
            .catch(error => {
            console.error('[SentinelPass Background] Lock vault error:', error);
            sendResponse({
                success: false,
                unlocked: true,
                error: error.message
            });
        });
        return true;
    }
    if (request.type === 'request_save_notification') {
        console.log('[SentinelPass Background] Handling request_save_notification');
        handleSaveNotification(request.data)
            .then(result => {
            console.log('[SentinelPass Background] Save notification result:', result);
            sendResponse({ success: result });
        })
            .catch(error => {
            console.error('[SentinelPass Background] Save notification error:', error);
            sendResponse({
                success: false,
                error: error.message
            });
        });
        return true;
    }
});
// Handle keyboard shortcut for autofill
chrome.commands.onCommand.addListener((command) => {
    if (command === 'autofill') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {
                    type: 'trigger_autofill'
                });
            }
        });
    }
});
// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    console.log('[SentinelPass Background] ========== NOTIFICATION BUTTON CLICKED ==========');
    console.log('[SentinelPass Background] Notification ID:', notificationId);
    console.log('[SentinelPass Background] Button Index:', buttonIndex);
    // Check if this is a save password notification
    if (notificationId.startsWith('save-password-')) {
        chrome.storage.session.get(['pendingSaveCredential'], (result) => {
            if (result && result.pendingSaveCredential) {
                const data = result.pendingSaveCredential;
                if (buttonIndex === 0) {
                    // Save button clicked
                    console.log('[SentinelPass Background] Save button clicked, saving credential...');
                    console.log('[SentinelPass Background] Domain:', data.domain);
                    // Format data for native host
                    const saveData = {
                        username: data.username,
                        password: data.password,
                        title: data.domain || data.url || 'Unknown',
                        url: data.url || null
                    };
                    // Send save request to native host
                    chrome.runtime.sendNativeMessage(HOST_NAME, {
                        type: 'save_credential',
                        domain: data.domain,
                        data: saveData
                    }, (response) => {
                        console.log('[SentinelPass Background] Save credential response:', redactForLog(response));
                        if (response && response.success) {
                            console.log('[SentinelPass Background] Credential saved successfully!');
                            // Show success notification
                            chrome.notifications.create('save-success-' + Date.now(), {
                                type: 'basic',
                                title: 'SentinelPass',
                                message: 'Password saved successfully!',
                                requireInteraction: false
                            });
                        }
                        else {
                            console.error('[SentinelPass Background] Failed to save credential');
                            chrome.notifications.create('save-error-' + Date.now(), {
                                type: 'basic',
                                title: 'SentinelPass Error',
                                message: 'Failed to save password. Is the daemon running?',
                                requireInteraction: false
                            });
                        }
                    });
                }
                else {
                    // Never button clicked
                    console.log('[SentinelPass Background] Never for this site clicked');
                    void addNeverSaveDomain(data.domain || data.url || '')
                        .then((stored) => {
                        if (!stored) {
                            return;
                        }
                        console.log('[SentinelPass Background] Added never-save policy for domain:', data.domain);
                        chrome.notifications.create('never-save-' + Date.now(), {
                            type: 'basic',
                            title: 'SentinelPass',
                            message: `Will no longer prompt to save for ${data.domain || 'this site'}`,
                            requireInteraction: false
                        });
                    })
                        .catch((error) => {
                        console.error('[SentinelPass Background] Failed to persist never-save policy:', error);
                    });
                }
                // Clear the pending credential
                chrome.storage.session.remove('pendingSaveCredential');
            }
        });
    }
});
// Handle notification closed (clicked X or dismissed)
chrome.notifications.onClosed.addListener((notificationId) => {
    console.log('[SentinelPass Background] Notification closed:', notificationId);
    // Clean up any pending data
    chrome.storage.session.remove('pendingSaveCredential');
});
console.log('Password Manager background service worker initialized');
