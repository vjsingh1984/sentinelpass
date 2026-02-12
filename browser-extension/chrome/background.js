// Background service worker for Password Manager Extension

// Native messaging host configuration
const HOST_NAME = 'com.passwordmanager.host';

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request);

  if (request.type === 'get_credential') {
    handleGetCredential(request.domain, request.request_id)
      .then(response => sendResponse(response))
      .catch(error => sendResponse({
        success: false,
        error: error.message
      }));
    return true; // Keep message channel open for async response
  }

  if (request.type === 'save_credential') {
    handleSaveCredential(request.data)
      .then(response => sendResponse(response))
      .catch(error => sendResponse({
        success: false,
        error: error.message
      }));
    return true;
  }

  if (request.type === 'check_vault_status') {
    handleCheckVaultStatus()
      .then(status => sendResponse({ success: true, status }))
      .catch(error => sendResponse({
        success: false,
        error: error.message
      }));
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

// Get credential from native messaging host
async function handleGetCredential(domain, requestId) {
  try {
    const response = await sendNativeMessage({
      version: 1,
      type: 'get_credential',
      domain: domain,
      request_id: requestId || generateUUID()
    });

    if (response.success && response.data) {
      // Store in session storage for content script to access
      await chrome.storage.session.set({
        pendingCredential: response.data
      });
    }

    return response;
  } catch (error) {
    console.error('Failed to get credential:', error);
    return { success: false, error: error.message };
  }
}

// Save credential via native messaging host
async function handleSaveCredential(data) {
  try {
    const response = await sendNativeMessage({
      version: 1,
      type: 'save_credential',
      data: data
    });
    return response;
  } catch (error) {
    console.error('Failed to save credential:', error);
    return { success: false, error: error.message };
  }
}

// Check if vault is unlocked
async function handleCheckVaultStatus() {
  try {
    const response = await sendNativeMessage({
      version: 1,
      type: 'check_vault_status'
    });
    return response;
  } catch (error) {
    console.error('Failed to check vault status:', error);
    return { unlocked: false };
  }
}

// Send message to native messaging host
function sendNativeMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// Generate a UUID for request tracking
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

console.log('Password Manager background service worker loaded');
