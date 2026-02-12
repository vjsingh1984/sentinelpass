// Content script for password field detection and autofill

console.log('Password Manager content script loaded');

// Configuration
const AUTOFILL_BUTTON_CLASS = 'pm-autofill-button';
const AUTOFILL_BUTTON_STYLE = `
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: #1a73e8;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 4px 8px;
  cursor: pointer;
  font-size: 14px;
  z-index: 9999;
  display: flex;
  align-items: center;
  gap: 4px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
`;

const AUTOFILL_BUTTON_HOVER_STYLE = `
  background: #1557b0;
`;

// Wait for DOM to be ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

function init() {
  // Observe DOM changes for dynamically added forms
  observeDOMChanges();

  // Scan for password fields immediately
  detectAndInjectButtons();

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'trigger_autofill') {
      performAutofill();
    }
    if (request.type === 'fill_credentials') {
      fillCredentials(request.username, request.password);
    }
  });
}

// Observe DOM for changes
function observeDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        detectAndInjectButtons();
        break;
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Detect password fields and inject autofill buttons
function detectAndInjectButtons() {
  const passwordFields = document.querySelectorAll('input[type="password"]');

  passwordFields.forEach(field => {
    // Skip if button already exists
    if (field.parentElement.querySelector(`.${AUTOFILL_BUTTON_CLASS}`)) {
      return;
    }

    // Make parent relative for absolute positioning
    const parent = field.parentElement;
    const computedStyle = window.getComputedStyle(parent);
    if (computedStyle.position === 'static') {
      parent.style.position = 'relative';
    }

    injectAutofillButton(field, parent);
  });
}

// Inject autofill button next to password field
function injectAutofillButton(passwordField, parent) {
  const button = document.createElement('button');
  button.className = AUTOFILL_BUTTON_CLASS;
  button.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></svg>';
  button.setAttribute('type', 'button');
  button.setAttribute('aria-label', 'Fill password from Password Manager');

  // Apply styles
  button.style.cssText = AUTOFILL_BUTTON_STYLE;

  // Hover effect
  button.addEventListener('mouseenter', () => {
    button.style.cssText = AUTOFILL_BUTTON_STYLE + AUTOFILL_BUTTON_HOVER_STYLE;
  });
  button.addEventListener('mouseleave', () => {
    button.style.cssText = AUTOFILL_BUTTON_STYLE;
  });

  // Click handler
  button.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    requestAutofill(passwordField);
  });

  // Hide when password field is not focused
  passwordField.addEventListener('focus', () => {
    button.style.display = 'flex';
  });
  passwordField.addEventListener('blur', () => {
    // Delay hiding to allow button click
    setTimeout(() => {
      if (document.activeElement !== button) {
        button.style.display = 'none';
      }
    }, 200);
  });

  // Initially hide
  button.style.display = 'none';

  parent.appendChild(button);
}

// Request credentials from background script
async function requestAutofill(passwordField) {
  const domain = window.location.hostname;
  const requestId = generateUUID();

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'get_credential',
      domain: domain,
      request_id: requestId
    });

    if (response.success && response.data) {
      fillCredentials(response.data.username, response.data.password);

      // Show success indicator
      showNotification('Password filled successfully!', 'success');
    } else {
      showNotification('No credentials found for this site', 'info');
    }
  } catch (error) {
    console.error('Autofill failed:', error);
    showNotification('Failed to autofill password', 'error');
  }
}

// Fill credentials into form fields
function fillCredentials(username, password) {
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return;

  // Fill password
  passwordField.value = password;
  passwordField.dispatchEvent(new Event('input', { bubbles: true }));
  passwordField.dispatchEvent(new Event('change', { bubbles: true }));

  // Try to find username field
  const usernameField = findUsernameField(passwordField);
  if (usernameField && username) {
    usernameField.value = username;
    usernameField.dispatchEvent(new Event('input', { bubbles: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

// Find username field based on password field location
function findUsernameField(passwordField) {
  const form = passwordField.form;

  if (form) {
    // Try to find username in same form
    let usernameField = form.querySelector('input[type="text"], input[type="email"]');

    // Look for input with "username", "email", "user" in name/id
    const inputs = form.querySelectorAll('input[type="text"], input[type="email"]');
    for (const input of inputs) {
      const attr = input.name + input.id + input.placeholder + input.autocomplete;
      if (/user|email|login/i.test(attr)) {
        usernameField = input;
        break;
      }
    }

    return usernameField;
  }

  // Try to find input before password field
  let prev = passwordField.previousElementSibling;
  while (prev) {
    if (prev.tagName === 'INPUT' && (prev.type === 'text' || prev.type === 'email')) {
      return prev;
    }
    prev = prev.previousElementSibling;
  }

  return null;
}

// Perform autofill from keyboard shortcut
function performAutofill() {
  const passwordField = document.querySelector('input[type="password"]');
  if (passwordField) {
    requestAutofill(passwordField);
  } else {
    showNotification('No password field found on this page', 'info');
  }
}

// Show notification to user
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${type === 'success' ? '#34a853' : type === 'error' ? '#ea4335' : '#1a73e8'};
    color: white;
    border-radius: 4px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    z-index: 100000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    animation: slideIn 0.3s ease-out;
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Generate UUID
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(100%);
      opacity: 0;
    }
  }

  .${AUTOFILL_BUTTON_CLASS}:hover {
    background: #1557b0 !important;
  }
`;
document.head.appendChild(style);

console.log('Password Manager content script initialized');
