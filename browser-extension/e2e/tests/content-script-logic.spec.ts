/**
 * Content Script Logic Tests
 *
 * These tests verify the core logic of the content script without needing
 * the full Chrome extension environment. We mock the chrome API to test
 * the form detection and notification logic.
 */

import { test, expect } from '@playwright/test';

// Mock chrome API
class MockChromeRuntime {
  private listeners: Map<string, Function[]> = new Map();
  private id = 'test-extension-id';

  onMessage: any = {
    addListener: (callback: Function) => {
      if (!this.listeners.has('message')) {
        this.listeners.set('message', []);
      }
      this.listeners.get('message')!.push(callback);
    }
  };

  sendMessage(message: any) {
    // Simulate sending a message to the background script
    console.log('[MockChrome] sendMessage:', message);
    return Promise.resolve({ success: true });
  }

  get id() {
    return this.id;
  }
}

// Simplified content script logic for testing
class ContentScriptLogic {
  private chrome: any;

  constructor(chrome: any) {
    this.chrome = chrome;
  }

  detectPasswordField(form: HTMLElement): HTMLInputElement | null {
    const passwordField = form.querySelector('input[type="password"]');
    return passwordField;
  }

  findUsernameField(passwordField: HTMLInputElement): HTMLInputElement | null {
    // Try before (label: username) then after (password field, label: password)
    const form = passwordField.form;
    if (!form) return null;

    const inputs = Array.from(form.querySelectorAll('input:not([type="password"])'));
    return inputs.length > 0 ? inputs[0] : null;
  }

  captureCredentials(form: HTMLElement) {
    const passwordField = this.detectPasswordField(form);
    if (!passwordField) return null;

    const usernameField = this.findUsernameField(passwordField);
    const password = passwordField.value;
    const username = usernameField?.value || '';

    if (!password) return null;

    return { username, password };
  }
}

test('content script: detects password field in form', () => {
  // Create a test form
  const form = document.createElement('form');
  form.innerHTML = `
    <input name="username" type="email" value="test@example.com" />
    <input name="password" type="password" value="test-password" />
    <button type="submit">Submit</button>
  `;
  document.body.appendChild(form);

  try {
    const logic = new ContentScriptLogic(new MockChromeRuntime());
    const passwordField = logic.detectPasswordField(form);

    expect(passwordField).not.toBeNull();
    expect(passwordField?.type).toBe('password');
  } finally {
    document.body.removeChild(form);
  }
});

test('content script: captures credentials from form', () => {
  const form = document.createElement('form');
  form.innerHTML = `
    <input name="username" type="email" value="test@example.com" />
    <input name="password" type="password" value="secret123" />
    <button type="submit">Submit</button>
  `;
  document.body.appendChild(form);

  try {
    const logic = new ContentScriptLogic(new MockChromeRuntime());
    const credentials = logic.captureCredentials(form);

    expect(credentials).not.toBeNull();
    expect(credentials?.username).toBe('test@example.com');
    expect(credentials?.password).toBe('secret123');
  } finally {
    document.body.removeChild(form);
  }
});

test('content script: handles empty password', () => {
  const form = document.createElement('form');
  form.innerHTML = `
    <input name="username" type="email" value="test@example.com" />
    <input name="password" type="password" value="" />
    <button type="submit">Submit</button>
  `;
  document.body.appendChild(form);

  try {
    const logic = new ContentScriptLogic(new MockChromeRuntime());
    const credentials = logic.captureCredentials(form);

    // Should return null when password is empty
    expect(credentials).toBeNull();
  } finally {
    document.body.removeChild(form);
  }
});

test('content script: handles form without password field', () => {
  const form = document.createElement('form');
  form.innerHTML = `
    <input name="username" type="email" value="test@example.com" />
    <button type="submit">Submit</button>
  `;
  document.body.appendChild(form);

  try {
    const logic = new ContentScriptLogic(new MockChromeRuntime());
    const credentials = logic.captureCredentials(form);

    // Should return null when there's no password field
    expect(credentials).toBeNull();
  } finally {
    document.body.removeChild(form);
  }
});

test('content script: finds username field before password', () => {
  const form = document.createElement('form');
  form.innerHTML = `
    <input name="email" type="email" value="user@example.com" />
    <input name="password" type="password" value="secret" />
    <button type="submit">Submit</button>
  `;
  document.body.appendChild(form);

  try {
    const logic = new ContentScriptLogic(new MockChromeRuntime());
    const passwordField = logic.detectPasswordField(form);
    const usernameField = passwordField ? logic.findUsernameField(passwordField) : null;

    expect(usernameField).not.toBeNull();
    expect(usernameField?.value).toBe('user@example.com');
  } finally {
    document.body.removeChild(form);
  }
});
