/**
 * SentinelPass Desktop UI — pure utility functions.
 *
 * Stateless helpers used across the application: toast notifications,
 * clipboard operations, password-visibility toggling, HTML escaping,
 * and date formatting.
 */

import { writeText, readText } from './state.js';

/**
 * Display a transient toast notification that auto-dismisses after 3 seconds.
 *
 * @param message - The message text to display.
 * @param type - The toast style: `"success"`, `"warning"`, or `"error"`.
 */
export function showToast(message: any, type: string = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3000);
}

/**
 * Copy a string to the system clipboard via the Tauri clipboard plugin,
 * showing a toast on success.  Automatically clears the clipboard after
 * 30 seconds if the content has not changed.
 *
 * @param text - The text to copy.
 * @param label - A human-readable label for the toast (e.g. "Password").
 */
export async function copyToClipboard(text: string, label: string) {
    if (!text) {
        showToast('Nothing to copy', 'warning');
        return;
    }

    try {
        await writeText(text);
        showToast(`${label} copied to clipboard!`, 'success');

        // Auto-clear after 30 seconds
        setTimeout(async () => {
            try {
                const clipboard = await readText();
                if (clipboard === text) {
                    await writeText('');
                    showToast('Clipboard cleared', 'success');
                }
            } catch (clearError) {
                console.warn('Failed to clear clipboard:', clearError);
            }
        }, 30000);
    } catch (error) {
        showToast(error, 'error');
    }
}

/**
 * Toggle a password input between `type="password"` and `type="text"`,
 * swapping the adjacent button's eye icon accordingly.
 *
 * @param inputId - The DOM id of the `<input>` element to toggle.
 */
export function togglePasswordVisibility(inputId: string) {
    const input = document.getElementById(inputId) as HTMLInputElement;
    const button = input.nextElementSibling || input.parentElement.querySelector('.btn-icon');

    if (input.type === 'password') {
        input.type = 'text';
        if (button) button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/></svg>`;
    } else {
        input.type = 'password';
        if (button) button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
}

/**
 * Safely escape a string for insertion into HTML to prevent XSS.
 *
 * @param text - The raw text to escape.
 * @returns The HTML-safe string.
 */
export function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format an ISO date string into a short human-readable form
 * (e.g. "Feb 16, 2026, 03:45 PM").
 *
 * @param dateString - An ISO 8601 date string.
 * @returns The formatted date string.
 */
export function formatDate(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}
