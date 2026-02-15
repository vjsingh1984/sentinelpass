import { normalizeLaunchUrl } from './url-utils.js';
// Import Tauri API - wait for it to be loaded
let invoke, confirm, writeText, readText;
function initTauriAPI() {
    if (window.__TAURI__) {
        invoke = window.__TAURI__.core.invoke;
        confirm = window.__TAURI__.dialog.confirm;
        writeText = window.__TAURI__.clipboardManager.writeText;
        readText = window.__TAURI__.clipboardManager.readText;
        return true;
    }
    return false;
}
// Application State
let currentEntry = null;
let entries = [];
let isCreateVault = false;
let currentFilter = 'all';
let biometricStatus = null;
let daemonStatus = null;
let currentTotpMetadata = null;
let entriesRefreshInFlight = false;
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
const daemonStatusIndicator = document.getElementById('daemon-status-indicator');
// Initialize Application
async function init() {
    setupEventListeners();
    await checkVaultUnlocked();
    await refreshBiometricStatus();
    await refreshDaemonStatus();
    setInterval(() => {
        void refreshDaemonStatus();
    }, 15000);
    setInterval(() => {
        void backgroundRefreshEntries();
    }, 10000);
    window.addEventListener('focus', () => {
        void backgroundRefreshEntries();
    });
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            void backgroundRefreshEntries();
        }
    });
}
function setupEventListeners() {
    console.log('Setting up event listeners...');
    // Welcome Screen
    const createBtn = document.getElementById('create-vault-btn');
    const unlockBtn = document.getElementById('unlock-vault-btn');
    const unlockBiometricBtn = document.getElementById('unlock-biometric-btn');
    const settingsBtn = document.getElementById('settings-btn');
    console.log('Create vault button:', createBtn);
    console.log('Unlock vault button:', unlockBtn);
    if (createBtn) {
        createBtn.addEventListener('click', (e) => {
            console.log('Create vault button clicked!');
            showCreateVault();
        });
    }
    else {
        console.error('Create vault button not found!');
    }
    if (unlockBtn) {
        unlockBtn.addEventListener('click', (e) => {
            console.log('Unlock vault button clicked!');
            showUnlockVault();
        });
    }
    if (unlockBiometricBtn) {
        unlockBiometricBtn.addEventListener('click', unlockVaultWithBiometric);
    }
    document.getElementById('cancel-password').addEventListener('click', () => hidePasswordForm());
    passwordForm.addEventListener('submit', handlePasswordSubmit);
    masterPasswordInput.addEventListener('input', handlePasswordInput);
    // Vault Screen
    document.getElementById('lock-btn').addEventListener('click', lockVault);
    document.getElementById('add-entry-btn').addEventListener('click', createNewEntry);
    document.getElementById('refresh-entries-btn').addEventListener('click', refreshEntriesNow);
    document.getElementById('open-url-btn').addEventListener('click', openEntryUrl);
    if (settingsBtn) {
        settingsBtn.addEventListener('click', handleSettings);
    }
    searchInput.addEventListener('input', handleSearch);
    document.getElementById('detail-url').addEventListener('input', updateUrlOpenButtonState);
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
    document.getElementById('copy-totp').addEventListener('click', copyTotpForEntry);
    document.getElementById('configure-totp').addEventListener('click', openTotpModal);
    document.getElementById('remove-totp').addEventListener('click', removeTotpForEntry);
    document.getElementById('totp-form').addEventListener('submit', saveTotpForEntry);
    document.getElementById('cancel-totp').addEventListener('click', closeTotpModal);
    const totpModal = document.getElementById('totp-modal');
    if (totpModal) {
        totpModal.addEventListener('click', (event) => {
            if (event.target === totpModal) {
                closeTotpModal();
            }
        });
    }
    // Toggle password visibility in welcome screen
    document.getElementById('toggle-password').addEventListener('click', () => togglePasswordVisibility('master-password'));
    updateUrlOpenButtonState();
}
async function checkVaultUnlocked() {
    try {
        const unlocked = await invoke('is_unlocked');
        if (unlocked) {
            showVaultScreen();
            loadEntries();
        }
    }
    catch (error) {
        console.error('Error checking vault status:', error);
    }
}
async function refreshBiometricStatus() {
    try {
        biometricStatus = await invoke('biometric_status');
    }
    catch (error) {
        console.error('Error checking biometric status:', error);
        biometricStatus = null;
    }
    updateBiometricButton();
    return biometricStatus;
}
async function refreshDaemonStatus() {
    try {
        daemonStatus = await invoke('daemon_status');
    }
    catch (error) {
        daemonStatus = {
            available: false,
            unlocked: false,
            message: String(error)
        };
    }
    updateDaemonStatusBanner();
    return daemonStatus;
}
function updateDaemonStatusBanner() {
    if (!daemonStatusIndicator)
        return;
    if (!daemonStatus || (daemonStatus.available && daemonStatus.unlocked)) {
        daemonStatusIndicator.classList.add('hidden');
        daemonStatusIndicator.textContent = '';
        daemonStatusIndicator.classList.remove('warning', 'error');
        return;
    }
    let message = '';
    let type = 'warning';
    if (!daemonStatus.available) {
        type = 'error';
        message = daemonStatus.message
            ? `Browser integration daemon is unavailable (${daemonStatus.message}). SentinelPass will retry automatically.`
            : 'Browser integration daemon is unavailable. SentinelPass will retry automatically.';
    }
    else {
        message = 'Daemon is running but vault is locked. Unlock SentinelPass to re-enable browser autofill and save.';
    }
    daemonStatusIndicator.textContent = message;
    daemonStatusIndicator.classList.remove('hidden');
    daemonStatusIndicator.classList.remove('warning', 'error');
    daemonStatusIndicator.classList.add(type);
}
function updateBiometricButton() {
    const button = document.getElementById('unlock-biometric-btn');
    const label = document.getElementById('unlock-biometric-label');
    if (!button || !label)
        return;
    const methodName = biometricStatus?.method_name ||
        biometricStatus?.methodName ||
        'Biometric';
    label.textContent = `Unlock with ${methodName}`;
    const canUseBiometricUnlock = Boolean(biometricStatus?.available &&
        biometricStatus?.enrolled &&
        biometricStatus?.configured);
    button.classList.toggle('hidden', !canUseBiometricUnlock);
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
    }
    else {
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
    console.log('[SentinelPass UI] handlePasswordSubmit called', { isCreateVault });
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
            await refreshBiometricStatus();
            await refreshDaemonStatus();
        }
        catch (error) {
            showToast(error, 'error');
        }
    }
    else {
        try {
            console.log('[SentinelPass UI] Attempting unlock_vault invoke...');
            const unlockMessage = await invoke('unlock_vault', { masterPassword: password });
            console.log('[SentinelPass UI] unlock_vault response:', unlockMessage);
            const unlockType = typeof unlockMessage === 'string' && unlockMessage.includes('daemon unlock failed')
                ? 'warning'
                : 'success';
            showToast(unlockMessage || 'Vault unlocked successfully!', unlockType);
            showVaultScreen();
            loadEntries();
            await refreshBiometricStatus();
            const status = await refreshDaemonStatus();
            console.log('[SentinelPass UI] daemon_status after unlock:', status);
        }
        catch (error) {
            console.error('[SentinelPass UI] unlock_vault error:', error);
            showToast(error, 'error');
        }
    }
}
async function unlockVaultWithBiometric() {
    try {
        console.log('[SentinelPass UI] Attempting unlock_vault_biometric invoke...');
        const unlockMessage = await invoke('unlock_vault_biometric');
        console.log('[SentinelPass UI] unlock_vault_biometric response:', unlockMessage);
        const unlockType = typeof unlockMessage === 'string' && unlockMessage.includes('daemon biometric unlock failed')
            ? 'warning'
            : 'success';
        showToast(unlockMessage || 'Vault unlocked with biometric authentication!', unlockType);
        showVaultScreen();
        loadEntries();
        await refreshBiometricStatus();
        const status = await refreshDaemonStatus();
        console.log('[SentinelPass UI] daemon_status after biometric unlock:', status);
    }
    catch (error) {
        console.error('[SentinelPass UI] unlock_vault_biometric error:', error);
        showToast(error, 'error');
    }
}
async function handleSettings() {
    const status = await refreshBiometricStatus();
    if (!status) {
        showToast('Unable to load biometric settings', 'error');
        return;
    }
    const methodName = status.method_name || status.methodName || 'Biometric';
    if (!status.available) {
        showToast(`${methodName} is not available on this device`, 'warning');
        return;
    }
    if (!status.enrolled) {
        showToast(`${methodName} is not enrolled on this device`, 'warning');
        return;
    }
    if (status.configured) {
        const shouldDisable = await confirm(`Disable ${methodName} unlock for this vault?`, {
            title: 'Biometric Settings',
            kind: 'warning'
        });
        if (!shouldDisable)
            return;
        try {
            await invoke('disable_biometric_unlock');
            showToast(`${methodName} unlock disabled`, 'success');
            await refreshBiometricStatus();
        }
        catch (error) {
            showToast(error, 'error');
        }
        return;
    }
    const shouldEnable = await confirm(`Enable ${methodName} unlock for this vault? You will verify your identity during setup.`, {
        title: 'Biometric Settings',
        kind: 'info'
    });
    if (!shouldEnable)
        return;
    let masterPassword = await requestMasterPasswordForBiometric(methodName);
    if (masterPassword === null) {
        return;
    }
    try {
        await invoke('enable_biometric_unlock', { masterPassword });
        showToast(`${methodName} unlock enabled`, 'success');
        await refreshBiometricStatus();
    }
    catch (error) {
        showToast(error, 'error');
    }
    finally {
        masterPassword = '';
    }
}
async function lockVault() {
    try {
        await invoke('lock_vault');
        hidePasswordForm();
        welcomeScreen.classList.remove('hidden');
        vaultScreen.classList.add('hidden');
        currentEntry = null;
        currentTotpMetadata = null;
        entries = [];
        setTotpButtonState(false, false);
        closeTotpModal();
        await refreshBiometricStatus();
        await refreshDaemonStatus();
        showToast('Vault locked', 'success');
    }
    catch (error) {
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
    return loadEntriesWithOptions({
        preserveSelection: true,
        silent: false,
        selectionMissingToast: false
    });
}
function applyEntryFilters() {
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
async function loadEntriesWithOptions({ preserveSelection = true, silent = false, selectionMissingToast = false } = {}) {
    if (entriesRefreshInFlight) {
        return;
    }
    entriesRefreshInFlight = true;
    try {
        const selectedEntryId = preserveSelection ? currentEntry?.entry_id : null;
        entries = await invoke('list_entries');
        if (selectedEntryId && !entries.some(entry => entry.entry_id === selectedEntryId)) {
            currentEntry = null;
            currentTotpMetadata = null;
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
        entriesRefreshInFlight = false;
    }
}
async function backgroundRefreshEntries() {
    if (vaultScreen.classList.contains('hidden')) {
        return;
    }
    await loadEntriesWithOptions({
        preserveSelection: true,
        silent: true,
        selectionMissingToast: false
    });
}
async function refreshEntriesNow() {
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
        updateUrlOpenButtonState();
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
function createNewEntry() {
    currentEntry = null;
    currentTotpMetadata = null;
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
    updateUrlOpenButtonState();
    // Reset favorite button
    document.getElementById('detail-favorite').classList.remove('active');
    // Clear metadata
    document.getElementById('detail-created').textContent = '';
    document.getElementById('detail-modified').textContent = '';
    setTotpButtonState(false, false);
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
        }
        else {
            const entryId = await invoke('add_entry', { entry });
            entry.entry_id = entryId;
            showToast('Entry created successfully!', 'success');
        }
        currentEntry = entry;
        await loadEntries();
        loadEntry(entry.entry_id);
    }
    catch (error) {
        showToast(error, 'error');
    }
}
async function deleteEntry() {
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
        currentEntry = null;
        currentTotpMetadata = null;
        setTotpButtonState(false, false);
        await loadEntries();
        noSelection.classList.remove('hidden');
        entryDetail.classList.add('hidden');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
function toggleFavorite() {
    document.getElementById('detail-favorite').classList.toggle('active');
}
// Search & Filter
function handleSearch(e) {
    applyEntryFilters();
}
function handleFilter(filter) {
    currentFilter = filter;
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    if (filter === 'all') {
        applyEntryFilters();
    }
    else if (filter === 'favorites') {
        applyEntryFilters();
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
    }
    catch (error) {
        showToast(error, 'error');
    }
}
function updateUrlOpenButtonState() {
    const urlInput = document.getElementById('detail-url');
    const openButton = document.getElementById('open-url-btn');
    if (!urlInput || !openButton) {
        return;
    }
    const hasValue = urlInput.value.trim().length > 0;
    openButton.disabled = !hasValue;
    openButton.title = hasValue
        ? 'Open URL in default browser'
        : 'Enter URL to open';
}
async function openEntryUrl() {
    const urlInput = document.getElementById('detail-url');
    if (!urlInput) {
        showToast('URL field unavailable', 'error');
        return;
    }
    const rawUrl = urlInput.value;
    if (!rawUrl.trim()) {
        showToast('Enter a URL first', 'warning');
        urlInput.focus();
        return;
    }
    try {
        const normalized = normalizeLaunchUrl(rawUrl);
        await invoke('open_entry_url', { url: normalized });
        showToast('Opened in default browser', 'success');
    }
    catch (error) {
        const message = error?.message || String(error);
        showToast(message, 'error');
    }
}
async function updateTotpAvailability(entryId) {
    if (!entryId) {
        currentTotpMetadata = null;
        setTotpButtonState(false, false);
        return;
    }
    try {
        const metadata = await invoke('get_totp_metadata', { entryId });
        currentTotpMetadata = normalizeTotpMetadata(metadata);
        setTotpButtonState(true, Boolean(currentTotpMetadata));
    }
    catch (error) {
        console.error('Error checking TOTP status:', error);
        currentTotpMetadata = null;
        setTotpButtonState(true, false);
    }
}
function setTotpButtonState(hasSelection, configured) {
    const copyButton = document.getElementById('copy-totp');
    const configureButton = document.getElementById('configure-totp');
    const removeButton = document.getElementById('remove-totp');
    if (!copyButton || !configureButton || !removeButton)
        return;
    const canCopyOrRemove = hasSelection && configured;
    copyButton.disabled = !canCopyOrRemove;
    copyButton.title = canCopyOrRemove ? 'Copy TOTP code' : 'No TOTP configured';
    configureButton.disabled = !hasSelection;
    configureButton.title = hasSelection
        ? (configured ? 'Update TOTP' : 'Configure TOTP')
        : 'Select a saved entry first';
    removeButton.disabled = !canCopyOrRemove;
    removeButton.title = canCopyOrRemove ? 'Remove TOTP' : 'No TOTP configured';
}
function normalizeTotpMetadata(metadata) {
    if (!metadata)
        return null;
    return {
        algorithm: String(metadata.algorithm || 'sha1').toLowerCase(),
        digits: Number(metadata.digits || 6),
        period: Number(metadata.period || 30),
        issuer: metadata.issuer || '',
        accountName: metadata.account_name || metadata.accountName || ''
    };
}
async function copyTotpForEntry() {
    if (!currentEntry?.entry_id) {
        showToast('Select an entry first', 'warning');
        return;
    }
    try {
        const response = await invoke('get_totp_code', { entryId: currentEntry.entry_id });
        const code = response.code;
        const secondsRemaining = response.seconds_remaining ?? response.secondsRemaining;
        await writeText(code);
        showToast(`TOTP copied (${secondsRemaining}s remaining)`, 'success');
    }
    catch (error) {
        showToast(error, 'error');
        await updateTotpAvailability(currentEntry.entry_id);
    }
}
function openTotpModal() {
    if (!currentEntry?.entry_id) {
        showToast('Save the entry before configuring TOTP', 'warning');
        return;
    }
    const modal = document.getElementById('totp-modal');
    const title = document.getElementById('totp-modal-title');
    const uriInput = document.getElementById('totp-otpauth-uri');
    const secretInput = document.getElementById('totp-secret');
    const algorithmInput = document.getElementById('totp-algorithm');
    const digitsInput = document.getElementById('totp-digits');
    const periodInput = document.getElementById('totp-period');
    const issuerInput = document.getElementById('totp-issuer');
    const accountInput = document.getElementById('totp-account-name');
    if (!modal || !uriInput || !secretInput || !algorithmInput || !digitsInput || !periodInput || !issuerInput || !accountInput) {
        showToast('TOTP modal unavailable', 'error');
        return;
    }
    const metadata = currentTotpMetadata || {
        algorithm: 'sha1',
        digits: 6,
        period: 30,
        issuer: '',
        accountName: ''
    };
    title.textContent = currentTotpMetadata ? 'Update TOTP' : 'Configure TOTP';
    uriInput.value = '';
    secretInput.value = '';
    algorithmInput.value = metadata.algorithm;
    digitsInput.value = String(metadata.digits);
    periodInput.value = String(metadata.period);
    issuerInput.value = metadata.issuer;
    accountInput.value = metadata.accountName;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    secretInput.focus();
}
function closeTotpModal() {
    const modal = document.getElementById('totp-modal');
    if (!modal)
        return;
    const uriInput = document.getElementById('totp-otpauth-uri');
    const secretInput = document.getElementById('totp-secret');
    if (uriInput)
        uriInput.value = '';
    if (secretInput)
        secretInput.value = '';
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
}
async function saveTotpForEntry(event) {
    event.preventDefault();
    if (!currentEntry?.entry_id) {
        showToast('Save the entry before configuring TOTP', 'warning');
        return;
    }
    const uri = document.getElementById('totp-otpauth-uri').value.trim();
    const secret = document.getElementById('totp-secret').value.trim();
    const algorithm = document.getElementById('totp-algorithm').value;
    const digits = Number(document.getElementById('totp-digits').value);
    const period = Number(document.getElementById('totp-period').value);
    const issuer = document.getElementById('totp-issuer').value.trim();
    const accountName = document.getElementById('totp-account-name').value.trim();
    if (!uri && !secret) {
        showToast('Provide otpauth URI or base32 secret', 'warning');
        return;
    }
    try {
        await invoke('set_totp', {
            entryId: currentEntry.entry_id,
            secret: secret || null,
            otpauthUri: uri || null,
            algorithm,
            digits,
            period,
            issuer: issuer || null,
            accountName: accountName || null
        });
        closeTotpModal();
        await updateTotpAvailability(currentEntry.entry_id);
        showToast('TOTP configuration saved', 'success');
    }
    catch (error) {
        showToast(error, 'error');
    }
}
async function removeTotpForEntry() {
    if (!currentEntry?.entry_id) {
        showToast('Select an entry first', 'warning');
        return;
    }
    if (!currentTotpMetadata) {
        showToast('No TOTP configured for this entry', 'warning');
        return;
    }
    const confirmed = await confirm('Remove TOTP configuration for this entry?', {
        title: 'Remove TOTP',
        kind: 'warning'
    });
    if (!confirmed)
        return;
    try {
        await invoke('remove_totp', { entryId: currentEntry.entry_id });
        currentTotpMetadata = null;
        setTotpButtonState(true, false);
        showToast('TOTP removed', 'success');
    }
    catch (error) {
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
            try {
                const clipboard = await readText();
                if (clipboard === text) {
                    await writeText('');
                    showToast('Clipboard cleared', 'success');
                }
            }
            catch (clearError) {
                console.warn('Failed to clear clipboard:', clearError);
            }
        }, 30000);
    }
    catch (error) {
        showToast(error, 'error');
    }
}
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling || input.parentElement.querySelector('.btn-icon');
    if (input.type === 'password') {
        input.type = 'text';
        if (button)
            button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-5.06 5.94M1 1l22 22"/></svg>`;
    }
    else {
        input.type = 'password';
        if (button)
            button.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
}
async function requestMasterPasswordForBiometric(methodName) {
    const modal = document.getElementById('secure-password-modal');
    const title = document.getElementById('secure-password-title');
    const description = document.getElementById('secure-password-description');
    const form = document.getElementById('secure-password-form');
    const input = document.getElementById('secure-master-password');
    const cancelButton = document.getElementById('cancel-secure-password');
    const toggleButton = document.getElementById('toggle-secure-master-password');
    if (!modal || !title || !description || !form || !input || !cancelButton || !toggleButton) {
        showToast('Secure password prompt is unavailable', 'error');
        return null;
    }
    title.textContent = `Enable ${methodName} Unlock`;
    description.textContent = `Enter your master password to enable ${methodName} unlock for this vault.`;
    input.value = '';
    input.type = 'password';
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    await new Promise(resolve => setTimeout(resolve, 0));
    input.focus();
    return new Promise(resolve => {
        let finished = false;
        const cleanup = () => {
            form.removeEventListener('submit', onSubmit);
            cancelButton.removeEventListener('click', onCancel);
            toggleButton.removeEventListener('click', onToggleVisibility);
            modal.removeEventListener('click', onOverlayClick);
            document.removeEventListener('keydown', onEscape);
            input.value = '';
            input.type = 'password';
            modal.classList.add('hidden');
            modal.setAttribute('aria-hidden', 'true');
        };
        const finish = value => {
            if (finished)
                return;
            finished = true;
            cleanup();
            resolve(value);
        };
        const onSubmit = event => {
            event.preventDefault();
            const value = input.value;
            if (!value) {
                showToast('Master password is required', 'warning');
                input.focus();
                return;
            }
            finish(value);
        };
        const onCancel = () => finish(null);
        const onToggleVisibility = () => togglePasswordVisibility('secure-master-password');
        const onOverlayClick = event => {
            if (event.target === modal) {
                finish(null);
            }
        };
        const onEscape = event => {
            if (event.key === 'Escape') {
                event.preventDefault();
                finish(null);
            }
        };
        form.addEventListener('submit', onSubmit);
        cancelButton.addEventListener('click', onCancel);
        toggleButton.addEventListener('click', onToggleVisibility);
        modal.addEventListener('click', onOverlayClick);
        document.addEventListener('keydown', onEscape);
    });
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
// Initialize on load - wait for DOM and Tauri
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
}
else {
    initializeApp();
}
function initializeApp() {
    // Wait for Tauri to be available
    if (!initTauriAPI()) {
        console.error('Tauri API not available');
        return;
    }
    console.log('Tauri API loaded, initializing app...');
    init();
}
