import { test, expect, chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm } from 'node:fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXTENSION_PATH = path.resolve(__dirname, '..', '..', 'chrome');

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function startFixtureServer() {
  const server = createServer((req, res) => {
    if (!req.url) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('missing url');
      return;
    }

    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/login') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Fixture Login</h1>
    <form id="login-form" action="/after" method="get">
      <label for="username">Username</label>
      <input id="username" name="username" type="email" value="" />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" value="" />
      <button id="submit" type="submit">Sign in</button>
    </form>
  </body>
</html>`);
      return;
    }

    if (url.pathname === '/after') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>After Login</title></head>
  <body>
    <h1>Fixture After</h1>
    <p>Post-login destination page.</p>
  </body>
</html>`);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unable to determine fixture server address'));
        return;
      }
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
        hostname: '127.0.0.1'
      });
    });
  });
}

function stopFixtureServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function waitForServiceWorker(context) {
  const existing = context.serviceWorkers();
  if (existing.length > 0) {
    return existing[0];
  }
  return context.waitForEvent('serviceworker', { timeout: 15_000 });
}

function waitForLogMatch(logs, pattern, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise(async (resolve, reject) => {
    while (Date.now() < deadline) {
      if (logs.some((line) => pattern.test(line))) {
        resolve();
        return;
      }
      await delay(100);
    }
    reject(new Error(`Timed out waiting for log: ${pattern}`));
  });
}

function hasLogMatch(logs, pattern) {
  return logs.some((line) => pattern.test(line));
}

async function createHarness() {
  const fixture = await startFixtureServer();
  const userDataDir = await mkdtemp(path.join(tmpdir(), 'sentinelpass-e2e-'));
  const executablePath = process.env.CHROME_EXECUTABLE || undefined;
  const headless = process.env.HEADLESS === '1';
  const launchOptions = {
    headless,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`
    ]
  };
  if (executablePath) {
    launchOptions.executablePath = executablePath;
  } else {
    launchOptions.channel = 'chromium';
  }
  const context = await chromium.launchPersistentContext(userDataDir, launchOptions);

  const logs = [];
  const attachWorkerLogs = (worker) => {
    worker.on('console', (message) => {
      logs.push(message.text());
    });
  };

  context.on('serviceworker', attachWorkerLogs);
  context.serviceWorkers().forEach(attachWorkerLogs);

  const page = context.pages()[0] ?? (await context.newPage());
  await page.goto(`${fixture.baseUrl}/login`);

  const worker = await waitForServiceWorker(context);
  attachWorkerLogs(worker);
  return {
    ...fixture,
    context,
    page,
    worker,
    logs,
    userDataDir
  };
}

async function destroyHarness(harness) {
  await harness.context.close();
  await stopFixtureServer(harness.server);
  await rm(harness.userDataDir, { recursive: true, force: true });
}

async function seedPendingLogin(worker, payload) {
  await worker.evaluate((pendingLogin) => {
    return new Promise((resolve, reject) => {
      chrome.storage.local.set({ pendingLogin }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(true);
      });
    });
  }, payload);
}

test('submit flow does not auto-save before explicit click', async () => {
  const harness = await createHarness();
  try {
    const { page, baseUrl, logs } = harness;
    await page.goto(`${baseUrl}/login`);
    await page.fill('#username', 'singhvjd@gmail.com');
    await page.fill('#password', 'test-password-123');
    await page.click('#submit');
    await expect(page).toHaveURL(/\/after/);

    await waitForLogMatch(
      logs,
      /\[SentinelPass Background\] Save request source: (submit-button-click|submit-button-mousedown|form-submit)/
    );
    await waitForLogMatch(logs, /\[SentinelPass Background\] Save notification result: true/);

    await delay(1500);
    expect(hasLogMatch(logs, /\[SentinelPass Background\] Handling save_credential/)).toBeFalsy();
    expect(hasLogMatch(logs, /\[SentinelPass Background\] SAVE_INTENT_CONFIRMED/)).toBeFalsy();
  } finally {
    await destroyHarness(harness);
  }
});

test('inline prompt not-now emits NO_SAVE and does not call save', async () => {
  const harness = await createHarness();
  try {
    const { page, baseUrl, hostname, logs, worker } = harness;
    await seedPendingLogin(worker, {
      username: 'singhvjd@gmail.com',
      password: 'test-password-123',
      domain: hostname,
      url: `${baseUrl}/login`,
      timestamp: Date.now(),
      isNewPassword: false
    });

    await page.goto(`${baseUrl}/after`);
    await page.waitForSelector('.pm-save-prompt', { state: 'visible' });
    await waitForLogMatch(logs, /\[SentinelPass Background\] Inline save prompt shown/);
    await page.click('.pm-prompt-btn-notnow');

    await waitForLogMatch(logs, /\[SentinelPass Background\] NO_SAVE: no_save_not_now/);
    expect(hasLogMatch(logs, /\[SentinelPass Background\] Handling save_credential/)).toBeFalsy();
  } finally {
    await destroyHarness(harness);
  }
});

test('inline prompt save click emits save intent and triggers save call', async () => {
  const harness = await createHarness();
  try {
    const { page, baseUrl, hostname, logs, worker } = harness;
    await seedPendingLogin(worker, {
      username: 'singhvjd@gmail.com',
      password: 'test-password-123',
      domain: hostname,
      url: `${baseUrl}/login`,
      timestamp: Date.now(),
      isNewPassword: false
    });

    await page.goto(`${baseUrl}/after`);
    await page.waitForSelector('.pm-save-prompt', { state: 'visible' });
    await page.click('.pm-prompt-btn-save');

    await waitForLogMatch(logs, /\[SentinelPass Background\] SAVE_INTENT_CONFIRMED:/);
    await waitForLogMatch(logs, /\[SentinelPass Background\] Handling save_credential/);
  } finally {
    await destroyHarness(harness);
  }
});
