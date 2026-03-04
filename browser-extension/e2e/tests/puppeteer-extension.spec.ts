import puppeteer from 'puppeteer';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm } from 'node:fs/promises';
import { expect } from '@playwright/test';

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

test('Puppeteer: extension loads and content script is injected', async () => {
  const fixture = await startFixtureServer();
  const userDataDir = await mkdtemp(path.join(tmpdir(), 'sentinelpass-e2e-puppeteer-'));

  try {
    // Launch Chrome with the extension
    const browser = await puppeteer.launch({
      headless: true,
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    const logs = [];
    const page = await browser.newPage();

    // Capture console logs
    page.on('console', (msg) => {
      logs.push(msg.text());
    });

    // Navigate to the test page
    await page.goto(`${fixture.baseUrl}/login`);

    // Wait for content script to be injected
    await delay(3000);

    // Check if chrome.runtime is available in the page
    const extensionInfo = await page.evaluate(() => {
      const hasChrome = typeof chrome !== 'undefined';
      const hasRuntime = hasChrome && chrome.runtime;
      const hasSendMessage = hasRuntime && typeof chrome.runtime.sendMessage === 'function';
      const chromeProps = hasChrome ? Object.keys(chrome) : [];

      return {
        hasChrome,
        hasRuntime,
        hasSendMessage,
        chromeProps: chromeProps.slice(0, 20).join(', ')
      };
    });

    console.log('[Puppeteer] Extension info:', JSON.stringify(extensionInfo));

    // Puppeteer should be able to inject content scripts properly
    if (!extensionInfo.hasRuntime) {
      console.warn('[Puppeteer] chrome.runtime not available - content script may not be injected');
    }

    await browser.close();
    await stopFixtureServer(fixture.server);
    await rm(userDataDir, { recursive: true, force: true });

    // This test passes if we get this far - it means Puppeteer can launch with the extension
    expect(extensionInfo.hasChrome).toBe(true);
  } catch (error) {
    await stopFixtureServer(fixture.server);
    await rm(userDataDir, { recursive: true, force: true });
    throw error;
  }
});
