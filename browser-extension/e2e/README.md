# Browser Integration Tests

These tests validate extension save-prompt behavior in a real Chromium browser:

- submit flow does not auto-save before explicit user action
- inline prompt `Not now` emits `NO_SAVE`
- inline prompt `Save` emits save intent and triggers save flow

## Prerequisites

- Node.js 20+
- Chromium installed by Playwright

## Setup

```bash
cd browser-extension/e2e
npm install
npx playwright install chromium
```

## Run

```bash
# headless
npm run test:e2e

# headed (useful for debugging)
npm run test:e2e:headed
```

If Playwright browser download is blocked in your environment, point tests to a local Chromium/Chrome:

```bash
CHROME_EXECUTABLE=/usr/bin/chromium-browser npm run test:e2e
```

## Notes

- Tests load the unpacked extension from `browser-extension/chrome`.
- A local fixture HTTP server is started automatically for login-flow simulation.
- Native host is not required for these tests; assertions rely on extension logs and message flow.
- Playwright config/test sources are TypeScript (`playwright.config.ts`, `tests/*.ts`).
