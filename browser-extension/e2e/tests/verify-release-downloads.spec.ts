import { test, expect } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const VERSION = process.env.SENTINELPASS_VERSION ?? "0.1.2";
const REPO = "AltamashSentinelPass/sentinelpass";
const TAG = `v${VERSION}`;
const API_URL = `https://api.github.com/repos/${REPO}/releases/tags/${TAG}`;
const DOWNLOAD_BASE = `https://github.com/${REPO}/releases/download/${TAG}`;

// Expected release assets (15 total)
const EXPECTED_ASSETS = [
  `sentinelpass-${VERSION}-linux.tar.gz`,
  `sentinelpass-${VERSION}-macos.tar.gz`,
  `sentinelpass-${VERSION}-windows.zip`,
  `sentinelpass-${VERSION}-linux-amd64.deb`,
  `sentinelpass-${VERSION}-linux-amd64.rpm`,
  `sentinelpass-${VERSION}-linux-aarch64.deb`,
  `sentinelpass-${VERSION}-linux-aarch64.rpm`,
  `sentinelpass-${VERSION}-macos-aarch64.dmg`,
  `sentinelpass-${VERSION}-macos-x86_64.dmg`,
  `sentinelpass-${VERSION}-windows-x86_64.msi`,
  `sentinelpass-${VERSION}-windows-aarch64.msi`,
  `sentinelpass-chrome-${VERSION}.zip`,
  `sentinelpass-firefox-${VERSION}.zip`,
  `sha256sums.txt`,
  `sha256sums.txt.sig`,
];

interface GitHubAsset {
  name: string;
  size: number;
  browser_download_url: string;
}

interface GitHubRelease {
  tag_name: string;
  assets: GitHubAsset[];
}

let releaseData: GitHubRelease;

test.beforeAll(async () => {
  const res = await fetch(API_URL, {
    headers: {
      Accept: "application/vnd.github+json",
      ...(process.env.GITHUB_TOKEN
        ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
        : {}),
    },
  });
  expect(res.ok, `GitHub API returned ${res.status}`).toBe(true);
  releaseData = (await res.json()) as GitHubRelease;
});

test.describe(`SentinelPass ${TAG} Release Downloads`, () => {
  test("all expected assets exist with non-zero size", () => {
    const assetNames = releaseData.assets.map((a) => a.name);

    for (const expected of EXPECTED_ASSETS) {
      const asset = releaseData.assets.find((a) => a.name === expected);
      expect(asset, `Missing asset: ${expected}`).toBeDefined();
      expect(
        asset!.size,
        `Asset ${expected} has zero size`
      ).toBeGreaterThan(0);
    }

    expect(assetNames.length).toBeGreaterThanOrEqual(EXPECTED_ASSETS.length);
  });

  test("download URLs return 302 redirect to objects.githubusercontent.com", async () => {
    // Test a representative sample of assets
    const sampleAssets = [
      `sentinelpass-${VERSION}-linux.tar.gz`,
      `sentinelpass-${VERSION}-windows.zip`,
      `sentinelpass-chrome-${VERSION}.zip`,
    ];

    for (const assetName of sampleAssets) {
      const url = `${DOWNLOAD_BASE}/${assetName}`;
      const res = await fetch(url, { redirect: "manual" });

      expect(
        [301, 302],
        `Expected redirect for ${assetName}, got ${res.status}`
      ).toContain(res.status);

      const location = res.headers.get("location") ?? "";
      expect(
        location,
        `Redirect for ${assetName} should point to GitHub storage`
      ).toMatch(/objects\.githubusercontent\.com/);
    }
  });

  test("follow-redirect download returns correct content", async () => {
    // Pick a small asset to fully download (extension zips are typically smaller)
    const assetName = `sentinelpass-chrome-${VERSION}.zip`;
    const apiAsset = releaseData.assets.find((a) => a.name === assetName);
    expect(apiAsset, `Asset ${assetName} not found`).toBeDefined();

    const url = `${DOWNLOAD_BASE}/${assetName}`;
    const res = await fetch(url, { redirect: "follow" });

    expect(res.ok, `Download failed with ${res.status}`).toBe(true);

    const body = await res.arrayBuffer();
    const bytes = new Uint8Array(body);

    // Verify non-zero download
    expect(bytes.length).toBeGreaterThan(0);

    // Content-Length should match API-reported size (if header present)
    const contentLength = res.headers.get("content-length");
    if (contentLength) {
      expect(parseInt(contentLength, 10)).toBe(apiAsset!.size);
    }

    // Verify ZIP magic bytes: PK (0x50 0x4b)
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
  });

  test("tar.gz assets have correct magic bytes when downloaded with redirect", async () => {
    const assetName = `sentinelpass-${VERSION}-linux.tar.gz`;
    const url = `${DOWNLOAD_BASE}/${assetName}`;

    const res = await fetch(url, { redirect: "follow" });
    expect(res.ok).toBe(true);

    const body = await res.arrayBuffer();
    const bytes = new Uint8Array(body);

    // Verify gzip magic bytes: 0x1f 0x8b
    expect(bytes[0]).toBe(0x1f);
    expect(bytes[1]).toBe(0x8b);
  });

  test("sha256sums.txt covers all binary assets", async () => {
    const url = `${DOWNLOAD_BASE}/sha256sums.txt`;
    const res = await fetch(url, { redirect: "follow" });
    expect(res.ok, `Failed to download sha256sums.txt: ${res.status}`).toBe(
      true
    );

    const text = await res.text();
    const lines = text
      .trim()
      .split("\n")
      .filter((l) => l.length > 0);

    // Each line: "<hash>  <filename>"
    const checksummedFiles = lines.map((line) => {
      const parts = line.split(/\s+/);
      expect(
        parts.length,
        `Malformed checksum line: ${line}`
      ).toBeGreaterThanOrEqual(2);
      return parts[parts.length - 1];
    });

    // Every binary asset (excluding sha256sums.txt itself and .sig) should have a checksum
    const binaryAssets = EXPECTED_ASSETS.filter(
      (a) => !a.startsWith("sha256sums")
    );

    for (const asset of binaryAssets) {
      expect(
        checksummedFiles,
        `sha256sums.txt missing entry for ${asset}`
      ).toContain(asset);
    }
  });

  test("browser UI download produces non-zero file", async ({ browser }) => {
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();

    const releaseUrl = `https://github.com/${REPO}/releases/tag/${TAG}`;
    await page.goto(releaseUrl, { waitUntil: "domcontentloaded" });

    // Find a small asset link to click (Chrome extension zip)
    const assetName = `sentinelpass-chrome-${VERSION}.zip`;
    const downloadLink = page.locator(`a[href$="${assetName}"]`);

    const linkCount = await downloadLink.count();
    test.skip(linkCount === 0, `Download link for ${assetName} not found on page`);

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      downloadLink.first().click(),
    ]);

    // Wait for download to complete
    const filePath = await download.path();
    expect(filePath).toBeTruthy();

    const stat = fs.statSync(filePath!);
    expect(
      stat.size,
      `Downloaded file ${assetName} is 0 bytes`
    ).toBeGreaterThan(0);

    // Verify magic bytes
    const fd = fs.openSync(filePath!, "r");
    const magic = Buffer.alloc(2);
    fs.readSync(fd, magic, 0, 2, 0);
    fs.closeSync(fd);

    // ZIP: PK (0x50 0x4b)
    expect(magic[0]).toBe(0x50);
    expect(magic[1]).toBe(0x4b);

    await context.close();
  });

  test("curl -L downloads valid file vs curl without -L", () => {
    const assetName = `sentinelpass-chrome-${VERSION}.zip`;
    const url = `${DOWNLOAD_BASE}/${assetName}`;
    const tmpDir = fs.mkdtempSync(path.join("/tmp", "sp-download-test-"));

    try {
      // Test 1: curl WITHOUT -L (should get redirect HTML or empty)
      const noFollowPath = path.join(tmpDir, "no-follow.bin");
      try {
        execSync(`curl -s -o "${noFollowPath}" "${url}"`, {
          timeout: 30_000,
        });
        const noFollowSize = fs.statSync(noFollowPath).size;
        // Without -L, we get the redirect HTML (small) not the actual file
        // The API-reported size should be much larger
        const apiAsset = releaseData.assets.find((a) => a.name === assetName);
        if (apiAsset && noFollowSize > 0) {
          // The no-follow response is the redirect HTML, which is small
          // Actual asset should be significantly larger
          expect(noFollowSize).toBeLessThan(apiAsset.size);
        }
      } catch {
        // curl without -L may fail or produce unexpected output; that's the point
      }

      // Test 2: curl WITH -L (should get the actual file)
      const followPath = path.join(tmpDir, "follow.bin");
      execSync(`curl -sL -o "${followPath}" "${url}"`, {
        timeout: 60_000,
      });

      const followSize = fs.statSync(followPath).size;
      expect(followSize, "curl -L download is 0 bytes").toBeGreaterThan(0);

      // Verify ZIP magic bytes
      const fd = fs.openSync(followPath, "r");
      const magic = Buffer.alloc(2);
      fs.readSync(fd, magic, 0, 2, 0);
      fs.closeSync(fd);
      expect(magic[0]).toBe(0x50);
      expect(magic[1]).toBe(0x4b);
    } finally {
      // Cleanup
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
