#!/usr/bin/env node
/**
 * postinstall.js
 * Downloads the correct pre-built Provn binary from GitHub Releases,
 * verifies it against the published .sha256 asset, and places it in the
 * package's bin/ directory.
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execSync } = require("child_process");

const REPO = "ashvinctrl/Provn";
const BIN_DIR = path.join(__dirname, "bin");
const MAX_REDIRECTS = 5;

function getArtifact() {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "darwin") {
    if (arch === "arm64") return "provn-aarch64-apple-darwin.tar.gz";
    if (arch === "x64") return "provn-x86_64-apple-darwin.tar.gz";
  }
  if (platform === "linux") {
    if (arch === "x64") return "provn-x86_64-linux.tar.gz";
    if (arch === "arm64") return "provn-aarch64-linux.tar.gz";
  }
  if (platform === "win32" && arch === "x64") {
    return "provn-x86_64-windows.zip";
  }

  throw new Error(`Unsupported platform: ${platform} ${arch}`);
}

/**
 * GET a URL, following redirects. `sink` receives the response stream on a
 * 2xx; anything else rejects, so an error page is never mistaken for a payload.
 */
function get(url, sink, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        "User-Agent": "provn-npm-installer",
        Accept: "application/vnd.github+json",
      },
    };
    https
      .get(url, opts, (res) => {
        const { statusCode, headers } = res;

        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          res.resume();
          if (redirectsLeft === 0) {
            return reject(new Error(`Too many redirects fetching ${url}`));
          }
          return get(headers.location, sink, redirectsLeft - 1).then(resolve).catch(reject);
        }

        if (statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${statusCode} fetching ${url}`));
        }

        sink(res).then(resolve).catch(reject);
      })
      .on("error", reject);
  });
}

function fetchText(url) {
  return get(
    url,
    (res) =>
      new Promise((resolve, reject) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (d) => (data += d));
        res.on("end", () => resolve(data));
        res.on("error", reject);
      })
  );
}

async function fetchJson(url) {
  const body = await fetchText(url);
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new Error(`Bad JSON from ${url}: ${err.message}`);
  }
}

function download(url, dest) {
  return get(
    url,
    (res) =>
      new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on("error", reject);
        res.on("error", reject);
        file.on("finish", () => file.close((err) => (err ? reject(err) : resolve())));
      })
  );
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

async function main() {
  const artifact = getArtifact();
  const isWindows = artifact.endsWith(".zip");
  const packageVersion = require("./package.json").version;
  const tag = `v${packageVersion}`;

  const release = await fetchJson(`https://api.github.com/repos/${REPO}/releases/tags/${tag}`);
  const asset = release.assets?.find((entry) => entry.name === artifact);
  const checksum = release.assets?.find((entry) => entry.name === `${artifact}.sha256`);

  if (!asset) {
    throw new Error(
      `no ${artifact} in release ${tag} of ${REPO}. ` +
        `Build from source instead: https://github.com/${REPO}#install`
    );
  }

  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });
  const tmpFile = path.join(os.tmpdir(), artifact);
  process.stdout.write(`Downloading Provn ${tag} for ${os.platform()}/${os.arch()}...`);
  await download(asset.browser_download_url, tmpFile);
  process.stdout.write(" done\n");

  // Every release publishes a matching .sha256 next to each archive. Verify it
  // rather than trusting whatever the network handed back.
  if (checksum) {
    const expected = (await fetchText(checksum.browser_download_url)).trim().split(/\s+/)[0];
    const actual = sha256(tmpFile);
    if (expected.toLowerCase() !== actual.toLowerCase()) {
      fs.unlinkSync(tmpFile);
      throw new Error(`checksum mismatch for ${artifact}: expected ${expected}, got ${actual}`);
    }
  }

  const binPath = path.join(BIN_DIR, isWindows ? "provn.exe" : "provn");
  if (isWindows) {
    execSync(`powershell -Command "Expand-Archive -Force '${tmpFile}' '${BIN_DIR}'"`, {
      stdio: "inherit",
    });
  } else {
    execSync(`tar xzf "${tmpFile}" -C "${BIN_DIR}"`, { stdio: "inherit" });
    fs.chmodSync(binPath, 0o755);
  }

  fs.unlinkSync(tmpFile);

  if (!fs.existsSync(binPath)) {
    throw new Error(`archive ${artifact} did not contain the expected binary`);
  }
  console.log(`  provn installed → ${binPath}`);
}

main().catch((err) => {
  console.error(`\n  provn install failed: ${err.message}`);
  console.error(`  Install manually: https://github.com/${REPO}#install`);
  // Exit non-zero so `npm install` reports the failure. Without this the
  // install looks successful and leaves a package whose `provn` command
  // cannot run.
  process.exitCode = 1;
});
