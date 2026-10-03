import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// Public updater key baked into the production app. No signing secret is used.
const publicKey = 'dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEY4QUI1Q0UxNUIwNzcwNjAKUldSZ2NBZGI0VnlyK0ZjbG92YTdQNkJseGk3Qjd2QkpJQU00cmRndHl5YXhOODZjZVFwMytYdlgK';
assert.ok(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === '--stable'));
const stable = process.argv[2] === '--stable';
const pointer = stable ? 'latest-windows.json' : 'latest-windows-prerelease.json';
const snapshot = readFileSync(pointer);
const manifest = JSON.parse(snapshot);
assert.match(manifest.version, /^\d+\.\d+\.\d+$/u);
assert.ok(Number.isFinite(Date.parse(manifest.pub_date)));
assert.deepEqual(Object.keys(manifest.platforms), ['windows-x86_64']);
const { signature, url } = manifest.platforms['windows-x86_64'];
const installerName = `drifty_${manifest.version}_x64-setup.exe`;
const match = url.match(/^https:\/\/github\.com\/edgethink00\/drifty_releases\/releases\/download\/([^/]+)\/([^/]+)$/u);
assert.ok(match);
const [, tag, filename] = match;
assert.equal(filename, installerName);
if (stable) assert.equal(tag, `${manifest.version}-win`);
else {
  assert.match(tag, /^\d+\.\d+\.\d+-winbeta\.\d+$/u);
  assert.ok(tag.startsWith(`${manifest.version}-winbeta.`));
}

if (process.env.BASE_SHA) {
  assert.match(process.env.BASE_SHA, /^[a-f0-9]{40}$/u);
  const oldBytes = execFileSync('git', ['show', `${process.env.BASE_SHA}:${pointer}`]);
  // The workflow for the changed channel enforces isolation. When shared
  // verifier code changes, the other workflow also validates its unchanged
  // feed without rejecting the independently verified channel advancement.
  const isolatedFiles = ['latest-prerelease.json', ...(snapshot.equals(oldBytes) ? [] : [stable ? 'latest-windows-prerelease.json' : 'latest-windows.json'])];
  for (const file of isolatedFiles) {
    assert.deepEqual(readFileSync(file), execFileSync('git', ['show', `${process.env.BASE_SHA}:${file}`]));
  }
  const old = JSON.parse(oldBytes);
  const parts = value => value.split('.').map(Number);
  const next = parts(manifest.version), prior = parts(old.version);
  const firstDifference = next.findIndex((value, index) => value !== prior[index]);
  // A verifier-only PR may inspect the unchanged other channel. A changed
  // pointer must advance its numeric version, including same-version RC swaps.
  assert.ok(snapshot.equals(oldBytes) || (firstDifference >= 0 && next[firstDifference] > prior[firstDifference]), 'Changed pointer must advance the numeric version');
}

const download = async endpoint => {
  assert.ok(endpoint.startsWith('https://'));
  const response = await fetch(endpoint, { signal: AbortSignal.timeout(60000) });
  assert.equal(response.status, 200, `Public download failed: ${endpoint}`);
  const declared = response.headers.get('content-length');
  if (declared) assert.ok(Number(declared) <= 512 * 1024 ** 2);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.ok(bytes.length <= 512 * 1024 ** 2);
  return bytes;
};
const release = JSON.parse((await download(`https://api.github.com/repos/edgethink00/drifty_releases/releases/tags/${tag}`)).toString());
assert.equal(release.draft, false);
assert.equal(release.prerelease, !stable);
assert.equal(release.tag_name, tag);
const names = [installerName, `${installerName}.sig`, pointer, ...(stable ? ['update-policy.json'] : [])].sort();
assert.deepEqual(release.assets.map(asset => asset.name).sort(), names);
const assetBytes = new Map();
for (const asset of release.assets) {
  assert.equal(asset.state, 'uploaded');
  const expectedUrl = `https://github.com/edgethink00/drifty_releases/releases/download/${tag}/${asset.name}`;
  assert.equal(asset.browser_download_url, expectedUrl);
  const bytes = await download(expectedUrl);
  assert.equal(bytes.length, asset.size);
  assert.equal(`sha256:${createHash('sha256').update(bytes).digest('hex')}`, asset.digest);
  assetBytes.set(asset.name, bytes);
}
assert.deepEqual(assetBytes.get(pointer), snapshot, 'Live pointer must equal immutable snapshot bytes');
assert.equal(assetBytes.get(`${installerName}.sig`).toString(), signature);
if (stable) {
  const bytes = assetBytes.get('update-policy.json');
  assert.ok(bytes.length <= 16 * 1024);
  const policy = JSON.parse(bytes);
  assert.equal(policy.version, manifest.version);
  assert.equal(policy.policyVersion, 2);
  assert.ok(['general', 'urgent'].includes(policy.urgency));
  assert.equal(policy.backgroundDownload, policy.urgency === 'general');
  assert.equal(policy.installBehavior, policy.urgency === 'general' ? 'idle' : 'manual');
  assert.equal(policy.promptAfterHours, 72);
  assert.equal(policy.autoInstall, false);
  assert.ok(typeof policy.message === 'string' && policy.message.trim());
  const latest = JSON.parse((await download('https://api.github.com/repos/edgethink00/drifty_releases/releases/latest')).toString());
  assert.notEqual(latest.tag_name, tag, 'Windows must not replace the shared Mac latest release');
}

const decode = (value, size) => {
  assert.match(value, /^[A-Za-z0-9+/]+={0,2}$/u);
  const bytes = Buffer.from(value, 'base64');
  assert.equal(bytes.toString('base64'), value);
  if (size !== undefined) assert.equal(bytes.length, size);
  return bytes;
};
const keyLines = decode(publicKey).toString().trimEnd().split('\n');
const sigLines = decode(signature).toString().trimEnd().split('\n');
assert.equal(keyLines.length, 2);
assert.equal(sigLines.length, 4);
assert.ok(sigLines[0].startsWith('untrusted comment: '));
assert.ok(sigLines[2].startsWith('trusted comment: '));
const key = decode(keyLines[1], 42), packet = decode(sigLines[1], 74);
assert.equal(key.subarray(0, 2).toString(), 'Ed');
assert.equal(packet.subarray(0, 2).toString(), 'ED');
assert.deepEqual(packet.subarray(2, 10), key.subarray(2, 10));
const nativeKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key.subarray(10)]), format: 'der', type: 'spki' });
const signatureBytes = packet.subarray(10);
assert.ok(verify(null, createHash('blake2b512').update(assetBytes.get(installerName)).digest(), nativeKey, signatureBytes), 'Installer signature must verify');
assert.ok(verify(null, Buffer.concat([signatureBytes, Buffer.from(sigLines[2].slice('trusted comment: '.length))]), nativeKey, decode(sigLines[3], 64)), 'Trusted comment must verify');
console.log(`Verified ${tag}: ${names.length} exact public assets, signed installer, isolated monotonic Windows ${stable ? 'stable' : 'developer'} pointer.`);
