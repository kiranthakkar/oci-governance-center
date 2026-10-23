// Real Chromium form submission: unlike TestClient, the browser derives Origin from response policy.
// Run with Node 22+: node tests/browser/setup.mjs
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const chromePath = process.env.CHROME_PATH
  || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
assert(existsSync(chromePath), 'Set CHROME_PATH to a Chromium executable');
const temporary = await mkdtemp(join(tmpdir(), 'ogc-browser-'));
const profile = join(temporary, 'chrome');
const portServer = createServer();
await new Promise(resolve => portServer.listen(0, '127.0.0.1', resolve));
const port = portServer.address().port;
await new Promise(resolve => portServer.close(resolve));
const base = `http://127.0.0.1:${port}`;
const enrollment = process.argv.includes('--enrollment');
const keyFile = join(temporary, 'synthetic-scanner.pem');
const password = 'synthetic-browser-setup-password';
let server, chrome, socket;
async function until(check) {
  for (let attempt = 0; attempt < 200; attempt++) {
    try { const value = await check(); if (value) return value; } catch { /* Not ready yet. */ }
    await delay(100);
  }
  throw new Error('Timed out waiting for browser or application');
}
try {
  const serverArgs = enrollment ? ['tests/browser/enrollment_server.py', String(port)] : ['-c',
    'import uvicorn; from oci_governance_center.config import Settings; '
    + 'from oci_governance_center.web.app import create_app; '
    + `uvicorn.run(create_app(Settings()), host="127.0.0.1", port=${port}, access_log=False)`];
  server = spawn(resolve('.venv/bin/python'), serverArgs, {
    env: { ...process.env, OGC_PUBLIC_BASE_URL: base,
      OGC_ENCRYPTION_KEY: randomBytes(32).toString('base64url') + '=',
      OGC_SETUP_PASSWORD: password, OGC_DATA_ROOT: join(temporary, 'data'),
      OGC_BROWSER_KEY_FILE: keyFile },
    stdio: 'ignore',
  });
  await until(async () => (await fetch(`${base}/health`)).ok);
  chrome = spawn(chromePath, ['--headless=new', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--remote-debugging-port=0',
    `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
  const debugPort = await until(async () => (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
  const pages = await (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
  socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let sequence = 0;
  const pending = new Map();
  let submittedOrigin;
  let blockedRedirect = false;
  let externalLoginReached = false;
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const task = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) task.reject(new Error(message.error.message));
      else task.resolve(message.result);
    }
    if (message.method === 'Log.entryAdded' && message.params.entry.text.includes('form-action')) {
      blockedRedirect = true;
    }
    if (message.method === 'Fetch.requestPaused') {
      externalLoginReached = true;
      call('Fetch.fulfillRequest', {
        requestId: message.params.requestId, responseCode: 200,
        responseHeaders: [{name: 'Content-Type', value: 'text/html'}],
        body: Buffer.from('<html><body>Synthetic identity-domain login</body></html>').toString('base64'),
      }).catch(() => {});
    }
    if (message.method === 'Network.requestWillBeSentExtraInfo') {
      const headers = message.params.headers;
      if (headers.Origin !== undefined) submittedOrigin = headers.Origin;
    }
  });
  function call(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await call('Runtime.evaluate', { expression, returnByValue: true });
    if (result.exceptionDetails) throw new Error('Browser evaluation failed');
    return result.result.value;
  }
  await call('Network.enable');
  await call('Log.enable');
  await call('Fetch.enable', {patterns: [{
    urlPattern: 'https://idcs-' + 'a'.repeat(32) + '.identity.oraclecloud.com/oauth2/v1/authorize*',
    requestStage: 'Request',
  }]});
  await call('Page.navigate', { url: `${base}/setup` });
  await until(() => evaluate('Boolean(document.querySelector("input[name=password]"))'));
  await evaluate(`document.querySelector('input[name=password]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit();`);
  const text = await until(async () => {
    const content = await evaluate('document.body.innerText');
    return /Parent details|Cross-origin form rejected|Form expired/.test(content) && content;
  });
  console.log(JSON.stringify({ submittedOrigin, setupUnlocked: text.includes('Parent details') }));
  assert.equal(submittedOrigin, base, 'Browser must retain its same-origin POST Origin');
  assert(text.includes('Parent details'), 'Setup password submission must unlock parent onboarding');
  if (enrollment) {
    const inputs = JSON.parse(await readFile(keyFile.replace(/\.pem$/, '.json'), 'utf8'));
    async function fill(names) {
      const selected = Object.fromEntries(names.map(name => [name, inputs[name]]));
      await evaluate(`for (const [name, value] of Object.entries(${JSON.stringify(selected)})) document.querySelector('[name="' + name + '"]').value = value;`);
    }
    await fill(['name', 'tenancy_ocid', 'domain_ocid', 'guid', 'url', 'home_region']);
    await evaluate("document.querySelector('form[action=\"/setup/metadata\"]').requestSubmit()");
    await until(() => evaluate('Boolean(document.querySelector("input[name=private_key]"))'));
    await fill(['user_ocid', 'fingerprint', 'client_id', 'client_secret']);
    const documentNode = await call('DOM.getDocument');
    const input = await call('DOM.querySelector', {nodeId: documentNode.root.nodeId, selector: 'input[name=private_key]'});
    await call('DOM.setFileInputFiles', {nodeId: input.nodeId, files: [keyFile]});
    await evaluate("document.querySelector('form[action=\"/setup/credentials\"]').requestSubmit()");
    await until(async () => blockedRedirect || (externalLoginReached && await evaluate("document.body.innerText.includes('Synthetic identity-domain login')")));
    console.log(JSON.stringify({externalLoginReached, blockedRedirect}));
    assert(!blockedRedirect, 'CSP must permit the enrollment redirect to the configured identity domain');
    assert(externalLoginReached, 'Enrollment must reach the identity-domain authorization endpoint');
  }
} finally {
  socket?.close();
  for (const child of [chrome, server]) {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  }
  await rm(temporary, { recursive: true, force: true });
}
