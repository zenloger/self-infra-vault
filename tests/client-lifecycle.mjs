import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const app = await readFile(new URL('../client/app.js', import.meta.url), 'utf8');
const html = await readFile(new URL('../client/index.html', import.meta.url), 'utf8');
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.dataset = {}; this.value = ''; this.hidden = false; this.disabled = false; this.inert = false; this.files = []; this.type = 'password'; this.textContent = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(type, fn) { const callbacks = this.listeners.get(type) || []; callbacks.push(fn); this.listeners.set(type, callbacks); }
  emit(type, target = this) { for (const fn of this.listeners.get(type) || []) fn({ target, preventDefault() {} }); }
  reportValidity() { return true; }
  reset() {}
  focus() {}
  remove() {}
  click() { this.emit('click'); }
}

async function setup() {
  const nodes = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  nodes['entry-form'].hidden = true;
  const grid = new Element(), document = new Element(), window = new Element(), timers = new Map(), requests = [], workers = [];
  document.getElementById = id => nodes[id]; document.createElement = tag => new Element(tag);
  document.querySelector = selector => selector === '.vault-grid' ? grid : nodes[selector.slice(1)]; document.body = new Element();
  const controls = { put: null, body: null, bodySignal: null };
  let timerId = 0;
  const response = (data, headers = {}) => ({ ok: true, status: 200,
    headers: { get: key => headers[key] || null }, json: async () => data, arrayBuffer: async () => data, text: async () => '' });
  const fetch = async (path, options) => {
    requests.push({ path, options });
    if (path === '/api/session') return response({ authenticated: true, configured: true, csrfToken: 'synthetic-csrf', user: { login: 'fixture' }, limits: { maxFileBytes: 64 * 1024 * 1024 } });
    if (path === '/api/vaults') return response({ files: [{ name: 'test.kdbx', size: 512, modified: '2026-01-01T00:00:00Z', revision: 'old' }] });
    if (options.method === 'PUT') return controls.put ? controls.put.promise : response({ name: 'test.version.kdbx', sourceName: 'test.kdbx', revision: 'new' });
    if (path.startsWith('/api/vault?')) {
      const result = response(new ArrayBuffer(8), { 'X-Vault-Revision': 'old' });
      if (controls.body) {
        const body = controls.body; controls.body = null; controls.bodySignal = options.signal;
        result.arrayBuffer = () => body.promise;
        options.signal.addEventListener('abort', () => body.reject(Object.assign(new Error(), { name: 'AbortError' })), { once: true });
      }
      return result;
    }
    return response({});
  };
  class Worker {
    constructor() { this.calls = []; this.terminated = false; workers.push(this); }
    postMessage({ id, op, args }) {
      this.calls.push({ op, args: structuredClone(args) });
      const listing = { entries: [{ id: 'one', title: 'fixture', username: 'account', groupId: 'group', group: 'fixture' }], groups: [{ id: 'group', name: 'fixture' }] };
      const entry = { id: 'one', groupId: 'group', fields: { Title: args[0]?.fields?.Title || 'fixture', UserName: 'account', Notes: '', URL: '' }, hasPassword: true, historyCount: 0, customFieldCount: 0, attachments: [] };
      let result = ['unlock', 'create', 'list', 'remove', 'merge'].includes(op) ? listing : ['read', 'upsert'].includes(op) ? entry : op === 'export' ? new ArrayBuffer(12) : op === 'password' ? 'synthetic password' : undefined;
      queueMicrotask(() => { if (!this.terminated) this.onmessage({ data: { id, result } }); });
    }
    terminate() { this.terminated = true; }
  }
  const context = vm.createContext({ document, window, Worker, fetch, AbortController, ArrayBuffer, Uint8Array, Blob,
    URL: { createObjectURL: () => 'blob:fixture', revokeObjectURL() {} }, navigator: { clipboard: { writeText: async () => {} } },
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; }, clearTimeout: id => timers.delete(id),
    confirm: () => true, console });
  vm.runInContext(app, context); await settle();
  const run = code => vm.runInContext(code, context);
  const unlock = async () => {
    run("prepareUnlock('test.kdbx', false)"); nodes.master.value = 'synthetic-master-only'; nodes['unlock-form'].emit('submit'); await settle();
  };
  return { nodes, grid, timers, requests, workers, controls, run, unlock, response };
}

test('sync serializes edits until PUT completes and updates the append-only filename', async () => {
  const { nodes, grid, controls, workers, run, unlock, response, requests } = await setup();
  await unlock(); assert.equal(run('opened'), true);
  nodes['entries'].children[0].children[0].emit('click'); await settle();
  nodes['entry-title'].value = 'edit A'; nodes['entry-form'].emit('input', nodes['entry-title']);
  controls.put = deferred(); nodes.sync.emit('click'); await settle();
  assert.equal(grid.inert, true); assert.equal(run('busy'), true);
  const before = workers[0].calls.filter(call => call.op === 'upsert').length;
  nodes['entry-form'].emit('submit'); await settle();
  assert.equal(workers[0].calls.filter(call => call.op === 'upsert').length, before, 'blocked submit cannot mutate snapshot in flight');
  const upload = requests.find(request => request.options.method === 'PUT');
  assert.ok(upload.options.body instanceof ArrayBuffer);
  assert.equal(upload.options.headers['If-Match'], 'old');
  assert.equal(JSON.stringify(requests.map(r => ({ path: r.path, headers: r.options.headers }))).includes('synthetic-master-only'), false);
  controls.put.resolve(response({ name: 'test.version.kdbx', sourceName: 'test.kdbx', revision: 'new' })); await settle();
  assert.equal(run('currentName'), 'test.version.kdbx'); assert.equal(run('dirty'), false); assert.equal(grid.inert, false);
});

test('lock aborts a pending body, cancels unlock and permits a clean subsequent worker', async () => {
  const { nodes, controls, workers, run, unlock } = await setup();
  controls.body = deferred(); await unlock();
  assert.equal(workers.length, 0); assert.equal(run('busy'), true);
  assert.equal(nodes['unlock-form'].inert, true);
  nodes['unlock-cancel'].emit('click'); await settle();
  assert.equal(controls.bodySignal.aborted, true); assert.equal(run('opened'), false); assert.equal(run('busy'), false);
  assert.equal(nodes['unlock-submit'].disabled, false);
  await unlock(); assert.equal(workers.length, 1); assert.equal(workers[0].terminated, false); assert.equal(run('opened'), true);
});

test('inactivity kills the worker and plaintext while retaining only encrypted recovery', async () => {
  const { nodes, timers, workers, run, unlock } = await setup(); await unlock();
  nodes['entries'].children[0].children[0].emit('click'); await settle();
  nodes['entry-title'].value = 'modified fixture'; nodes['entry-form'].emit('input', nodes['entry-title']);
  nodes['entry-form'].emit('submit'); await settle();
  assert.ok(run('recovery instanceof ArrayBuffer'));
  const timer = [...timers.values()].find(timer => timer.delay === 300_000); assert.ok(timer); timer.fn(); await settle();
  assert.equal(workers[0].terminated, true); assert.equal(run('worker'), null); assert.equal(run('opened'), false);
  assert.equal(nodes.entries.children.length, 0); assert.equal(nodes.workspace.hidden, true);
  assert.equal(nodes['recovery-panel'].hidden, false); assert.ok(run('recovery instanceof ArrayBuffer'));
  assert.equal(run('pending.size'), 0);
});

test('conflict keeps local changes and sealed recovery, with no blind overwrite retry', async () => {
  const { nodes, controls, requests, run, unlock, response } = await setup(); await unlock();
  nodes['entries'].children[0].children[0].emit('click'); await settle();
  nodes['entry-title'].value = 'conflicting local edit'; nodes['entry-form'].emit('input', nodes['entry-title']);
  controls.put = deferred(); nodes.sync.emit('click'); await settle();
  controls.put.resolve({ ...response({ error: 'conflict', revision: 'external' }), ok: false, status: 409 }); await settle();
  assert.equal(run('dirty'), true); assert.equal(run('currentRevision'), 'old');
  assert.equal(nodes.conflict.hidden, false); assert.ok(run('recovery instanceof ArrayBuffer'));
  assert.equal(requests.filter(request => request.options.method === 'PUT').length, 1);
});

test('new vault sends If-None-Match and is created only when the user synchronizes', async () => {
  const { nodes, requests, run } = await setup();
  run("prepareUnlock('', true)"); nodes['new-name'].value = 'fresh.kdbx'; nodes.master.value = 'synthetic master'; nodes['master-confirm'].value = 'synthetic master';
  nodes['unlock-form'].emit('submit'); await settle();
  assert.equal(requests.filter(request => request.options.method === 'PUT').length, 0);
  nodes.sync.emit('click'); await settle();
  const upload = requests.find(request => request.options.method === 'PUT');
  assert.equal(upload.options.headers['If-None-Match'], '*'); assert.equal(upload.options.headers['If-Match'], undefined);
});

test('request body timeout is visible; a late terminated-worker error cannot kill a new session', async () => {
  const { nodes, controls, timers, workers, run, unlock } = await setup();
  controls.body = deferred(); await unlock();
  const timer = [...timers.values()].find(timer => timer.delay === 65_000); timer.fn(); await settle();
  assert.match(nodes.status.textContent, /не ответил вовремя/);
  await unlock(); const old = workers[0]; run('lock(true)'); await unlock();
  old.onerror(); assert.equal(workers[1].terminated, false); assert.equal(run('opened'), true);
});

test('client and worker have no persistent plaintext storage, telemetry or dynamic HTML sinks', async () => {
  const worker = await readFile(new URL('../client/vault-worker.js', import.meta.url), 'utf8');
  assert.doesNotMatch(app, /\b(?:localStorage|sessionStorage|indexedDB|innerHTML|insertAdjacentHTML|eval)\b/);
  assert.doesNotMatch(worker, /\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|indexedDB)\b/);
  assert.doesNotMatch(html, /<script[^>]*src=["']https?:/);
  assert.doesNotMatch(html, /\son(?:click|load|error)=/);
});
