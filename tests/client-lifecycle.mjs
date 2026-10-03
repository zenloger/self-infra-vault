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
  const controls = { put: null, body: null, bodySignal: null, holdOps: new Set() };
  let timerId = 0, now = Date.now();
  class ClockDate extends Date { static now() { return now; } }
  for (const node of Object.values(nodes)) node.focus = () => { document.activeElement = node; };
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
      const listing = { entries: [{ id: 'one', title: 'fixture', username: 'account', groupId: 'group', group: 'fixture' }], groups: [{ id: 'group', name: 'fixture' }] };
      const entry = { id: 'one', groupId: 'group', fields: { Title: args[0]?.fields?.Title || 'fixture', UserName: 'account', Notes: '', URL: '' }, hasPassword: true, historyCount: 0, customFieldCount: 0, attachments: [] };
      let result = ['unlock', 'create', 'list', 'remove', 'merge'].includes(op) ? listing : ['read', 'upsert'].includes(op) ? entry : op === 'export' ? new ArrayBuffer(12) : op === 'password' ? 'synthetic password' : undefined;
      const call = { id, op, args: structuredClone(args), replied: false, reply: error => {
        call.replied = true; this.onmessage({ data: error ? { id, error } : { id, result } });
      } };
      this.calls.push(call);
      if (!controls.holdOps.has(op)) queueMicrotask(() => { if (!this.terminated) call.reply(); });
    }
    reply(op, error) { const call = this.calls.find(call => call.op === op && !call.replied); assert.ok(call, `pending ${op}`); call.reply(error); }
    terminate() { this.terminated = true; }
  }
  const context = vm.createContext({ document, window, Worker, fetch, AbortController, ArrayBuffer, Uint8Array, Blob, Date: ClockDate,
    URL: { createObjectURL: () => 'blob:fixture', revokeObjectURL() {} }, navigator: { clipboard: { writeText: async () => {} } },
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay, at: now + delay }); return timerId; }, clearTimeout: id => timers.delete(id),
    confirm: () => true, console });
  vm.runInContext(app, context); await settle();
  const run = code => vm.runInContext(code, context);
  const unlock = async () => {
    run("prepareUnlock('test.kdbx', false)"); nodes.master.value = 'synthetic-master-only'; nodes['unlock-form'].emit('submit'); await settle();
  };
  const advance = async milliseconds => {
    const end = now + milliseconds;
    for (;;) {
      const next = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      const [id, timer] = next; timers.delete(id); now = timer.at; timer.fn();
    }
    now = end; await settle();
  };
  return { nodes, grid, document, window, timers, requests, workers, controls, run, unlock, response, advance };
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

test('unlock shows an indeterminate loader and elapsed time for an arbitrarily long KDF', async () => {
  const { nodes, controls, workers, timers, run, unlock, advance } = await setup();
  controls.holdOps.add('unlock'); await unlock();
  assert.equal(nodes['operation-panel'].hidden, false); assert.match(nodes['operation-stage'].textContent, /Вычисляем ключ/);
  assert.equal(nodes['operation-cancel'].inert, false); assert.equal(nodes['operation-cancel'].disabled, false);
  assert.equal(nodes.master.value, ''); assert.equal(nodes['unlock-form']['aria-busy'], 'true');
  await advance(361_000);
  assert.equal(nodes['operation-elapsed'].textContent, '6:01'); assert.equal(workers[0].terminated, false);
  assert.equal(run('busy'), true); assert.equal(run('pending.size'), 1);
  workers[0].reply('unlock'); await settle();
  assert.equal(run('opened'), true); assert.equal(run('busy'), false); assert.equal(nodes['operation-panel'].hidden, true);
  assert.equal(workers[0].calls.filter(call => call.op === 'export').length, 0, 'opening never repeats the expensive KDF to make a snapshot');
  assert.equal([...timers.values()].filter(timer => timer.delay === 300_000).length, 1, 'idle locking starts after the KDF');
});

test('new vault creation keeps the loader across create and encryption and resumes idle locking', async () => {
  const { nodes, controls, workers, document, timers, run, advance } = await setup();
  controls.holdOps.add('create'); controls.holdOps.add('export');
  run("prepareUnlock('', true)"); nodes['new-name'].value = 'fresh.kdbx'; nodes.master.value = 'synthetic master'; nodes['master-confirm'].value = 'synthetic master';
  nodes['unlock-form'].emit('submit'); await settle();
  assert.match(nodes['operation-stage'].textContent, /Создаём/);
  await advance(15_000); workers[0].reply('create'); await settle();
  assert.match(nodes['operation-stage'].textContent, /шифруем/); assert.equal(run('opened'), true);
  assert.equal([...timers.values()].some(timer => timer.delay === 300_000), false);
  await advance(360_000); document.emit('visibilitychange');
  assert.equal(workers[0].terminated, false); assert.equal(nodes['operation-elapsed'].textContent, '6:15');
  workers[0].reply('export'); await settle();
  assert.equal(nodes['operation-panel'].hidden, true); assert.equal(run('recoveryUnsynced'), true);
  await advance(299_000); assert.equal(workers[0].terminated, false);
  await advance(1000); assert.equal(workers[0].terminated, true); assert.equal(nodes['recovery-panel'].hidden, false);
});

test('cancel releases the UI immediately, retains encrypted recovery and ignores old callbacks after reopen', async () => {
  const { nodes, controls, workers, run, unlock } = await setup(); await unlock();
  nodes.entries.children[0].children[0].emit('click'); await settle();
  nodes['entry-title'].value = 'saved local fixture'; nodes['entry-form'].emit('input', nodes['entry-title']);
  nodes['entry-form'].emit('submit'); await settle();
  assert.equal(run('recoveryUnsynced'), true);
  const sealed = run('recovery'); controls.holdOps.add('export'); nodes.sync.emit('click'); await settle();
  const old = workers[0]; nodes['operation-cancel'].emit('click');
  assert.equal(old.terminated, true); assert.equal(run('busy'), false); assert.equal(run('opened'), false);
  assert.equal(run('recovery'), sealed); assert.equal(run('recoveryUnsynced'), true); assert.equal(nodes['recovery-panel'].hidden, false);
  assert.equal(nodes.entries.children.length, 0); assert.equal(run('pending.size'), 0);
  controls.holdOps.add('unlock');
  // Start the next action before old promise catch/finally callbacks have run.
  run("prepareUnlock('test.kdbx', false)"); nodes.master.value = 'synthetic-master-only'; nodes['unlock-form'].emit('submit');
  await settle();
  old.reply('export', 'ResourceLimit'); old.onerror(); await settle();
  assert.equal(workers.length, 2); assert.equal(workers[1].terminated, false);
  assert.equal(run('busy'), true); assert.equal(nodes['unlock-form'].inert, true); assert.equal(nodes.sync.disabled, true);
  assert.equal(nodes['operation-panel'].hidden, false); assert.match(nodes['operation-stage'].textContent, /открываем/);
  assert.doesNotMatch(nodes.status.textContent, /не смог выделить память/);
  workers[1].reply('unlock'); await settle(); assert.equal(run('opened'), true); assert.equal(run('busy'), false);
});

test('resource failure hides the loader, clears pending calls and permits retry', async () => {
  const { nodes, controls, workers, run, unlock } = await setup();
  controls.holdOps.add('unlock'); await unlock(); workers[0].reply('unlock', 'ResourceLimit'); await settle();
  assert.match(nodes.status.textContent, /не смог выделить память/); assert.equal(nodes.status.dataset.error, 'true');
  assert.equal(nodes['operation-panel'].hidden, true); assert.equal(nodes['unlock-form'].inert, false); assert.equal(nodes['unlock-submit'].disabled, false);
  assert.equal(run('pending.size'), 0); assert.equal(run('cryptoCalls.size'), 0); assert.equal(run('busy'), false);
  assert.equal(workers[0].terminated, true); assert.equal(nodes.master.value, '');
  controls.holdOps.delete('unlock'); await unlock(); assert.equal(run('opened'), true);
});

test('save and merge expose stages, survive more than five minutes and keep idle locking afterwards', async () => {
  const { nodes, controls, workers, document, timers, run, unlock, advance, response } = await setup(); await unlock();
  controls.holdOps.add('export'); controls.put = deferred(); nodes.sync.emit('click'); await settle();
  assert.match(nodes['operation-stage'].textContent, /шифруем/);
  await advance(360_000); document.emit('visibilitychange'); assert.equal(workers[0].terminated, false); assert.equal(run('opened'), true);
  workers[0].reply('export'); await settle(); assert.match(nodes['operation-stage'].textContent, /Отправляем/);
  controls.put.resolve({ ...response({ error: 'conflict', revision: 'external' }), ok: false, status: 409 }); await settle();
  assert.equal(nodes.conflict.hidden, false); assert.equal(nodes['operation-panel'].hidden, true);
  controls.holdOps.add('merge'); nodes.merge.emit('click'); await settle();
  assert.match(nodes['operation-stage'].textContent, /объединяем/);
  await advance(360_000); document.emit('visibilitychange'); assert.equal(workers[0].terminated, false);
  workers[0].reply('merge'); await settle(); assert.match(nodes['operation-stage'].textContent, /шифруем/);
  await advance(360_000); assert.equal(workers[0].terminated, false);
  workers[0].reply('export'); await settle(); assert.equal(nodes['operation-panel'].hidden, true);
  assert.equal(run('dirty'), true); assert.equal(nodes.conflict.hidden, true);
  assert.equal([...timers.values()].filter(timer => timer.delay === 300_000).length, 1);
});

test('explicit lock, logout and pagehide still terminate active crypto', async () => {
  for (const trigger of ['lock', 'logout', 'pagehide']) {
    const { nodes, controls, workers, window, requests, run, unlock } = await setup();
    controls.holdOps.add('unlock'); await unlock();
    trigger === 'pagehide' ? window.emit('pagehide') : nodes[trigger].emit('click'); await settle();
    assert.equal(workers[0].terminated, true); assert.equal(run('busy'), false); assert.equal(run('pending.size'), 0);
    assert.equal(nodes['operation-panel'].hidden, true); assert.equal(run('opened'), false);
    if (trigger === 'logout') assert.equal(requests.filter(request => request.path === '/auth/logout').length, 1);
  }
});

test('loader is accessible, outside inert forms, responsive and respects reduced motion', async () => {
  const css = await readFile(new URL('../client/style.css', import.meta.url), 'utf8');
  const panel = html.match(/<section id="operation-panel"[\s\S]*?<\/section>/)[0];
  assert.match(panel, /role="progressbar"[^>]*aria-labelledby="operation-stage"[^>]*aria-describedby="operation-detail"/);
  assert.doesNotMatch(panel, /aria-valuenow/);
  assert.match(panel, /id="operation-stage"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(panel, /id="operation-elapsed" aria-live="off"/);
  assert.match(panel, /<button id="operation-cancel" type="button">Отменить и заблокировать<\/button>/);
  assert.ok(html.indexOf(panel) < html.indexOf('<section id="files-panel"'));
  assert.match(css, /@media\(max-width:800px\)\{\.operation-panel/);
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)\{\.operation-progress\{animation:none\}\}/);
});

test('client and worker have no persistent plaintext storage, telemetry or dynamic HTML sinks', async () => {
  const worker = await readFile(new URL('../client/vault-worker.js', import.meta.url), 'utf8');
  assert.doesNotMatch(app, /\b(?:localStorage|sessionStorage|indexedDB|innerHTML|insertAdjacentHTML|eval)\b/);
  assert.doesNotMatch(worker, /\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|indexedDB)\b/);
  assert.doesNotMatch(html, /<script[^>]*src=["']https?:/);
  assert.doesNotMatch(html, /\son(?:click|load|error)=/);
});
