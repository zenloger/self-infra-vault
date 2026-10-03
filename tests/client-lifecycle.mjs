import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const app = await readFile(new URL('../client/app.js', import.meta.url), 'utf8');
const html = await readFile(new URL('../client/index.html', import.meta.url), 'utf8');
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve)); };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const descendants = node => [node, ...node.children.flatMap(descendants)];
const folderButton = (nodes, id) => descendants(nodes.folders).find(node => node.dataset.groupId === id);
const folderToggle = (nodes, id) => descendants(nodes.folders).find(node => node.dataset.folderToggle === id);
const entryTitles = nodes => nodes.entries.children.map(item => item.children[0].children[0].textContent);
const folderFixture = () => ({
  groups: [
    { id: 'root', title: 'Personal', name: 'Personal', parentId: null, depth: 0 },
    { id: 'work', title: 'Work / Ops', name: 'Personal / Work / Ops', parentId: 'root', depth: 1 },
    { id: 'shared', title: 'Same', name: 'Personal / Work / Ops / Same', parentId: 'work', depth: 2 },
    { id: 'private', title: 'Same', name: 'Personal / Same', parentId: 'root', depth: 1 },
    { id: 'empty', title: '<img src=x onerror=1>', name: 'Personal / <img src=x onerror=1>', parentId: 'root', depth: 1 },
    { id: 'container', title: 'Projects', name: 'Personal / Projects', parentId: 'root', depth: 1 },
    { id: 'nested', title: 'Archive', name: 'Personal / Projects / Archive', parentId: 'container', depth: 2 },
  ],
  entries: [
    { id: 'root-entry', title: 'Root account', username: 'root-user', groupId: 'root', group: 'Personal' },
    { id: 'work-entry', title: 'Work account', username: 'work-user', groupId: 'work', group: 'Personal / Work / Ops' },
    { id: 'shared-entry', title: 'Child account', username: 'child-user', groupId: 'shared', group: 'Personal / Work / Ops / Same' },
    { id: 'private-entry', title: 'Private account', username: 'private-user', groupId: 'private', group: 'Personal / Same' },
    { id: 'nested-entry', title: 'Archived account', username: 'archive-user', groupId: 'nested', group: 'Personal / Projects / Archive' },
  ],
});

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
  const controls = { put: null, body: null, bodySignal: null, revision: 'old', holdOps: new Set(), listing: null, confirmResult: true, confirmCalls: [] };
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
      const result = response(new ArrayBuffer(8), { 'X-Vault-Revision': controls.revision });
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
      const listing = controls.listing || { entries: [{ id: 'one', title: 'fixture', username: 'account', groupId: 'group', group: 'fixture' }], groups: [{ id: 'group', name: 'fixture', title: 'fixture', parentId: null, depth: 0 }] };
      const listed = listing.entries.find(entry => entry.id === (typeof args[0] === 'string' ? args[0] : args[0]?.id)) || listing.entries[0];
      const entry = { id: listed?.id || 'one', groupId: args[0]?.groupId || listed?.groupId || listing.groups[0]?.id, fields: { Title: args[0]?.fields?.Title || listed?.title || 'fixture', UserName: listed?.username || 'account', Notes: '', URL: '' }, hasPassword: true, historyCount: 0, customFieldCount: 0, attachments: [] };
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
    confirm: message => { controls.confirmCalls.push(message); return controls.confirmResult; }, console });
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

test('a cancelled key-file read cannot request or overwrite the subsequently opened vault', async () => {
  const { nodes, controls, requests, workers, run } = await setup();
  const keyRead = deferred(), oldKey = new Uint8Array([1, 2, 3, 4]);
  run("prepareUnlock('old.kdbx', false)");
  nodes['key-file'].files = [{ size: oldKey.byteLength, arrayBuffer: () => keyRead.promise }];
  nodes.master.value = 'old synthetic master'; nodes['unlock-form'].emit('submit'); await settle();
  assert.equal(workers.length, 0); assert.equal(requests.filter(request => request.path.startsWith('/api/vault?')).length, 0);
  nodes['operation-cancel'].emit('click');
  run("prepareUnlock('fresh.kdbx', false)"); nodes['key-file'].files = []; controls.revision = 'fresh-revision';
  nodes.master.value = 'new synthetic master'; nodes['unlock-form'].emit('submit'); await settle();
  assert.equal(run('opened'), true); assert.equal(run('currentRevision'), 'fresh-revision');
  const requestCount = requests.length, callCount = workers[0].calls.length;
  controls.revision = 'stale-revision'; keyRead.resolve(oldKey.buffer); await settle();
  assert.equal(requests.length, requestCount, 'old file read must not start a GET using new shared state');
  assert.equal(workers.length, 1); assert.equal(workers[0].calls.length, callCount); assert.equal(workers[0].terminated, false);
  assert.equal(run('currentName'), 'fresh.kdbx'); assert.equal(run('currentRevision'), 'fresh-revision');
  assert.equal(run('opened'), true); assert.equal(run('busy'), false); assert.equal(nodes['operation-panel'].hidden, true);
  assert.deepEqual([...oldKey], [0, 0, 0, 0], 'cancelled key-file bytes are wiped before aborting');
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

test('folders follow UUID hierarchy, count only direct entries and keep names as plain text', async () => {
  const { nodes, controls, workers, requests, run, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  assert.equal(run('selectedGroupId'), null); assert.equal(nodes['all-folders']['aria-current'], 'true');
  assert.equal(nodes['all-folders-count'].textContent, '5'); assert.equal(nodes.entries.children.length, 5);
  assert.equal(nodes['folder-path'].textContent, 'Все записи');
  const rootItem = nodes.folders.children[0], rootChildren = rootItem.children[1], workItem = rootChildren.children[0];
  assert.equal(workItem.children[0].children[1].children[0].textContent, 'Work / Ops', 'slash belongs to the folder title');
  assert.equal(workItem.children[1].children[0].children[0].children[1].dataset.groupId, 'shared');
  assert.equal(rootChildren.children[1].children[0].children[1].dataset.groupId, 'private', 'same-named groups keep their distinct parents');
  assert.equal(folderButton(nodes, 'root').children[1].textContent, '1');
  assert.equal(folderButton(nodes, 'container').children[1].textContent, '0', 'nested entry is not counted as a direct entry');
  assert.equal(folderButton(nodes, 'empty').children[0].textContent, '<img src=x onerror=1>');
  assert.equal(folderButton(nodes, 'empty').children[0].children.length, 0, 'hostile folder names are text, not markup');
  const calls = workers[0].calls.length, requestCount = requests.length;
  folderButton(nodes, 'work').emit('click'); await settle();
  assert.deepEqual(entryTitles(nodes), ['Work account']); assert.equal(nodes['folder-path'].textContent, 'Personal / Work / Ops');
  assert.equal(folderButton(nodes, 'work')['aria-current'], 'true'); assert.equal(nodes['all-folders']['aria-current'], 'false');
  folderButton(nodes, 'shared').emit('click'); assert.deepEqual(entryTitles(nodes), ['Child account']);
  folderButton(nodes, 'private').emit('click'); assert.deepEqual(entryTitles(nodes), ['Private account']);
  assert.equal(workers[0].calls.length, calls); assert.equal(requests.length, requestCount, 'folder navigation performs no RPC or network work');
});

test('search is scoped to the selected folder and empty folders explain direct-entry semantics', async () => {
  const { nodes, controls, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  folderButton(nodes, 'work').emit('click'); assert.equal(nodes['search-scope'].textContent, 'Поиск в выбранной папке');
  nodes.search.value = 'Child'; nodes.search.emit('input');
  assert.deepEqual(entryTitles(nodes), []); assert.match(nodes['no-entries'].textContent, /В этой папке ничего/);
  nodes['all-folders'].emit('click'); assert.deepEqual(entryTitles(nodes), ['Child account']);
  assert.equal(nodes['search-scope'].textContent, 'Поиск по всем записям');
  nodes.search.value = ''; nodes.search.emit('input');
  folderButton(nodes, 'empty').emit('click'); assert.equal(nodes['no-entries'].hidden, false); assert.match(nodes['no-entries'].textContent, /Создай первую/);
  folderButton(nodes, 'container').emit('click'); assert.deepEqual(entryTitles(nodes), []); assert.match(nodes['no-entries'].textContent, /Выбери вложенную папку/);
});

test('new entries default to the selected folder while existing entries keep their own group', async () => {
  const { nodes, controls, workers, run, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  nodes.entries.children[3].children[0].emit('click'); await settle();
  assert.equal(nodes['entry-group'].value, 'private', 'editing from All entries preserves the actual group');
  folderButton(nodes, 'empty').emit('click'); nodes['new-entry'].emit('click');
  assert.equal(nodes['entry-group'].value, 'empty');
  nodes['entry-title'].value = 'new certificate'; nodes['entry-form'].emit('input', nodes['entry-title']);
  nodes['entry-form'].emit('submit'); await settle();
  assert.equal(workers[0].calls.find(call => call.op === 'upsert').args[0].groupId, 'empty');
  assert.equal(run('selectedGroupId'), 'empty');
});

test('folder changes guard unsaved drafts, while collapsing a branch preserves the editor', async () => {
  const { nodes, controls, run, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  nodes.entries.children[0].children[0].emit('click'); await settle();
  nodes['entry-title'].value = 'unfinished edit'; nodes['entry-form'].emit('input', nodes['entry-title']);
  controls.confirmResult = false; folderButton(nodes, 'work').emit('click');
  assert.equal(run('selectedGroupId'), null); assert.equal(run('entryId'), 'root-entry');
  assert.equal(run('draftDirty'), true); assert.equal(nodes['entry-title'].value, 'unfinished edit');
  const prompts = controls.confirmCalls.length;
  folderToggle(nodes, 'work').emit('click'); assert.equal(folderToggle(nodes, 'work')['aria-expanded'], 'false');
  assert.equal(run('draftDirty'), true); assert.equal(controls.confirmCalls.length, prompts, 'disclosure alone never discards the editor');
  controls.confirmResult = true; folderButton(nodes, 'private').emit('click');
  assert.equal(run('selectedGroupId'), 'private'); assert.equal(run('draftDirty'), false); assert.equal(nodes['entry-form'].hidden, true);
  nodes['new-entry'].emit('click'); nodes['entry-title'].value = 'another unfinished edit'; nodes['entry-form'].emit('input', nodes['entry-title']);
  controls.confirmResult = false; nodes['all-folders'].emit('click');
  assert.equal(run('selectedGroupId'), 'private'); assert.equal(run('draftDirty'), true);
});

test('list refresh preserves selection and collapsed branches; lock and another database clear them', async () => {
  const { nodes, controls, run, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  folderButton(nodes, 'private').emit('click'); folderToggle(nodes, 'work').emit('click');
  const listing = folderFixture(); listing.entries.push({ id: 'additional', title: 'More private', username: '', groupId: 'private', group: 'Personal / Same' });
  run(`setListing(${JSON.stringify(listing)})`);
  assert.equal(run('selectedGroupId'), 'private'); assert.deepEqual(entryTitles(nodes), ['Private account', 'More private']);
  assert.equal(folderToggle(nodes, 'work')['aria-expanded'], 'false'); assert.equal(folderButton(nodes, 'private').children[1].textContent, '2');
  run('lock(true)');
  assert.equal(nodes.folders.children.length, 0); assert.equal(nodes['folder-path'].textContent, ''); assert.equal(nodes['all-folders-count'].textContent, '');
  assert.equal(run('selectedGroupId'), null); assert.equal(run('collapsedGroups.size'), 0); assert.equal(run('folderButtons.size'), 0);
  controls.listing = { groups: [{ id: 'next-root', title: 'Another database', name: 'Another database', parentId: null, depth: 0 }], entries: [] };
  run("prepareUnlock('another.kdbx', false)"); nodes.master.value = 'synthetic master'; nodes['unlock-form'].emit('submit'); await settle();
  assert.equal(run('selectedGroupId'), null); assert.equal(nodes['folder-path'].textContent, 'Все записи');
  assert.equal(folderButton(nodes, 'next-root').children[0].textContent, 'Another database'); assert.equal(folderButton(nodes, 'private'), undefined);
});

test('folder selection, disclosure and new-entry actions cannot mutate the UI during encryption', async () => {
  const { nodes, controls, workers, run, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  controls.holdOps.add('export'); nodes.sync.emit('click'); await settle();
  const callCount = workers[0].calls.length;
  folderButton(nodes, 'private').emit('click'); folderToggle(nodes, 'work').emit('click'); nodes['new-entry'].emit('click');
  assert.equal(run('selectedGroupId'), null); assert.equal(folderToggle(nodes, 'work')['aria-expanded'], 'true');
  assert.equal(nodes['entry-form'].hidden, true); assert.equal(workers[0].calls.length, callCount);
  nodes['operation-cancel'].emit('click'); await settle();
});

test('folder navigation uses labelled disclosures, a search scope and touch-sized controls', async () => {
  const { nodes, controls, unlock } = await setup(); controls.listing = folderFixture(); await unlock();
  const toggle = folderToggle(nodes, 'work'), branch = descendants(nodes.folders).find(node => node.id === toggle['aria-controls']);
  assert.ok(branch); assert.equal(branch.hidden, false); assert.equal(toggle['aria-expanded'], 'true');
  assert.match(toggle['aria-label'], /Свернуть папку/); toggle.emit('click');
  assert.equal(branch.hidden, true); assert.equal(toggle['aria-expanded'], 'false'); assert.match(toggle['aria-label'], /Развернуть папку/);
  assert.match(html, /<nav class="folder-nav" aria-label="Папки KeePass">/);
  assert.match(html, /id="search"[^>]*aria-describedby="folder-path"/);
  const css = await readFile(new URL('../client/style.css', import.meta.url), 'utf8');
  assert.match(css, /\.folder-toggle,\.folder-spacer\{[^}]*min-height:44px/);
  assert.match(css, /@media\(max-width:800px\)\{\.folders\{max-height:240px\}/);
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
