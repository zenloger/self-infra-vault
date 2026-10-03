// Execute the production worker bundle without a browser or Node crypto APIs.
// String code generation is forbidden, matching the production script CSP.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';

const pending = new Map();
let sequence = 0;
const context = vm.createContext({
  crypto: webcrypto, TextEncoder, TextDecoder, WebAssembly, atob, btoa, setTimeout, clearTimeout,
  // Native crypto/encoding/WASM return host-realm BufferSources. Keep their
  // standard constructors in the same realm so instanceof matches a real worker.
  ArrayBuffer, Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array,
  Float32Array, Float64Array, DataView, BigInt64Array, BigUint64Array,
  console: { log() {}, warn() {}, error() {} },
}, { codeGeneration: { strings: false, wasm: true } });
context.self = context;
context.postMessage = ({ id, result, error }) => {
  const promise = pending.get(id);
  if (!promise) throw new Error('Unexpected worker response');
  pending.delete(id);
  error ? promise.reject(new Error(`${promise.op}: ${error}`)) : promise.resolve(result);
};
const bundle = await readFile(new URL('../dist/vault-worker.js', import.meta.url), 'utf8');
new vm.Script(bundle)
  .runInContext(context, { timeout: 5000 });

function rpc(op, args = []) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, op });
    context.onmessage({ data: { id, op, args } });
  });
}
const master = 'synthetic bundle check password';
await rpc('create', ['Synthetic test vault', master]);
const entry = await rpc('upsert', [{ fields: { Title: '<synthetic>', Password: 'synthetic-entry-secret' } }]);
const sealed = await rpc('export');
assert.equal(Buffer.from(sealed).includes(Buffer.from('synthetic-entry-secret')), false);
assert.equal(Buffer.from(sealed).subarray(0, 8).toString('hex'), '03d9a29a67fb4bb5');
await rpc('unlock', [sealed.slice(0), master]);
assert.equal(await rpc('password', [entry.id]), 'synthetic-entry-secret');
assert.equal(pending.size, 0);
console.log('PASS: bundled browser worker creates, encrypts and reopens KDBX with native WebCrypto; no Node globals or JS eval');

// Exercise actual thread termination while the production WASM KDF is busy.
// This synthetic header deliberately requires a long computation. Its public
// checksum is updated; its HMAC need not match, because we cancel during KDF.
const expensive = sealed.slice(0), view = new DataView(expensive);
const octets = new Uint8Array(expensive);
let cursor = 12, headerEnd = 0, changed = 0;
while (cursor < octets.length) {
  const id = octets[cursor++], size = view.getUint32(cursor, true); cursor += 4;
  if (id === 11) {
    let pos = cursor + 2;
    while (octets[pos++]) {
      const length = view.getUint32(pos, true); pos += 4;
      const name = new TextDecoder().decode(octets.subarray(pos, pos + length)); pos += length;
      const valueLength = view.getUint32(pos, true); pos += 4;
      if (name === 'I') { view.setBigUint64(pos, 1_000_000n, true); changed++; }
      if (name === 'M') { view.setBigUint64(pos, 1024n * 1024n, true); changed++; }
      pos += valueLength;
    }
  }
  cursor += size;
  if (!id) { headerEnd = cursor; break; }
}
assert.equal(changed, 2);
assert.ok(headerEnd > 0);
octets.set(new Uint8Array(await webcrypto.subtle.digest('SHA-256', expensive.slice(0, headerEnd))), headerEnd);

// Node supplies the thread transport only; the code under test is the unchanged
// production browser bundle. No UI/browser automation or real vault is used.
const threaded = new Worker(`
  const { parentPort, workerData } = require('node:worker_threads');
  globalThis.crypto = require('node:crypto').webcrypto;
  globalThis.self = globalThis;
  globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
  require('node:vm').runInThisContext(workerData);
  parentPort.on('message', data => { self.onmessage({ data }); parentPort.postMessage({ accepted: true }); });
  parentPort.postMessage({ ready: true });
`, { eval: true, workerData: bundle });
const events = [];
let threadError;
threaded.on('message', message => events.push(message));
threaded.on('error', error => { threadError = error; });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitUntil(predicate) {
  const started = performance.now();
  while (!predicate()) {
    if (threadError) throw threadError;
    assert.ok(performance.now() - started < 10_000, 'worker start deadline');
    await delay(10);
  }
}
try {
  await waitUntil(() => events.some(event => event.ready));
  threaded.postMessage({ id: 1, op: 'unlock', args: [expensive, master] }, [expensive]);
  await waitUntil(() => events.some(event => event.accepted));
  let mainThreadTicks = 0;
  const heartbeat = setInterval(() => mainThreadTicks++, 20);
  try { await delay(500); } finally { clearInterval(heartbeat); }
  assert.ok(mainThreadTicks >= 5, 'main thread remains responsive during expensive KDF');
  assert.equal(events.some(event => event.id === 1), false, 'expensive KDF is still running, not rejected by a cost cap');
  if (threadError) throw threadError;
  const cancelled = performance.now();
  await threaded.terminate();
  assert.ok(performance.now() - cancelled < 5_000, 'actual worker termination cancels the running KDF promptly');
  console.log('PASS: production worker accepts a million-pass KDF, keeps the main thread responsive and can be terminated');
} finally {
  await threaded.terminate();
}
