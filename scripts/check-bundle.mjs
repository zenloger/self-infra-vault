// Execute the production worker bundle without a browser or Node crypto APIs.
// String code generation is forbidden, matching the production script CSP.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

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
new vm.Script(await readFile(new URL('../dist/vault-worker.js', import.meta.url), 'utf8'))
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
await rpc('unlock', [sealed, master]);
assert.equal(await rpc('password', [entry.id]), 'synthetic-entry-secret');
assert.equal(pending.size, 0);
console.log('PASS: bundled browser worker creates, encrypts and reopens KDBX with native WebCrypto; no Node globals or JS eval');
