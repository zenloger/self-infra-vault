import { VaultCore, generatePassword } from './vault-core.js';

const vault = new VaultCore();
let queue = Promise.resolve();
const allowed = new Set(['unlock', 'create', 'list', 'read', 'password', 'upsert', 'remove', 'attach', 'attachment', 'removeAttachment', 'export', 'merge', 'synced']);
self.onmessage = ({ data }) => {
  queue = queue.then(async () => {
    const { id, op, args = [] } = data;
    try {
      if (!allowed.has(op) && op !== 'generate') throw Object.assign(new Error(), { code: 'InvalidInput' });
      const result = op === 'generate' ? generatePassword(...args) : await vault[op](...args);
      // Never send exception messages/stacks, which could contain user material.
      self.postMessage({ id, result }, result instanceof ArrayBuffer ? [result] : []);
    } catch (error) {
      self.postMessage({ id, error: typeof error.code === 'string' ? error.code : 'OperationFailed' });
    } finally {
      for (const arg of args) if (arg instanceof ArrayBuffer) new Uint8Array(arg).fill(0);
      args.fill(null);
    }
  });
};
