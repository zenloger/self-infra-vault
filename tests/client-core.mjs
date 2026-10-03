import test from 'node:test';
import assert from 'node:assert/strict';
import * as K from 'kdbxweb';
import { VaultCore, deriveArgon2, validateArgon2Parameters, generatePassword, inspectHeader, LIMITS } from '../client/vault-core.js';

const password = 'synthetic master password only';
const encode = (text) => new TextEncoder().encode(text).buffer;
const decode = (data) => new TextDecoder().decode(data);

test('KDBX4 Argon2id roundtrip preserves groups, protected fields, history and certificate attachments', async () => {
  const vault = new VaultCore(); await vault.create('Синтетический <vault>', password);
  const group = vault.db.createGroup(vault.db.getDefaultGroup(), 'Certificates <script>');
  let entry = vault.upsert({ groupId: group.uuid.id, fields: { Title: '<img src=x onerror=alert(1)>', UserName: 'a&b', Password: 'fixture-old', URL: 'javascript:synthetic', Notes: 'строка\n漢字' } });
  vault.entry(entry.id).fields.set('CustomProtected', K.ProtectedValue.fromString('synthetic custom secret'));
  entry = vault.upsert({ id: entry.id, groupId: group.uuid.id, fields: { Password: 'fixture-new', Notes: 'changed' } });
  await vault.attach(entry.id, 'synthetic.pem', encode('-----BEGIN SYNTHETIC ONLY-----\nabc\n'));
  await vault.attach(entry.id, 'synthetic.key', encode('synthetic private key bytes'));
  const data = await vault.export();
  assert.equal(inspectHeader(data), 4);
  assert.equal(decode(data).includes('fixture-new'), false);
  assert.equal(decode(data).includes('synthetic private key'), false);
  const opened = new VaultCore(); await opened.unlock(data, password);
  assert.equal(opened.password(entry.id), 'fixture-new');
  assert.equal(opened.read(entry.id).fields.Title, '<img src=x onerror=alert(1)>');
  assert.equal(opened.read(entry.id).fields.Password, undefined, 'password is not part of normal entry metadata');
  assert.equal(opened.read(entry.id).customFieldCount, 1);
  assert.equal(opened.entry(entry.id).fields.get('CustomProtected').getText(), 'synthetic custom secret');
  assert.equal(opened.entry(entry.id).parentGroup.name, 'Certificates <script>');
  assert.ok(opened.read(entry.id).historyCount >= 3);
  assert.equal(decode(opened.attachment(entry.id, 'synthetic.key')), 'synthetic private key bytes');
  assert.equal(opened.read(entry.id).attachments.find(a => a.name === 'synthetic.key').size, 27);
  assert.throws(() => opened.removeAttachment(entry.id, 'not-found'), { code: 'NotFound' });
  opened.removeAttachment(entry.id, 'synthetic.key');
  assert.equal(opened.read(entry.id).attachments.length, 1);
  await assert.rejects(opened.attach(entry.id, 'synthetic.pem', encode('new')), { code: 'AttachmentExists' });
  await assert.rejects(opened.attach(entry.id, '../bad', encode('new')), { code: 'InvalidInput' });
  opened.lock(); assert.throws(() => opened.list(), { code: 'Locked' });
});

test('KDBX3 AES and KDBX4 Argon2d import/export, wrong credentials, tampering', async () => {
  for (const version of [3, 4]) {
    const source = new VaultCore(); await source.create('fixture', password);
    if (version === 3) source.db.setVersion(3);
    else source.db.setKdf(K.Consts.KdfId.Argon2d);
    const entry = source.upsert({ fields: { Title: `v${version}`, Password: 'fixture' } });
    const binary = await source.export();
    assert.equal(inspectHeader(binary), version);
    const opened = new VaultCore(); await opened.unlock(binary, password);
    assert.equal(opened.password(entry.id), 'fixture');
    assert.equal(inspectHeader(await opened.export()), version);
    await assert.rejects(new VaultCore().unlock(binary, 'incorrect password'));
    const corrupt = binary.slice(0); new Uint8Array(corrupt)[Math.floor(corrupt.byteLength / 2)] ^= 0x80;
    await assert.rejects(new VaultCore().unlock(corrupt, password));
  }
});

test('key-file credentials and deletion/recycle-bin preserve compatibility', async () => {
  const keyFile = crypto.getRandomValues(new Uint8Array(32)).buffer;
  const vault = new VaultCore(); await vault.create('keyfile test', password, keyFile);
  const entry = vault.upsert({ fields: { Title: 'delete fixture', Password: 'data' } });
  const data = await vault.export();
  await assert.rejects(new VaultCore().unlock(data, password));
  const opened = new VaultCore(); await opened.unlock(data, password, keyFile);
  opened.remove(entry.id); assert.equal(opened.list().entries.length, 0);
  assert.equal(opened.entry(entry.id).fields.get('Title'), 'delete fixture');
  const sealed = await opened.export();
  const roundtrip = new VaultCore(); await roundtrip.unlock(sealed, password, keyFile);
  assert.equal(roundtrip.list().entries.length, 0);
});

test('explicit merge keeps independent edits, unknown fields and attachments', async () => {
  const source = new VaultCore(); await source.create('merge fixture', password);
  const one = source.upsert({ fields: { Title: 'one', Password: 'initial' } });
  const two = source.upsert({ fields: { Title: 'two', Password: 'initial' } });
  const base = await source.export();
  const local = new VaultCore(), remote = new VaultCore();
  await local.unlock(base, password); await remote.unlock(base, password);
  local.upsert({ id: one.id, fields: { Password: 'local change' } });
  remote.upsert({ id: two.id, fields: { Password: 'remote change' } });
  await remote.attach(two.id, 'fixture.crt', encode('certificate fixture'));
  await local.merge(await remote.export());
  assert.equal(local.password(one.id), 'local change'); assert.equal(local.password(two.id), 'remote change');
  assert.equal(decode(local.attachment(two.id, 'fixture.crt')), 'certificate fixture');
  const reopened = new VaultCore(); await reopened.unlock(await local.export(), password);
  assert.equal(reopened.password(one.id), 'local change'); assert.equal(reopened.password(two.id), 'remote change');
  const unrelated = new VaultCore(); await unrelated.create('different root', password);
  await assert.rejects(local.merge(await unrelated.export()));
});

test('valid Argon2 parameters have no application memory, iteration, parallelism or combined-work cap', async () => {
  // Validation alone exercises high work factors without allocating gigabytes.
  for (const args of [
    [256 * 1024 + 1, 1, 32, 1, 2, 19],
    [64 * 1024, 51, 32, 1, 2, 19],
    [64 * 1024, 17, 32, 1, 2, 19],
    [1024 * 1024, 100_000, 32, 32, 0, 19],
    [8, 0xffffffff, 32, 1, 2, 19],
  ]) assert.doesNotThrow(() => validateArgon2Parameters(...args));
  const p = encode('password'), s = encode('1234567890123456');
  for (const type of [0, 2]) {
    assert.equal((await deriveArgon2(p, s, 32, 51, 32, 1, type, 19)).byteLength, 32);
    assert.equal((await deriveArgon2(p, s, 17 * 8, 1, 32, 17, type, 19)).byteLength, 32);
  }
});

test('malformed or unrepresentable KDF values fail explicitly instead of wrapping or downgrading', async () => {
  const p = encode('password'), s = encode('1234567890123456');
  for (const args of [
    [Infinity, 1, 32, 1, 2, 19], [8.5, 1, 32, 1, 2, 19], [7, 1, 32, 1, 2, 19],
    [8, 0, 32, 1, 2, 19], [8, 1.5, 32, 1, 2, 19], [8, 0x100000000, 32, 1, 2, 19],
    [8, 1, 32, 0, 2, 19], [8, 1, 32, 2, 2, 19], [8, 1, 3, 1, 2, 19],
  ]) await assert.rejects(deriveArgon2(p, s, ...args), { code: 'InvalidKdf' });
  await assert.rejects(deriveArgon2(p, s, 8, 1, 32, 1, 2, 16), { code: 'UnsupportedKdf' });
  await assert.rejects(deriveArgon2(p, s, 8, 1, 32, 1, 1, 19), { code: 'UnsupportedKdf' });
  // A valid Argon2 memory parameter that cannot fit this engine's wasm32 allocator.
  await assert.rejects(deriveArgon2(p, s, 4 * 1024 * 1024, 1, 32, 1, 2, 19), { code: 'ResourceLimit' });
  assert.equal(Object.hasOwn(LIMITS, 'memoryKiB'), false);
  assert.equal(Object.hasOwn(LIMITS, 'aesRounds'), false);
});

test('a real engine allocation failure produces only the sanitized ResourceLimit code', async (context) => {
  const instantiate = WebAssembly.instantiate;
  context.mock.method(WebAssembly, 'instantiate', async (...args) => {
    const instance = await instantiate(...args);
    // Simulate memory.grow exhaustion at the same hash-wasm allocation boundary
    // without asking the test process to exhaust its actual memory.
    if (instance.exports.Hash_SetMemorySize) return { exports: {
      ...instance.exports, Hash_SetMemorySize: () => -1,
    } };
    return instance;
  });
  await assert.rejects(deriveArgon2(encode('password'), encode('1234567890123456'), 1024, 1, 32, 1, 2, 19),
    { code: 'ResourceLimit', message: 'ResourceLimit' });
});

test('AES headers accept rounds above the former ten-million cap up to exact library representation', async () => {
  for (const version of [3, 4]) {
    const source = new VaultCore(); await source.create('AES header fixture', password);
    if (version === 3) source.db.setVersion(3);
    else source.db.setKdf(K.Consts.KdfId.Aes);
    for (const rounds of [10_000_001, Number.MAX_SAFE_INTEGER]) {
      if (version === 3) source.db.header.keyEncryptionRounds = rounds;
      else source.db.header.kdfParameters.set('R', K.VarDictionary.ValueType.UInt64, K.Int64.from(rounds));
      const stream = new K.BinaryStream(); source.db.header.generateSalts(); source.db.header.write(stream);
      const data = stream.getWrittenBytes();
      assert.equal(inspectHeader(data), version);
      if (rounds === Number.MAX_SAFE_INTEGER) {
        const view = new DataView(data);
        let offset = -1;
        for (let p = 12; p + 8 <= data.byteLength; p++) if (view.getBigUint64(p, true) === BigInt(rounds)) { offset = p; break; }
        assert.ok(offset >= 0);
        view.setBigUint64(offset, 0x20000000000000n, true);
        assert.throws(() => inspectHeader(data), { code: 'UnsupportedKdf' });
        view.setBigUint64(offset, 0n, true);
        assert.throws(() => inspectHeader(data), { code: 'InvalidKdf' });
      }
    }
  }
});

test('high-work Argon2 vault opens, edits and saves without changing its original KDF parameters', async () => {
  const source = new VaultCore(); await source.create('high-work fixture', password);
  source.db.header.kdfParameters.set('I', K.VarDictionary.ValueType.UInt64, K.Int64.from(17));
  const entry = source.upsert({ fields: { Title: 'heavy vault', Password: 'synthetic secret' } });
  // 64 MiB x 17 passes exceeded the old combined-work cap.
  const encrypted = await source.export();
  const opened = new VaultCore(); await opened.unlock(encrypted, password);
  assert.equal(opened.password(entry.id), 'synthetic secret');
  opened.upsert({ id: entry.id, fields: { Notes: 'edited after high-work unlock' } });
  const saved = await opened.export();
  const reopened = new VaultCore(); await reopened.unlock(saved, password);
  assert.equal(reopened.read(entry.id).fields.Notes, 'edited after high-work unlock');
  for (const key of ['$UUID', 'M', 'I', 'P', 'V']) {
    assert.deepEqual(reopened.db.header.kdfParameters.get(key), source.db.header.kdfParameters.get(key), key);
  }
});

test('AES vault roundtrip above the old rounds cap preserves the transform count', async () => {
  const source = new VaultCore(); await source.create('AES work fixture', password); source.db.setVersion(3);
  source.db.header.keyEncryptionRounds = 10_000_001;
  const entry = source.upsert({ fields: { Title: 'AES', Password: 'synthetic AES secret' } });
  const opened = new VaultCore(); await opened.unlock(await source.export(), password);
  assert.equal(opened.password(entry.id), 'synthetic AES secret');
  assert.equal(opened.db.header.keyEncryptionRounds, 10_000_001);
});

test('file validation and crypto-random password generator bounds remain unchanged', () => {
  assert.throws(() => inspectHeader(new ArrayBuffer(16)), { code: 'BadSignature' });
  assert.throws(() => inspectHeader(new ArrayBuffer(LIMITS.file + 1)), { code: 'FileLimit' });
  assert.throws(() => generatePassword(15), { code: 'InvalidInput' });
  const generated = new Set(Array.from({ length: 64 }, () => generatePassword()));
  assert.equal(generated.size, 64); for (const value of generated) assert.equal(value.length, 24);
});

test('rapid edits survive whole-second timestamps; ambiguous independent edits are rejected without mutation', async () => {
  const source = new VaultCore(); await source.create('timestamp fixture', password);
  const entry = source.upsert({ fields: { Title: 'same-entry', Password: 'initial' } });
  const initial = source.entry(entry.id).lastModTime;
  source.upsert({ id: entry.id, fields: { Password: 'second' } });
  const second = source.entry(entry.id).lastModTime;
  source.upsert({ id: entry.id, fields: { Password: 'third' } });
  assert.ok(second >= initial + 1000);
  assert.ok(source.entry(entry.id).lastModTime >= second + 1000);
  const base = await source.export();
  const local = new VaultCore(), remote = new VaultCore();
  await local.unlock(base, password); await remote.unlock(base, password);
  local.upsert({ id: entry.id, fields: { Password: 'local concurrent' } });
  remote.upsert({ id: entry.id, fields: { Password: 'remote concurrent' } });
  remote.entry(entry.id).times.lastModTime = new Date(local.entry(entry.id).lastModTime);
  await assert.rejects(local.merge(await remote.export()), { code: 'MergeConflict' });
  assert.equal(local.password(entry.id), 'local concurrent');
});
