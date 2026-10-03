import * as K from 'kdbxweb';
import { argon2d, argon2id } from 'hash-wasm';

export const LIMITS = Object.freeze({ file: 64 * 1024 * 1024, attachment: 8 * 1024 * 1024, memoryKiB: 256 * 1024, iterations: 50, parallelism: 16, aesRounds: 10_000_000 });
const EDITABLE = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
const fail = (code) => { throw Object.assign(new Error(code), { code }); };
const bytes = (value) => value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
const buffer = (value) => bytes(value).slice().buffer;
const text = (value) => value instanceof K.ProtectedValue ? value.getText() : String(value || '');
const uuid = (value) => value.uuid.id;
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

export async function boundedArgon2(password, salt, memory, iterations, length, parallelism, type, version) {
  if (version !== 0x13 || ![0, 2].includes(type)) fail('UnsupportedKdf');
  if (!integer(memory, 8, LIMITS.memoryKiB) || !integer(iterations, 1, LIMITS.iterations) ||
      !integer(parallelism, 1, LIMITS.parallelism) || memory < parallelism * 8 ||
      memory * iterations > 1024 * 1024 || !integer(length, 16, 64)) fail('KdfLimit');
  return (type === 0 ? argon2d : argon2id)({ password: bytes(password), salt: bytes(salt), memorySize: memory,
    iterations, parallelism, hashLength: length, outputType: 'binary' });
}
K.CryptoEngine.setArgon2Impl(boundedArgon2);

// Bound the untrusted AES work factor before asking the library to decrypt.
// Argon2 work is bounded again in the implementation above, before WASM allocation.
export function inspectHeader(input) {
  const data = bytes(input);
  if (data.byteLength < 16 || data.byteLength > LIMITS.file) fail('FileLimit');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(0, true) !== 0x9aa2d903 || view.getUint32(4, true) !== 0xb54bfb67) fail('BadSignature');
  const major = view.getUint32(8, true) >>> 16;
  if (major !== 3 && major !== 4) fail('InvalidVersion');
  const read64 = (offset) => {
    const n = view.getBigUint64(offset, true);
    if (n > BigInt(LIMITS.aesRounds)) fail('KdfLimit');
  };
  let pos = 12;
  while (pos < data.byteLength) {
    if (pos + 1 + (major === 3 ? 2 : 4) > data.byteLength) fail('FileCorrupt');
    const id = data[pos++];
    const size = major === 3 ? view.getUint16(pos, true) : view.getUint32(pos, true);
    pos += major === 3 ? 2 : 4;
    if (size > data.byteLength - pos || pos + size > 1024 * 1024) fail('FileCorrupt');
    if (major === 3 && id === 6) { if (size !== 8) fail('FileCorrupt'); read64(pos); }
    if (major === 4 && id === 11) {
      const end = pos + size;
      let p = pos + 2;
      while (p < end) {
        const type = data[p++];
        if (!type) break;
        if (p + 4 > end) fail('FileCorrupt');
        const nameLength = view.getUint32(p, true); p += 4;
        if (nameLength > end - p) fail('FileCorrupt');
        const name = new TextDecoder().decode(data.subarray(p, p + nameLength)); p += nameLength;
        if (p + 4 > end) fail('FileCorrupt');
        const valueLength = view.getUint32(p, true); p += 4;
        if (valueLength > end - p) fail('FileCorrupt');
        if (name === 'R') { if (valueLength !== 8) fail('FileCorrupt'); read64(p); }
        p += valueLength;
      }
    }
    pos += size;
    if (id === 0) return major;
  }
  fail('FileCorrupt');
}

export function generatePassword(length = 24) {
  if (!integer(length, 16, 128)) fail('InvalidInput');
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*+-=?';
  const ceiling = 256 - 256 % alphabet.length;
  let out = '';
  while (out.length < length) {
    const random = crypto.getRandomValues(new Uint8Array(64));
    for (const n of random) { if (n < ceiling && out.length < length) out += alphabet[n % alphabet.length]; }
    random.fill(0);
  }
  return out;
}

export class VaultCore {
  db = null;

  async unlock(data, password, keyFile) {
    inspectHeader(data);
    const credentials = new K.Credentials(K.ProtectedValue.fromString(password), keyFile ? buffer(keyFile) : undefined);
    this.db = await K.Kdbx.load(buffer(data), credentials);
    return this.list();
  }

  async create(name, password, keyFile) {
    if (!password || password.length < 12) fail('WeakPassword');
    this.db = K.Kdbx.create(new K.Credentials(K.ProtectedValue.fromString(password), keyFile ? buffer(keyFile) : undefined), name);
    this.db.setKdf(K.Consts.KdfId.Argon2id);
    this.db.header.kdfParameters.set('M', K.VarDictionary.ValueType.UInt64, K.Int64.from(64 * 1024 * 1024));
    this.db.header.kdfParameters.set('I', K.VarDictionary.ValueType.UInt64, K.Int64.from(3));
    this.db.header.kdfParameters.set('P', K.VarDictionary.ValueType.UInt32, 1);
    this.db.header.kdfParameters.set('V', K.VarDictionary.ValueType.UInt32, 0x13);
    return this.list();
  }

  require() { if (!this.db) fail('Locked'); return this.db; }

  groups() {
    const db = this.require();
    const result = [];
    const visit = (group, path, recycled) => {
      const trash = recycled || group.uuid.equals(db.meta.recycleBinUuid);
      const label = [...path, group.name || 'Группа'];
      result.push({ id: uuid(group), name: label.join(' / '), recycled: trash });
      for (const child of group.groups) visit(child, label, trash);
    };
    for (const group of db.groups) visit(group, [], false);
    return result;
  }

  list() {
    const db = this.require(), groups = this.groups();
    const result = [];
    for (const group of groups) {
      if (group.recycled) continue;
      const source = db.getGroup(new K.KdbxUuid(group.id));
      for (const entry of source.entries) result.push({ id: uuid(entry), title: text(entry.fields.get('Title')),
        username: text(entry.fields.get('UserName')), group: group.name, groupId: group.id });
    }
    return { entries: result, groups: groups.filter(g => !g.recycled), name: db.meta.name || 'Хранилище', version: db.header.versionMajor };
  }

  entry(id) {
    const db = this.require();
    for (const root of db.groups) for (const entry of root.allEntries()) if (uuid(entry) === id) return entry;
    fail('NotFound');
  }

  read(id) {
    const entry = this.entry(id), fields = {};
    for (const key of EDITABLE) if (key !== 'Password') fields[key] = text(entry.fields.get(key));
    return { id, fields, groupId: uuid(entry.parentGroup), hasPassword: Boolean(text(entry.fields.get('Password'))),
      attachments: [...entry.binaries].map(([name, binary]) => ({ name, size: this.binarySize(binary) })),
      historyCount: entry.history.length, customFieldCount: [...entry.fields.keys()].filter(k => !EDITABLE.includes(k)).length };
  }

  password(id) { return text(this.entry(id).fields.get('Password')); }

  upsert({ id, fields, groupId }) {
    const db = this.require();
    if (!fields || typeof fields !== 'object') fail('InvalidInput');
    for (const key of EDITABLE) if (Object.hasOwn(fields, key) && (typeof fields[key] !== 'string' || fields[key].length > 1024 * 1024)) fail('InvalidInput');
    const group = groupId ? db.getGroup(new K.KdbxUuid(groupId)) : db.getDefaultGroup();
    if (!group || this.groups().find(g => g.id === uuid(group))?.recycled) fail('NotFound');
    const entry = id ? this.entry(id) : db.createEntry(group);
    if (id) entry.pushHistory();
    for (const key of EDITABLE) {
      if (!Object.hasOwn(fields, key)) continue;
      const protectedField = key === 'Password' || entry.fields.get(key) instanceof K.ProtectedValue;
      entry.fields.set(key, protectedField ? K.ProtectedValue.fromString(fields[key]) : fields[key]);
    }
    if (entry.parentGroup !== group) db.move(entry, group);
    this.touch(entry);
    return this.read(uuid(entry));
  }

  touch(entry) {
    const previous = entry.lastModTime;
    entry.times.update();
    // KDBX timestamps serialize at whole-second precision. Millisecond bumps
    // disappear after export and can make a later merge skip a real update.
    entry.times.lastModTime = new Date(Math.max(Math.floor(Date.now() / 1000) * 1000, Math.floor(previous / 1000) * 1000 + 1000));
  }

  remove(id) { this.require().remove(this.entry(id)); return this.list(); }

  async attach(id, name, data) {
    if (!name || name.length > 240 || /[\x00-\x1f/\\]/.test(name)) fail('InvalidInput');
    if (bytes(data).byteLength > LIMITS.attachment) fail('AttachmentLimit');
    const entry = this.entry(id);
    if (entry.binaries.has(name)) fail('AttachmentExists');
    const protectedData = K.ProtectedValue.fromBinary(bytes(data));
    const binary = await this.db.binaries.add(protectedData);
    entry.pushHistory();
    entry.binaries.set(name, binary);
    this.touch(entry);
    return this.read(id);
  }

  binarySize(binary) { const value = binary?.value ?? binary; return value instanceof K.ProtectedValue ? value.byteLength : value.byteLength; }

  attachment(id, name) {
    const binary = this.entry(id).binaries.get(name);
    if (!binary) fail('NotFound');
    const value = binary.value ?? binary;
    return value instanceof K.ProtectedValue ? buffer(value.getBinary()) : buffer(value);
  }

  removeAttachment(id, name) {
    const entry = this.entry(id);
    if (!entry.binaries.has(name)) fail('NotFound');
    entry.pushHistory();
    entry.binaries.delete(name);
    this.touch(entry);
    return this.read(id);
  }

  async export() {
    const data = await this.require().save();
    if (data.byteLength > LIMITS.file) fail('FileLimit');
    return data;
  }

  async merge(data) {
    inspectHeader(data);
    const db = this.require();
    const remote = await K.Kdbx.load(buffer(data), db.credentials);
    const localEntries = new Map(db.groups.flatMap(group => [...group.allEntries()].map(entry => [uuid(entry), entry])));
    const content = async (entry) => JSON.stringify({
      fields: [...entry.fields].map(([key, value]) => [key, text(value)]).sort((a, b) => a[0].localeCompare(b[0])),
      binaries: (await Promise.all([...entry.binaries].map(async ([key, binary]) => {
        const value = binary.value ?? binary;
        const hash = binary.hash || K.ByteUtils.bytesToHex(await K.CryptoEngine.sha256(value instanceof K.ProtectedValue ? buffer(value.getBinary()) : buffer(value)));
        return [key, hash];
      }))).sort((a, b) => a[0].localeCompare(b[0])),
      group: entry.parentGroup?.uuid.id, tags: entry.tags, icon: entry.icon, customIcon: entry.customIcon?.id,
      customData: entry.customData ? [...entry.customData] : null,
      fgColor: entry.fgColor, bgColor: entry.bgColor, overrideUrl: entry.overrideUrl, autoType: entry.autoType,
      qualityCheck: entry.qualityCheck, previousParentGroup: entry.previousParentGroup?.id,
      expires: entry.times.expires, expiryTime: entry.times.expiryTime,
    });
    for (const group of remote.groups) for (const incoming of group.allEntries()) {
      const local = localEntries.get(uuid(incoming));
      if (local && local.lastModTime === incoming.lastModTime && await content(local) !== await content(incoming)) fail('MergeConflict');
    }
    db.merge(remote);
    return this.list();
  }

  synced() { this.require().removeLocalEditState(); }
  lock() { this.db = null; }
}
