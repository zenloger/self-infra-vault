import * as K from 'kdbxweb';
import { argon2d, argon2id } from 'hash-wasm';

export const LIMITS = Object.freeze({ file: 64 * 1024 * 1024, attachment: 8 * 1024 * 1024 });
const EDITABLE = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
const fail = (code) => { throw Object.assign(new Error(code), { code }); };
const bytes = (value) => value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
const buffer = (value) => bytes(value).slice().buffer;
const text = (value) => value instanceof K.ProtectedValue ? value.getText() : String(value || '');
const uuid = (value) => value.uuid.id;
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

export function validateArgon2Parameters(memory, iterations, length, parallelism, type, version) {
  if (version !== 0x13 || ![0, 2].includes(type)) fail('UnsupportedKdf');
  // These are Argon2's encoded integer ranges, not application work budgets.
  // hash-wasm stores each parameter in a uint32; larger values would wrap.
  if (!integer(memory, 8, 0xffffffff) || !integer(iterations, 1, 0xffffffff) ||
      !integer(parallelism, 1, 0xffffff) || memory < parallelism * 8 ||
      !integer(length, 4, 0xffffffff)) fail('InvalidKdf');
  // The wasm32 allocator accepts a uint32 byte count, including one scratch
  // block. Do not wrap it or silently lower the vault's requested memory.
  if (memory * 1024 + 1024 > 0xffffffff) fail('ResourceLimit');
}

export async function deriveArgon2(password, salt, memory, iterations, length, parallelism, type, version) {
  validateArgon2Parameters(memory, iterations, length, parallelism, type, version);
  try {
    return await (type === 0 ? argon2d : argon2id)({ password: bytes(password), salt: bytes(salt), memorySize: memory,
      iterations, parallelism, hashLength: length, outputType: 'binary' });
  } catch (error) {
    // hash-wasm constructs a typed view after memory.grow. A failed growth or
    // typed-array allocation raises RangeError; only expose a fixed error code.
    if (error instanceof RangeError) fail('ResourceLimit');
    throw error;
  }
}
K.CryptoEngine.setArgon2Impl(deriveArgon2);

// Validate framing and exact AES round representation before library parsing.
// Valid work factors have no policy cap; the worker can be cancelled by the UI.
export function inspectHeader(input) {
  const data = bytes(input);
  if (data.byteLength < 16 || data.byteLength > LIMITS.file) fail('FileLimit');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(0, true) !== 0x9aa2d903 || view.getUint32(4, true) !== 0xb54bfb67) fail('BadSignature');
  const major = view.getUint32(8, true) >>> 16;
  if (major !== 3 && major !== 4) fail('InvalidVersion');
  const read64 = (offset) => {
    const n = view.getBigUint64(offset, true);
    if (n === 0n) fail('InvalidKdf');
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) fail('UnsupportedKdf');
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
      const title = group.name || 'Группа';
      const label = [...path, title];
      result.push({ id: uuid(group), name: label.join(' / '), title,
        parentId: group.parentGroup ? uuid(group.parentGroup) : null, depth: path.length, recycled: trash });
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
