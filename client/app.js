const $ = (id) => document.getElementById(id);
const messages = {
  InvalidKey: 'Не удалось открыть базу: проверь мастер-пароль и ключевой файл.',
  FileCorrupt: 'Файл повреждён или не является поддерживаемой базой KDBX.',
  BadSignature: 'Это не файл KeePass KDBX.', InvalidVersion: 'Поддерживаются KDBX 3 и 4.',
  UnsupportedKdf: 'Алгоритм, версия или параметры KDF не поддерживаются криптодвижком. База не изменена.',
  InvalidKdf: 'В файле некорректные параметры вычисления ключа. Проверь целостность базы.',
  ResourceLimit: 'Браузерный криптодвижок не смог выделить память, которую требует база. Параметры защиты не изменены.',
  FileLimit: 'База превышает допустимый размер (до 64 МБ).', AttachmentLimit: 'Вложение превышает 8 МБ.',
  AttachmentExists: 'Вложение с таким именем уже есть. Сначала удали старое или переименуй файл.',
  WeakPassword: 'Новый мастер-пароль должен содержать не меньше 12 символов.',
  InvalidInput: 'Проверь введённые данные.', NotFound: 'Запись или файл больше не найдены.',
  InvalidState: 'Эти базы нельзя объединить: они созданы независимо.',
  MergeConflict: 'В одной записи обнаружены разные изменения с одинаковым временем. Автоматическое объединение остановлено. Скачай обе версии и сравни их в KeePass.',
  OperationFailed: 'Операция не выполнена. База осталась в браузере; скачай зашифрованную копию.',
  unauthorized: 'Сеанс входа истёк. Скачай зашифрованную копию и войди снова.',
  authentication_required: 'Сеанс входа истёк. Скачай зашифрованную копию и войди снова.',
  oauth_not_configured: 'Яндекс OAuth ещё не настроен на сервере.',
  storage_unavailable: 'Яндекс Диск сейчас недоступен. Изменения остались в памяти.',
  csrf: 'Сеанс изменился. Скачай зашифрованную копию, затем перезагрузи страницу.',
  rate_limited: 'Слишком много запросов. Подожди немного и повтори операцию.',
  save_unconfirmed: 'Диск принял загрузку, но её завершение не подтверждено. Скачай локальную копию и проверь список файлов перед повторной синхронизацией.',
  NetworkTimeout: 'Сервер не ответил вовремя. Результат синхронизации неизвестен: скачай локальную копию и проверь файлы на Диске перед повторной отправкой.',
  not_configured: 'Яндекс OAuth ещё не настроен на сервере.',
  upstream_error: 'Яндекс Диск сейчас недоступен. Изменения остались в памяти.',
  quota_exceeded: 'На Яндекс Диске недостаточно места.',
  forbidden: 'Нет доступа. Проверь разрешения приложения Яндекса.',
  file_too_large: 'Файл превышает ограничение сервера.',
};
let session, worker, serial = 0, generation = 0, pending = new Map(), fetches = new Set();
let currentName = '', currentRevision = null, createMode = false, opened = false;
let entryId = null, entries = [], groups = [], draftDirty = false, passwordChanged = false, dirty = false;
let recovery = null, recoveryName = '', idleTimer, lastActivity = 0;
let saving = false, busy = false, recoveryUnsynced = false, uploadStarted = false;
let actionSerial = 0, operationSerial = 0, operationStarted = null, operationTimer;
const cryptoCalls = new Set();
const cryptoStages = {
  unlock: 'Вычисляем ключ и открываем базу…',
  create: 'Создаём хранилище в браузере…',
  export: 'Вычисляем ключ и шифруем базу…',
  merge: 'Открываем вторую версию и объединяем записи…',
};
const MAX_FILE = 64 * 1024 * 1024;
const element = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; };
function status(message, error = false) { $('status').textContent = message; $('status').dataset.error = String(error); }
function report(error) {
  if (error.name === 'AbortError' || error.code === 'Locked') return;
  status(messages[error.code] || 'Не удалось завершить операцию. Проверь соединение; локальные изменения не отправлены.', true);
  if (['authentication_required', 'unauthorized'].includes(error.code)) {
    const login = element('a', ' Войти снова'); login.href = '/auth/login'; $('status').append(login);
  }
  if (error.code === 'save_unconfirmed' && error.targetName) $('status').append(element('span', ` Имя версии: ${error.targetName}`));
}
function setBusy(value) {
  busy = value;
  for (const selector of ['#files-panel', '#unlock-form', '.vault-grid', '#conflict']) {
    const region = document.querySelector(selector); region.inert = value; region.setAttribute('aria-busy', String(value));
  }
  $('sync').disabled = value; $('export').disabled = value;
}
function showOperation(stage, detail = 'Время зависит от защиты базы и устройства. Вычисления продолжатся до завершения или отмены.') {
  $('operation-stage').textContent = stage; $('operation-detail').textContent = detail;
  if (operationStarted !== null) return;
  operationStarted = Date.now();
  const serial = ++operationSerial;
  $('operation-panel').hidden = false;
  const tick = () => {
    if (serial !== operationSerial) return;
    const seconds = Math.max(0, Math.floor((Date.now() - operationStarted) / 1000));
    const minutes = Math.floor(seconds / 60), hours = Math.floor(minutes / 60);
    $('operation-elapsed').textContent = hours ? `${hours}:${String(minutes % 60).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}` : `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
    operationTimer = setTimeout(tick, 1000);
  };
  tick(); $('operation-cancel').focus({ preventScroll: true });
}
function hideOperation() {
  const restoreFocus = document.activeElement === $('operation-cancel');
  operationSerial++; clearTimeout(operationTimer); operationStarted = null;
  $('operation-panel').hidden = true;
  if (restoreFocus) {
    const target = opened ? $('sync') : !$('unlock-panel').hidden ? $('unlock-submit') : $('refresh');
    target.focus({ preventScroll: true });
  }
}
function action(callback) { return (event) => {
  event?.preventDefault();
  if (busy) return;
  const serial = ++actionSerial;
  setBusy(true);
  Promise.resolve().then(() => { if (serial !== actionSerial) throw abortError(); return callback(event); })
    .catch(error => { if (serial === actionSerial) report(error); })
    .finally(() => { if (serial === actionSerial) { setBusy(false); hideOperation(); } });
}; }
const abortError = () => Object.assign(new Error(), { code: 'Locked', name: 'AbortError' });

async function request(path, options = {}) {
  const controller = new AbortController(), epoch = generation;
  fetches.add(controller);
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, 65_000);
  const normalizeError = (error) => timedOut && epoch === generation ? Object.assign(new Error(), { code: 'NetworkTimeout' }) : error;
  const release = () => { fetches.delete(controller); clearTimeout(timeout); };
  try {
    const response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
    if (epoch !== generation) throw abortError();
    // Keep the controller alive through body consumption, not only headers.
    for (const method of ['json', 'arrayBuffer', 'text']) {
      const original = response[method].bind(response);
      response[method] = async (...args) => {
        try {
          const data = await original(...args);
          if (epoch !== generation) throw abortError();
          return data;
        } catch (error) { throw normalizeError(error); } finally { release(); }
      };
    }
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      if (epoch !== generation) throw abortError();
      throw Object.assign(new Error(), { code: data.error || 'OperationFailed', status: response.status, revision: data.revision, targetName: data.name });
    }
    return response;
  } catch (error) { release(); throw normalizeError(error); }
}

function launchWorker() {
  const launched = new Worker('/vault-worker.js', { type: 'module', name: 'local-vault' });
  worker = launched;
  launched.onmessage = ({ data }) => {
    if (worker !== launched) return;
    const call = pending.get(data.id);
    if (!call) return;
    pending.delete(data.id);
    if (cryptoCalls.delete(data.id) && !cryptoCalls.size) activity(true);
    data.error ? call.reject(Object.assign(new Error(), { code: data.error })) : call.resolve(data.result);
  };
  launched.onerror = () => {
    if (worker !== launched) return;
    lock(true); status('Локальный обработчик остановился. Скачай сохранённую зашифрованную копию, если она доступна.', true);
  };
}
function rpc(op, args = [], transfer = []) {
  if (!worker) return Promise.reject(abortError());
  const id = ++serial;
  if (cryptoStages[op]) {
    cryptoCalls.add(id); clearTimeout(idleTimer); showOperation(cryptoStages[op]);
  }
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try { worker.postMessage({ id, op, args }, transfer); }
    catch (error) {
      pending.delete(id);
      if (cryptoCalls.delete(id) && !cryptoCalls.size) activity(true);
      reject(error);
    }
  });
}

function wipeEditor() {
  $('entry-form').reset(); $('entry-form').hidden = true; $('select-entry').hidden = false;
  $('entry-password').type = 'password'; $('reveal').textContent = 'Показать';
  $('attachments').replaceChildren(); $('entry-meta').textContent = ''; $('entry-group').replaceChildren();
  entryId = null; draftDirty = false; passwordChanged = false;
}
function showRecovery() { $('recovery-panel').hidden = !recovery || opened; }
function lock(force = false) {
  if (!force && (dirty || draftDirty) && !confirm('Остались несинхронизированные изменения. Сохранится последняя завершённая зашифрованная копия; более поздние изменения и неприменённый текст будут потеряны. Заблокировать?')) return false;
  generation++; actionSerial++;
  for (const controller of fetches) controller.abort();
  fetches.clear();
  worker?.terminate(); worker = null;
  for (const call of pending.values()) call.reject(abortError());
  pending.clear(); cryptoCalls.clear(); clearTimeout(idleTimer);
  opened = false; saving = false; uploadStarted = false; entries = []; groups = [];
  $('entries').replaceChildren(); $('search').value = ''; $('active-name').textContent = '';
  $('workspace').hidden = true; $('unlock-panel').hidden = true; $('conflict').hidden = true;
  $('unlock-form').reset(); $('unlock-submit').disabled = false; $('unlock-name').textContent = ''; wipeEditor(); dirty = false;
  $('files-panel').hidden = !session?.authenticated; showRecovery();
  setBusy(false); hideOperation();
  return true;
}
function activity(reset = false) {
  if (!opened || cryptoCalls.size) return;
  const now = Date.now();
  if (reset !== true && now - lastActivity < 1000) return;
  lastActivity = now; clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { if (cryptoCalls.size) return; lock(true); status('Хранилище заблокировано после 5 минут без действий.'); }, 5 * 60 * 1000);
}
for (const type of ['pointerdown', 'keydown', 'touchstart']) document.addEventListener(type, activity, { passive: true });
document.addEventListener('visibilitychange', () => {
  if (opened && !cryptoCalls.size && Date.now() - lastActivity >= 5 * 60 * 1000) { lock(true); status('Хранилище заблокировано после отсутствия.'); }
});
window.addEventListener('pagehide', () => lock(true));
window.addEventListener('beforeunload', (event) => { if (dirty || draftDirty || recovery) { event.preventDefault(); event.returnValue = ''; } });

function updateSaveState() {
  $('save-state').textContent = draftDirty ? 'Есть неприменённый текст в редакторе.' : dirty ? 'Изменения в памяти. На Диск ещё не отправлены.' : 'Версия с Диска. Локальных изменений нет.';
}
function download(data, name) {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
  const link = element('a'); link.href = url; link.download = name.replace(/[\x00-\x1f/\\]/g, '_');
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function snapshot() {
  const epoch = generation;
  const data = await rpc('export');
  if (epoch !== generation) throw abortError();
  if (recovery) new Uint8Array(recovery).fill(0);
  recovery = data; recoveryName = currentName; recoveryUnsynced = dirty; showRecovery();
  return data;
}
async function loadFiles() {
  const epoch = generation;
  const response = await request('/api/vaults'); const data = await response.json();
  if (epoch !== generation) throw abortError();
  $('files').replaceChildren();
  const files = [...(data.files || [])].sort((a, b) => String(b.modified).localeCompare(String(a.modified)));
  $('empty-files').hidden = files.length !== 0;
  for (const file of files) {
    const item = element('li'), info = element('div', undefined, 'file-info'), buttons = element('div', undefined, 'actions');
    info.append(element('strong', file.name));
    const date = new Date(file.modified);
    info.append(element('small', `${(file.size / 1024).toFixed(1)} КБ · ${Number.isNaN(date.getTime()) ? 'дата неизвестна' : date.toLocaleString('ru-RU')}`));
    const open = element('button', 'Открыть'), sealed = element('button', 'Скачать .kdbx');
    open.addEventListener('click', action(() => prepareUnlock(file.name, false)));
    sealed.addEventListener('click', action(async () => {
      const epoch = generation, response = await request(`/api/vault?name=${encodeURIComponent(file.name)}`), data = await response.arrayBuffer();
      if (epoch === generation) download(data, file.name);
    }));
    buttons.append(open, sealed); item.append(info, buttons); $('files').append(item);
  }
}
function prepareUnlock(name, creating) {
  if (recoveryUnsynced && recovery && !confirm('В памяти есть несинхронизированная зашифрованная копия. Открытие другой базы может заменить её. Уже скачал копию и хочешь продолжить?')) return;
  if (!lock()) return;
  currentName = name; currentRevision = null; createMode = creating;
  $('unlock-mode').textContent = creating ? 'Новое хранилище' : 'Открыть локально';
  $('unlock-name').textContent = creating ? 'Твой новый KDBX' : name;
  $('new-name-label').hidden = !creating; $('confirm-label').hidden = !creating;
  $('new-name').required = creating; $('master-confirm').required = creating;
  $('new-name').value = 'personal.kdbx';
  $('unlock-submit').textContent = creating ? 'Создать локально' : 'Открыть';
  $('unlock-panel').hidden = false; (creating ? $('new-name') : $('master')).focus();
}
function renderEntries() {
  const query = $('search').value.toLocaleLowerCase();
  $('entries').replaceChildren();
  const filtered = entries.filter(e => `${e.title}\n${e.username}\n${e.group}`.toLocaleLowerCase().includes(query));
  $('no-entries').hidden = filtered.length !== 0;
  for (const entry of filtered) {
    const li = element('li'), button = element('button');
    button.setAttribute('aria-current', String(entry.id === entryId));
    button.append(element('strong', entry.title || 'Без названия'), element('small', entry.username || entry.group));
    button.addEventListener('click', action(async () => {
      if (draftDirty && !confirm('Отменить неприменённые изменения записи?')) return;
      const selected = await rpc('read', [entry.id]); renderEditor(selected);
    }));
    li.append(button); $('entries').append(li);
  }
}
function setListing(data) { entries = data.entries; groups = data.groups; renderEntries(); }
function renderEditor(entry) {
  wipeEditor(); entryId = entry?.id || null; $('select-entry').hidden = true; $('entry-form').hidden = false;
  for (const group of groups) { const option = element('option', group.name); option.value = group.id; $('entry-group').append(option); }
  if (entry) $('entry-group').value = entry.groupId;
  for (const [key, id] of [['Title', 'entry-title'], ['UserName', 'entry-username'], ['URL', 'entry-url'], ['Notes', 'entry-notes']]) $(id).value = entry?.fields[key] || '';
  $('entry-password').placeholder = entry?.hasPassword ? 'Сохранён · оставь поле пустым, чтобы не менять' : 'Пароль не задан';
  $('entry-meta').textContent = entry ? `Версий в истории: ${entry.historyCount}. Дополнительных полей: ${entry.customFieldCount}. Они сохраняются при редактировании.` : 'Новая запись. Сначала примени её в памяти, затем добавляй файлы.';
  $('delete-entry').hidden = !entryId; $('attachment-file').disabled = !entryId;
  for (const attachment of entry?.attachments || []) {
    const li = element('li'), name = element('span', `${attachment.name} · ${(attachment.size / 1024).toFixed(1)} КБ`, 'attachment-name'), actions = element('div', undefined, 'actions');
    const get = element('button', 'Скачать'), remove = element('button', 'Удалить', 'quiet'); get.type = remove.type = 'button';
    get.addEventListener('click', action(async () => { const data = await rpc('attachment', [entry.id, attachment.name]); download(data, attachment.name); new Uint8Array(data).fill(0); }));
    remove.addEventListener('click', action(async () => {
      if (!confirm(`Удалить вложение «${attachment.name}»?`)) return;
      await flushEditor(); const updated = await rpc('removeAttachment', [entry.id, attachment.name]);
      dirty = true; renderEditor(updated); await snapshot(); updateSaveState();
    }));
    actions.append(get, remove); li.append(name, actions); $('attachments').append(li);
  }
  renderEntries(); updateSaveState();
}
async function flushEditor() {
  if ($('entry-form').hidden || (!draftDirty && entryId)) return;
  if (!$('entry-title').value.trim() || !$('entry-form').reportValidity()) throw Object.assign(new Error(), { code: 'InvalidInput' });
  const fields = { Title: $('entry-title').value, UserName: $('entry-username').value, URL: $('entry-url').value, Notes: $('entry-notes').value };
  if (passwordChanged || !entryId) fields.Password = $('entry-password').value;
  const entry = await rpc('upsert', [{ id: entryId, fields, groupId: $('entry-group').value }]);
  dirty = true; setListing(await rpc('list')); renderEditor(entry); await snapshot(); updateSaveState();
}

$('unlock-form').addEventListener('submit', action(async () => {
  if (worker) return;
  const epoch = generation;
  let password = $('master').value;
  if (createMode && password !== $('master-confirm').value) { status('Мастер-пароли не совпадают.', true); return; }
  if (createMode) {
    currentName = $('new-name').value.trim();
    if (!currentName.endsWith('.kdbx')) currentName += '.kdbx';
    if (!/^[^\x00-\x1f/\\]{1,120}\.kdbx$/.test(currentName)) { status('Используй короткое имя файла без слешей.', true); return; }
  }
  const keyFile = $('key-file').files[0];
  if (keyFile?.size > 1024 * 1024) { status('Ключевой файл должен быть не больше 1 МБ.', true); return; }
  $('master').value = ''; $('master-confirm').value = '';
  $('unlock-submit').disabled = true; status('Открываем базу локально…');
  showOperation(createMode ? 'Готовим новое хранилище…' : 'Загружаем зашифрованную базу…', 'Мастер-пароль и ключевой файл остаются в браузере.');
  try {
    const key = keyFile ? await keyFile.arrayBuffer() : undefined;
    if (epoch !== generation) { key && new Uint8Array(key).fill(0); throw abortError(); }
    let data, revision = null;
    if (!createMode) {
      const response = await request(`/api/vault?name=${encodeURIComponent(currentName)}`);
      revision = response.headers.get('X-Vault-Revision'); data = await response.arrayBuffer();
      if (!revision) throw Object.assign(new Error(), { code: 'OperationFailed' });
    }
    if (epoch !== generation) { key && new Uint8Array(key).fill(0); throw abortError(); }
    currentRevision = revision;
    launchWorker();
    const args = createMode ? [currentName.slice(0, -5), password, key] : [data, password, key];
    const promise = rpc(createMode ? 'create' : 'unlock', args, [data, key].filter(Boolean));
    password = ''; $('master').value = ''; $('master-confirm').value = ''; $('key-file').value = ''; args[1] = '';
    const listing = await promise;
    if (epoch !== generation) throw abortError();
    opened = true; dirty = createMode; lastActivity = 0; activity();
    $('unlock-panel').hidden = true; $('files-panel').hidden = true; $('workspace').hidden = false; $('recovery-panel').hidden = true;
    $('active-name').textContent = currentName; setListing(listing); updateSaveState();
    if (createMode) await snapshot();
    status(createMode ? 'База создана в браузере. Добавь записи и синхронизируй файл.' : 'База открыта локально.');
  } catch (error) {
    if (epoch === generation) {
      if (opened) { lock(true); report(error); }
      else {
        worker?.terminate(); worker = null;
        for (const call of pending.values()) call.reject(abortError()); pending.clear();
      }
    }
    throw error;
  } finally {
    password = '';
    if (epoch === generation) { $('master').value = ''; $('master-confirm').value = ''; $('key-file').value = ''; $('unlock-submit').disabled = false; }
  }
}));
$('unlock-cancel').addEventListener('click', () => { lock(true); status('Открытие отменено.'); });
$('operation-cancel').addEventListener('click', () => {
  const mayHaveUploaded = uploadStarted;
  lock(true);
  status(mayHaveUploaded ? 'Операция отменена, база заблокирована. Уже отправленный файл мог сохраниться на Диске; обнови список перед повторной синхронизацией.' : 'Операция отменена, база заблокирована. Последняя завершённая зашифрованная копия доступна, если она была создана.');
});
$('new-vault').addEventListener('click', () => prepareUnlock('', true));
$('refresh').addEventListener('click', action(loadFiles));
$('search').addEventListener('input', renderEntries);
$('new-entry').addEventListener('click', () => { if (!draftDirty || confirm('Отменить неприменённые изменения?')) renderEditor(null); });
$('entry-form').addEventListener('input', (event) => {
  if (event.target.id === 'attachment-file') return;
  draftDirty = true; if (event.target.id === 'entry-password') passwordChanged = true; updateSaveState();
});
$('entry-form').addEventListener('submit', action(async () => { await flushEditor(); status('Запись применена в памяти. Синхронизируй, чтобы сохранить на Диск.'); }));
$('generate').addEventListener('click', action(async () => {
  $('entry-password').value = await rpc('generate', [24]); passwordChanged = true; draftDirty = true; updateSaveState();
}));
$('clear-password').addEventListener('click', () => { $('entry-password').value = ''; passwordChanged = true; draftDirty = true; updateSaveState(); });
$('reveal').addEventListener('click', action(async () => {
  const hidden = $('entry-password').type === 'password';
  if (hidden && !passwordChanged && entryId) $('entry-password').value = await rpc('password', [entryId]);
  $('entry-password').type = hidden ? 'text' : 'password'; $('reveal').textContent = hidden ? 'Скрыть' : 'Показать';
  if (!hidden && !passwordChanged) $('entry-password').value = '';
}));
$('copy').addEventListener('click', action(async () => {
  const password = passwordChanged || !entryId ? $('entry-password').value : await rpc('password', [entryId]);
  await navigator.clipboard.writeText(password);
  status('Пароль скопирован. Буфер обмена доступен другим приложениям; очисти его после использования.');
}));
$('delete-entry').addEventListener('click', action(async () => {
  if (!entryId || !confirm('Переместить запись в корзину KDBX?')) return;
  setListing(await rpc('remove', [entryId])); wipeEditor(); dirty = true; await snapshot(); updateSaveState();
}));
$('attachment-file').addEventListener('change', action(async () => {
  const file = $('attachment-file').files[0]; if (!file || !entryId) return;
  if (file.size > 8 * 1024 * 1024) { $('attachment-file').value = ''; throw Object.assign(new Error(), { code: 'AttachmentLimit' }); }
  const epoch = generation; await flushEditor(); const data = await file.arrayBuffer();
  if (epoch !== generation) { new Uint8Array(data).fill(0); throw abortError(); }
  const updated = await rpc('attach', [entryId, file.name, data], [data]);
  dirty = true; renderEditor(updated); await snapshot(); updateSaveState();
}));
async function exportVault() { await flushEditor(); download(await snapshot(), currentName); status('Зашифрованная база подготовлена к скачиванию.'); }
$('export').addEventListener('click', action(exportVault)); $('conflict-export').addEventListener('click', action(exportVault));
$('sync').addEventListener('click', action(async () => {
  if (saving) return; saving = true; $('sync').disabled = true;
  const epoch = generation;
  try {
    await flushEditor(); const data = await snapshot();
    if (data.byteLength > Math.min(MAX_FILE, session.limits?.maxFileBytes || MAX_FILE)) throw Object.assign(new Error(), { code: 'FileLimit' });
    status('Отправляем зашифрованный файл на Диск…');
    showOperation('Отправляем зашифрованный файл на Диск…', 'Сервер получает только зашифрованный файл. Уже начатую отправку отмена может не остановить.');
    const headers = { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': session.csrfToken };
    if (currentRevision) headers['If-Match'] = currentRevision; else headers['If-None-Match'] = '*';
    uploadStarted = true;
    const response = await request(`/api/vault?name=${encodeURIComponent(currentName)}`, { method: 'PUT', headers, body: data });
    const result = await response.json(); if (epoch !== generation) throw abortError();
    currentName = result.name || currentName; currentRevision = result.revision; createMode = false;
    await rpc('synced'); dirty = false; $('conflict').hidden = true; $('active-name').textContent = currentName;
    if (recovery) new Uint8Array(recovery).fill(0); recovery = null; recoveryName = ''; recoveryUnsynced = false;
    updateSaveState(); await loadFiles();
    status(result.sourceName && result.sourceName !== result.name ? 'Сохранена новая версия. Исходный файл сохранён.' : 'Зашифрованная база сохранена на Диске.');
  } catch (error) {
    if (epoch !== generation) throw abortError();
    if (error.status === 409) { $('conflict').hidden = false; status('Файл изменился на Диске. Локальные изменения сохранены в памяти.', true); }
    else throw error;
  } finally { if (epoch === generation) { saving = false; uploadStarted = false; } }
}));
$('merge').addEventListener('click', action(async () => {
  await flushEditor();
  showOperation('Загружаем вторую зашифрованную версию…', 'Объединение записей будет выполнено в браузере.');
  const epoch = generation, response = await request(`/api/vault?name=${encodeURIComponent(currentName)}`);
  const revision = response.headers.get('X-Vault-Revision'), data = await response.arrayBuffer();
  if (epoch !== generation) throw abortError();
  if (!revision) throw Object.assign(new Error(), { code: 'OperationFailed' });
  const listing = await rpc('merge', [data], [data]); currentRevision = revision;
  wipeEditor(); setListing(listing); dirty = true; await snapshot(); updateSaveState(); $('conflict').hidden = true;
  status('Объединено локально. Проверь записи и синхронизируй новую версию. История KDBX сохраняется.');
}));
$('lock').addEventListener('click', () => { if (lock()) status('Хранилище заблокировано.'); });
$('recovery-download').addEventListener('click', () => { if (recovery) download(recovery, recoveryName || 'recovery.kdbx'); });
$('recovery-discard').addEventListener('click', () => {
  if (!confirm('Удалить зашифрованную копию из памяти этой страницы?')) return;
  if (recovery) new Uint8Array(recovery).fill(0); recovery = null; recoveryName = ''; recoveryUnsynced = false; showRecovery();
});
$('logout').addEventListener('click', (event) => {
  event.preventDefault();
  if (!lock()) return;
  action(async () => {
    const response = await request('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken } });
    await response.text();
    session.authenticated = false; $('files-panel').hidden = true; $('files').replaceChildren(); $('account').textContent = ''; $('logout').hidden = true;
    $('welcome').hidden = false; $('login').hidden = false; status('Выход выполнен.');
  })(event);
});

(async () => {
  const response = await request('/api/session'); session = await response.json();
  $('welcome').hidden = Boolean(session.authenticated); $('setup').hidden = session.configured !== false;
  $('login').hidden = session.configured === false || session.authenticated;
  $('logout').hidden = !session.authenticated; $('files-panel').hidden = !session.authenticated;
  $('account').textContent = session.authenticated ? session.user.login : '';
  if (session.authenticated) { await loadFiles(); status('Выбери базу. Для открытия нужен её мастер-пароль.'); }
  else status(session.configured === false ? 'Хранилище готово. Осталось настроить вход через Яндекс.' : 'Войди через Яндекс, чтобы увидеть файлы на Диске.');
})().catch(report);
