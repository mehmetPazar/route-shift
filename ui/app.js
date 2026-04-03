// ============================================================
// Renderer — UI
// ============================================================

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let active = false;
let running = false;
let domainData = []; // [{ domain, source, enabled }]

const MAX_LOG_ENTRIES = 500;

// ==================== SVG ICONS ====================

const ICONS = {
  eyeOn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>'
};

// ==================== YARDIMCI FONKSIYONLAR ====================

function ts() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0'))
    .join(':');
}

function log(msg, cls) {
  const el = document.getElementById('log');
  const entry = document.createElement('div');
  entry.className = 'log-entry' + (cls ? ' log-' + cls : '');

  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = ts();
  entry.appendChild(time);

  const dot = document.createElement('span');
  dot.className = 'log-dot';
  entry.appendChild(dot);

  const message = document.createElement('span');
  message.className = 'log-msg';
  message.textContent = msg;
  entry.appendChild(message);

  el.appendChild(entry);
  el.scrollTop = el.scrollHeight;

  // Prune old entries
  while (el.children.length > MAX_LOG_ENTRIES) {
    el.removeChild(el.firstChild);
  }

  updateLogCount();
}

function logAuto(line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  if (trimmed.includes('[+]') || trimmed.includes('OK') || trimmed.includes('Wi-Fi')) {
    log(trimmed, 'success');
  } else if (trimmed.includes('HATA') || trimmed.includes('bypass çalışmıy') || trimmed.includes('VPN')) {
    log(trimmed, 'error');
  } else if (trimmed.includes('[') || trimmed.includes('===') || trimmed.includes('---')) {
    log(trimmed, 'info');
  } else {
    log(trimmed, 'muted');
  }
}

function updateLogCount() {
  const count = document.getElementById('log').children.length;
  document.getElementById('logCount').textContent = count;
}

// ==================== TAB YONETIMI ====================

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  document.querySelector('.tab[data-tab="' + tabName + '"]').classList.add('active');
  document.getElementById('tab-' + tabName).classList.add('active');
}

// ==================== DURUM YONETIMI ====================

function setStatus(state) {
  const dot = document.getElementById('dot');
  dot.className = 'dot ' + state;

  const statusBadge = document.getElementById('headerStatus');
  statusBadge.className = 'header-status ' + state;

  const label = document.getElementById('statusLabel');
  if (state === 'active') {
    label.textContent = 'Aktif';
  } else if (state === 'loading') {
    label.textContent = 'İşlem Yapılıyor';
  } else {
    label.textContent = 'Devre Dışı';
  }

  active = (state === 'active');
  updateButtons();
}

function updateButtons() {
  document.getElementById('btnOn').disabled = running || active;
  document.getElementById('btnOff').disabled = running || !active;
  document.getElementById('btnTest').disabled = running;
}

// ==================== KOMUT CALISTIRMA ====================

async function run(mode) {
  if (running) return;
  running = true;
  setStatus('loading');
  updateButtons();

  try {
    await invoke('bypass_run', { mode: mode || 'add' });
  } catch (err) {
    log('HATA: ' + (err.message || err), 'error');
  }
}

// ==================== EVENT DINLEYICILER ====================

listen('log-line', (event) => {
  logAuto(event.payload);
});

listen('run-done', (event) => {
  running = false;
  const data = event.payload;

  if (data.mode === 'remove') {
    setStatus('inactive');
    log('Kapatıldı.', 'warn');
  } else if (data.mode === 'test' || data.mode === 'status') {
    setStatus(active ? 'active' : 'inactive');
    log('Test tamamlandı.', 'info');
  } else if (data.success) {
    setStatus('active');
    log('Başarıyla aktif!', 'success');
  } else {
    setStatus('inactive');
    log('Aktif edilemedi. Yönetici izni gerekli olabilir.', 'error');
  }

  updateButtons();
});

listen('tray-action', (event) => {
  const mode = event.payload;
  if (mode === 'add') run('');
  else if (mode === 'remove') run('remove');
});

// ==================== DOMAIN YONETIMI ====================

async function loadDomains() {
  try {
    domainData = await invoke('get_domains');
    renderDomains();
  } catch (e) {
    // Sessizce devam et
  }
}

function renderDomains() {
  const container = document.getElementById('domainList');
  container.innerHTML = '';

  if (domainData.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'domain-empty';
    empty.textContent = 'Henüz domain eklenmemiş.';
    container.appendChild(empty);
    return;
  }

  domainData.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'domain-item';
    if (item.source === 'custom') row.classList.add('custom');
    if (!item.enabled) row.classList.add('disabled');

    // Status dot
    const statusDot = document.createElement('span');
    statusDot.className = 'domain-status-dot';
    row.appendChild(statusDot);

    // Domain name
    const name = document.createElement('span');
    name.className = 'domain-name';
    name.textContent = item.domain;
    row.appendChild(name);

    // Source badge
    const badge = document.createElement('span');
    badge.className = 'domain-badge';
    if (item.source === 'custom') {
      badge.classList.add('custom');
      badge.textContent = 'özel';
    } else {
      badge.textContent = 'varsayılan';
    }
    row.appendChild(badge);

    // Actions
    const actions = document.createElement('span');
    actions.className = 'domain-actions';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'domain-toggle';
    toggleBtn.title = item.enabled ? 'Devre dışı bırak' : 'Etkinleştir';
    toggleBtn.innerHTML = item.enabled ? ICONS.eyeOn : ICONS.eyeOff;
    toggleBtn.addEventListener('click', () => toggleDomain(item.domain, item.source));
    actions.appendChild(toggleBtn);

    if (item.source === 'custom') {
      const delBtn = document.createElement('button');
      delBtn.className = 'domain-remove';
      delBtn.title = 'Sil';
      delBtn.innerHTML = ICONS.trash;
      delBtn.addEventListener('click', () => removeDomain(item.domain));
      actions.appendChild(delBtn);
    }

    row.appendChild(actions);
    container.appendChild(row);
  });
}

async function persistDomains() {
  const extra = domainData
    .filter(d => d.source === 'custom')
    .map(d => d.domain);
  const disabled = domainData
    .filter(d => !d.enabled)
    .map(d => d.domain);

  await invoke('save_domains', { data: { extra, disabled } });
}

async function addDomain(domain) {
  domain = domain.trim().toLowerCase();
  if (!domain) return;

  if (!/^[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$/.test(domain)) {
    log('Geçersiz domain: ' + domain, 'error');
    return;
  }

  if (domainData.some(d => d.domain === domain)) {
    log('Domain zaten listede: ' + domain, 'warn');
    return;
  }

  domainData.push({ domain, source: 'custom', enabled: true });
  renderDomains();
  await persistDomains();
  log('Domain eklendi: ' + domain, 'success');

  if (active && !running) {
    try { await invoke('toggle_domain_route', { domain, enable: true }); } catch (e) { log('HATA: ' + e, 'error'); }
  }
}

async function removeDomain(domain) {
  domainData = domainData.filter(d => !(d.domain === domain && d.source === 'custom'));
  renderDomains();
  await persistDomains();
  log('Domain silindi: ' + domain, 'warn');

  if (active && !running) {
    try { await invoke('toggle_domain_route', { domain, enable: false }); } catch (e) { log('HATA: ' + e, 'error'); }
  }
}

async function toggleDomain(domain, source) {
  const item = domainData.find(d => d.domain === domain && d.source === source);
  if (!item) return;

  item.enabled = !item.enabled;
  renderDomains();
  await persistDomains();
  log('Domain ' + (item.enabled ? 'etkinleştirildi' : 'devre dışı bırakıldı') + ': ' + domain, 'info');

  if (active && !running) {
    try { await invoke('toggle_domain_route', { domain, enable: item.enabled }); } catch (e) { log('HATA: ' + e, 'error'); }
  }
}

// ==================== YONETICI IZNI ====================

async function ensureAdmin() {
  try {
    const alreadyAuthorized = await invoke('ensure_admin');
    if (alreadyAuthorized) {
      log('Yönetici izni mevcut.', 'muted');
    } else {
      log('Yönetici izni alındı.', 'success');
    }
  } catch (err) {
    log('Yönetici izni alınamadı: ' + (err.message || err), 'error');
    log('Her işlemde şifre sorulabilir.', 'warn');
  }
}

// ==================== TITLEBAR ====================

const MAXIMIZE_ICON = '<svg viewBox="0 0 10 10" fill="none"><rect x="1" y="1" width="8" height="8" stroke="currentColor" stroke-width="1" fill="none"/></svg>';
const RESTORE_ICON = '<svg viewBox="0 0 10 10" fill="none"><rect x="2.5" y="0.5" width="7" height="7" stroke="currentColor" stroke-width="1" fill="none"/><rect x="0.5" y="2.5" width="7" height="7" stroke="currentColor" stroke-width="1" fill="var(--bg-secondary)"/></svg>';

function setupTitlebar() {
  const appWindow = window.__TAURI__.window.getCurrentWindow();

  document.getElementById('titlebarMin').addEventListener('click', () => appWindow.minimize());
  document.getElementById('titlebarMax').addEventListener('click', () => appWindow.toggleMaximize());
  document.getElementById('titlebarClose').addEventListener('click', () => appWindow.hide());

  const maxBtn = document.getElementById('titlebarMax');
  async function updateMaxIcon() {
    const maximized = await appWindow.isMaximized();
    maxBtn.innerHTML = maximized ? RESTORE_ICON : MAXIMIZE_ICON;
    maxBtn.title = maximized ? 'Geri Yükle' : 'Büyült';
  }
  appWindow.onResized(updateMaxIcon);
  updateMaxIcon();
}

// ==================== BASLATMA ====================

function init() {
  setupTitlebar();

  // Butonlar
  document.getElementById('btnOn').addEventListener('click', () => run(''));
  document.getElementById('btnOff').addEventListener('click', () => run('remove'));
  document.getElementById('btnTest').addEventListener('click', () => run('test'));
  document.getElementById('btnClear').addEventListener('click', () => {
    document.getElementById('log').innerHTML = '';
    updateLogCount();
  });

  // Tab degistirme
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Domain ekleme
  document.getElementById('btnAddDomain').addEventListener('click', () => {
    const input = document.getElementById('domainInput');
    addDomain(input.value);
    input.value = '';
  });

  document.getElementById('domainInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const input = document.getElementById('domainInput');
      addDomain(input.value);
      input.value = '';
    }
  });

  // Baslangic
  log('RouteShift v2.0 hazır.', 'info');
  ensureAdmin();
  loadDomains();
  setStatus('inactive');
}

document.addEventListener('DOMContentLoaded', init);
