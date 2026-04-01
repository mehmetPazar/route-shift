// ============================================================
// Renderer — UI
// ============================================================

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let active = false;
let running = false;
let domainData = []; // [{ domain, source, enabled }]

// ==================== YARDIMCI FONKSIYONLAR ====================

function ts() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, '0'))
    .join(':');
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function log(msg, cls) {
  const el = document.getElementById('log');
  const span = document.createElement('span');
  span.className = cls || '';
  span.innerHTML = '[' + ts() + '] ' + esc(msg) + '\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
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

// ==================== TAB YONETIMI ====================

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  document.querySelector('.tab[data-tab="' + tabName + '"]').classList.add('active');
  document.getElementById('tab-' + tabName).classList.add('active');
}

// ==================== DURUM YONETIMI ====================

function setStatus(state) {
  document.getElementById('dot').className = 'dot ' + state;

  const header = document.getElementById('header');
  if (state === 'active') {
    header.classList.add('active');
  } else {
    header.classList.remove('active');
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

const MODE_LABELS = { add: 'ADD', remove: 'REMOVE', test: 'TEST', status: 'STATUS' };

async function run(mode) {
  if (running) return;
  running = true;
  setStatus('loading');
  const label = MODE_LABELS[mode || 'add'] || mode;
  log(label + ' başlatılıyor...', 'info');
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

  domainData.forEach((item, index) => {
    const row = document.createElement('div');
    row.className = 'domain-item';
    if (item.source === 'custom') row.classList.add('custom');
    if (!item.enabled) row.classList.add('disabled');

    const idx = document.createElement('span');
    idx.className = 'domain-index';
    idx.textContent = (index + 1).toString();
    row.appendChild(idx);

    const name = document.createElement('span');
    name.className = 'domain-name';
    name.textContent = item.domain;
    row.appendChild(name);

    const actions = document.createElement('span');
    actions.className = 'domain-actions';

    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'domain-toggle';
    toggleBtn.title = item.enabled ? 'Devre dışı bırak' : 'Etkinleştir';
    toggleBtn.textContent = item.enabled ? '\u25CF' : '\u25CB';
    toggleBtn.addEventListener('click', () => toggleDomain(item.domain, item.source));
    actions.appendChild(toggleBtn);

    if (item.source === 'custom') {
      const delBtn = document.createElement('button');
      delBtn.className = 'domain-remove';
      delBtn.title = 'Sil';
      delBtn.textContent = '\u00D7';
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

// ==================== BASLATMA ====================

function init() {
  // Butonlar
  document.getElementById('btnOn').addEventListener('click', () => run(''));
  document.getElementById('btnOff').addEventListener('click', () => run('remove'));
  document.getElementById('btnTest').addEventListener('click', () => run('test'));
  document.getElementById('btnClear').addEventListener('click', () => {
    document.getElementById('log').innerHTML = '';
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
  log('Aç butonuna tıklayın.', 'muted');

  loadDomains();
  setStatus('inactive');
}

document.addEventListener('DOMContentLoaded', init);
