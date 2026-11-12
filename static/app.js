'use strict';
/* NetWatch – interface d'administration (vanilla JS, français) */

const $ = (s, el = document) => el.querySelector(s);
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = !!v;
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

const S = { me: null, cats: {}, catList: [], kinds: {}, timer: null, status: null };

async function api(path, opts = {}) {
  const init = { method: opts.method || (opts.body ? 'POST' : 'GET'), headers: { 'Content-Type': 'application/json' } };
  if (opts.body) init.body = JSON.stringify(opts.body);
  const r = await fetch(path, init);
  if (r.status === 401 && !opts.quiet) { showLogin(); throw new Error('non authentifié'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { if (!opts.quiet) toast(data.error || ('Erreur ' + r.status), 'error'); throw new Error(data.error || r.status); }
  return data;
}

function toast(msg, kind = '') {
  const t = h('div', { class: 'toast ' + kind }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 4000);
}

function modal(title, content, buttons) {
  const card = $('#modalCard');
  card.innerHTML = '';
  card.append(h('h3', {}, title), content, h('div', { class: 'row end', style: 'margin-top:14px' }, buttons));
  $('#modal').classList.remove('hidden');
}
function closeModal() { $('#modal').classList.add('hidden'); }
function confirmDlg(text, okLabel = 'Confirmer') {
  return new Promise(res => {
    modal('Confirmation', h('p', {}, text), [
      h('button', { class: 'btn', onclick: () => { closeModal(); res(false); } }, 'Annuler'),
      h('button', { class: 'btn primary', onclick: () => { closeModal(); res(true); } }, okLabel)]);
  });
}

/* ---- formatting ---- */
const n = x => (x || 0).toLocaleString('fr-CA');
const fmtTs = ts => ts ? new Date(ts * 1000).toLocaleString('fr-CA', { dateStyle: 'short', timeStyle: 'short' }) : '';
const fmtTime = ts => ts ? new Date(ts * 1000).toLocaleTimeString('fr-CA', { hour: '2-digit', minute: '2-digit' }) : '';
function ago(ts) {
  if (!ts) return 'jamais';
  const d = Date.now() / 1000 - ts;
  if (d < 60) return "à l'instant";
  if (d < 3600) return `il y a ${Math.floor(d / 60)} min`;
  if (d < 86400) return `il y a ${Math.floor(d / 3600)} h`;
  return `il y a ${Math.floor(d / 86400)} j`;
}
const dayStr = d => d.toISOString().slice(0, 10);
function localDay(offset = 0) { const d = new Date(); d.setDate(d.getDate() + offset); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
function catBadge(key) {
  if (!key) return h('span', { class: 'muted' }, '—');
  const c = S.cats[key];
  return h('span', { class: 'badge sev' + (c ? c.severity : 2), title: key }, c ? c.label : key);
}
const ACTION_FR = { block: 'Bloqué', alert: 'Alerte', log: 'Journal', ignore: 'Ignoré', allow: 'Autorisé' };
const actionBadge = a => h('span', { class: 'badge ' + a }, ACTION_FR[a] || a);
const kindBadge = k => h('span', { class: 'badge kind' }, S.kinds[k] || k || 'Inconnu');
const devLink = (id, name) => h('a', { href: '#/appareils/' + id, class: 'nowrap' }, name);
const helpBtn = sec => h('a', { class: 'btn help', href: '#/manuel/' + sec, title: 'Ouvrir le chapitre du manuel sur cette page' }, '? Aide');
const pageHead = (title, sub, right, help) => h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, title), sub ? h('div', { class: 'sub' }, sub) : null),
  h('div', { class: 'row' }, right || null, help ? helpBtn(help) : null));
function store(key, value) {  // per-viewer conveniences only; storage may be unavailable
  try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; }
}
const card = (title, ...body) => h('div', { class: 'card' }, title ? h('h2', {}, title) : null, ...body);
function table(cols, rows, rowFn, emptyText = 'Rien à afficher') {
  if (!rows.length) return h('div', { class: 'empty' }, emptyText);
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, cols.map(c => h('th', { class: c.startsWith('#') ? 'num' : '' }, c.replace(/^#/, ''))))),
    h('tbody', {}, rows.map(rowFn))));
}
const td = (content, cls) => h('td', { class: cls || '' }, content);
function catSelect(value, extra = []) {
  return h('select', { value }, [...extra, ...S.catList.map(c => h('option', { value: c.key, selected: c.key === value }, c.label))]);
}
function periodSelect(value = '7') {
  return h('select', {}, [['today', "Aujourd'hui"], ['7', '7 derniers jours'], ['30', '30 derniers jours'], ['all', 'Tout']]
    .map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
}
function periodRange(v) {
  if (v === 'today') return { from: localDay(0), to: localDay(0) };
  if (v === '7') return { from: localDay(-6), to: localDay(0) };
  if (v === '30') return { from: localDay(-29), to: localDay(0) };
  return {};
}
const qs = o => Object.entries(o).filter(([, v]) => v !== '' && v != null && v !== false).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

async function addRule(domain, category, note = '') {
  await api('/api/rules', { body: { domain, category, note } });
  toast(category === 'allow' ? `${domain} autorisé` : `${domain} → ${S.cats[category] ? S.cats[category].label : category}`, 'ok');
}
function ruleButtons(domain, refresh) {
  return h('span', { class: 'nowrap' },
    h('button', { class: 'btn small', title: 'Ne plus signaler ce domaine', onclick: async e => { e.stopPropagation(); if (await confirmDlg(`Autoriser ${domain} (et ses sous-domaines) ? Il ne sera plus signalé.`)) { await addRule(domain, 'allow'); refresh && refresh(); } } }, 'Autoriser'), ' ',
    h('button', { class: 'btn small danger', title: 'Bloquer ce domaine sur tout le réseau', onclick: async e => { e.stopPropagation(); if (await confirmDlg(`Bloquer ${domain} (et ses sous-domaines) pour tous les appareils ?`, 'Bloquer')) { await addRule(domain, 'blocked'); refresh && refresh(); } } }, 'Bloquer'));
}

/* ---- auth ---- */
function showLogin(setup) {
  $('#shell').classList.add('hidden');
  $('#login').classList.remove('hidden');
  const first = !!setup;
  $('#loginTitle').textContent = first ? 'Choisir le mot de passe administrateur' : 'Connexion';
  $('#loginHint').textContent = first ? 'Premier démarrage : ce mot de passe protège le tableau de bord (8 caractères minimum).' : 'Entrez le mot de passe administrateur.';
  $('#loginPw2').classList.toggle('hidden', !first);
  $('#loginForm').dataset.setup = first ? '1' : '';
  $('#loginPw').focus();
}
$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = $('#loginPw').value, setup = $('#loginForm').dataset.setup === '1';
  $('#loginErr').textContent = '';
  if (setup && pw !== $('#loginPw2').value) { $('#loginErr').textContent = 'Les deux mots de passe diffèrent.'; return; }
  try {
    await api(setup ? '/api/setup' : '/api/login', { body: { password: pw }, quiet: true });
    $('#loginPw').value = ''; $('#loginPw2').value = '';
    await boot();
  } catch (err) { $('#loginErr').textContent = err.message; }
});
$('#logoutBtn').addEventListener('click', async () => { await api('/api/logout', { body: {} }); location.reload(); });

async function boot() {
  const me = await api('/api/me', { quiet: true });
  S.me = me;
  $('#loginSite').textContent = me.site_name || '';
  if (!me.auth) return showLogin(me.setup_needed);
  S.catList = me.categories || [];
  S.cats = Object.fromEntries(S.catList.map(c => [c.key, c]));
  S.kinds = me.kinds || {};
  $('#login').classList.add('hidden');
  $('#shell').classList.remove('hidden');
  $('#railSite').textContent = me.site_name || '';
  $('#versionTxt').textContent = 'NetWatch ' + me.version;
  refreshStatus();
  if (!S.statusTimer) S.statusTimer = setInterval(refreshStatus, 30000);
  route();
}

async function refreshStatus() {
  try {
    const st = await api('/api/status', { quiet: true });
    S.status = st;
    const pill = $('#statusPill');
    pill.className = 'pill ' + (st.dns.listening ? 'ok' : 'bad');
    pill.textContent = st.dns.listening ? `DNS actif · ${n(st.dns.stats.queries)} req.` : 'DNS inactif';
    pill.title = st.dns.listening ? `Relais : ${st.dns.upstreams.join(', ')}` : st.dns.error;
    const up = $('#updatePill');
    if (st.lists_update.running) { up.classList.remove('hidden'); up.className = 'pill warn'; up.textContent = `Listes : ${st.lists_update.message}`; }
    else up.classList.add('hidden');
  } catch (e) { /* session expirée : géré par api() */ }
}

/* ---- router ---- */
const VIEWS = { '': 'dashboard', appareils: 'devices', alertes: 'alerts', journal: 'journal', listes: 'lists', pc: 'agents', reglages: 'settings', manuel: 'manual' };
function route() {
  if (!S.me || !S.me.auth) return;
  const [seg, arg] = location.hash.replace(/^#\/?/, '').split('/');
  const view = VIEWS[seg] || 'dashboard';
  document.querySelectorAll('.rail a[data-view]').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  clearInterval(S.timer); S.timer = null;
  $('#main').innerHTML = '';
  const fn = { dashboard: renderDashboard, devices: arg ? () => renderDevice(+arg) : renderDevices, alerts: renderAlerts, journal: renderJournal, lists: renderLists, agents: renderAgents, settings: renderSettings, manual: () => renderManual(arg) }[view];
  fn().catch(e => { if (e.message !== 'non authentifié') $('#main').append(h('div', { class: 'note warn' }, 'Erreur : ' + e.message)); });
}
window.addEventListener('hashchange', route);

/* ---- tableau de bord ---- */
async function renderDashboard() {
  const main = $('#main');
  const draw = async () => {
    const [d, st] = await Promise.all([api('/api/dashboard?days=14'), api('/api/status')]);
    const k = d.kpi;
    main.innerHTML = '';
    main.append(pageHead('Tableau de bord', `${st.site_name} · ${new Date().toLocaleDateString('fr-CA', { weekday: 'long', day: 'numeric', month: 'long' })}`,
      h('button', { class: 'btn', onclick: draw }, 'Rafraîchir'), 'tableau-de-bord'));
    if (!store('nw-welcome-done')) main.append(h('div', { class: 'card welcome' },
      h('div', {}, h('b', {}, 'Nouveau sur NetWatch ?'), ' Le manuel explique chaque page en 10 minutes, avec des captures d\'écran. Le bouton « ? Aide » en haut de chaque page ouvre le bon chapitre.'),
      h('div', { class: 'row' }, h('a', { class: 'btn primary', href: '#/manuel' }, 'Lire le manuel'),
        h('button', { class: 'btn', onclick: e => { store('nw-welcome-done', '1'); e.target.closest('.welcome').remove(); } }, 'Masquer'))), h('div', { style: 'height:16px' }));
    const steps = [
      [st.dns.listening, `DNS en écoute sur le port ${st.dns.port}`, st.dns.error || ''],
      [st.listed > 2000, `Listes de domaines chargées (${n(st.listed)} entrées)`, 'lancez « Mettre à jour les listes » dans Listes'],
      [k.devices_total > 1, `Appareils vus sur le réseau (${k.devices_total})`, `option DNS du DHCP = ${st.ip}, puis les appareils arrivent en renouvelant leur adresse (jusqu'à 2 jours ; Wi-Fi off/on pour un téléphone)`],
      [st.password_set, 'Mot de passe administrateur défini', ''],
    ];
    if (steps.some(s => !s[0])) main.append(card('Mise en service', h('ul', { class: 'checklist' },
      steps.map(s => h('li', {}, h('span', { class: 'check ' + (s[0] ? 'ok' : 'bad') }, s[0] ? '✓' : '!'), s[1], !s[0] && s[2] ? h('span', { class: 'muted small' }, ' — ' + s[2]) : null)))), h('div', { style: 'height:16px' }));
    main.append(h('div', { class: 'grid kpi' },
      h('div', { class: 'card kpi-card' }, h('div', { class: 'num' }, n(k.active_devices)), h('div', { class: 'lbl' }, `appareils actifs (sur ${n(k.devices_total)})`)),
      h('div', { class: 'card kpi-card' }, h('div', { class: 'num' }, n(k.queries_today)), h('div', { class: 'lbl' }, "requêtes DNS aujourd'hui")),
      h('div', { class: 'card kpi-card' + (k.alerts_today ? ' warn' : '') }, h('div', { class: 'num' }, n(k.alerts_today)), h('div', { class: 'lbl' }, "alertes aujourd'hui")),
      h('div', { class: 'card kpi-card' + (k.blocks_today ? ' bad' : '') }, h('div', { class: 'num' }, n(k.blocks_today)), h('div', { class: 'lbl' }, "accès bloqués aujourd'hui"))));
    main.append(h('div', { style: 'height:16px' }));
    main.append(card(['Dernières alertes', h('a', { href: '#/alertes', class: 'small' }, 'Tout voir')],
      table(['Heure', 'Appareil', 'Domaine', 'Catégorie', 'Action'], d.latest.slice(0, 10), e => h('tr', {},
        td(fmtTs(e.ts), 'nowrap'), td(devLink(e.device_id, e.device)), td(e.domain, 'mono'), td(catBadge(e.category)), td(actionBadge(e.action))),
        'Aucune alerte pour le moment')));
    main.append(h('div', { style: 'height:16px' }));
    main.append(h('div', { class: 'grid two' },
      card("Appareils signalés aujourd'hui", table(['Appareil', '#Alertes', '#Bloqués'], d.top_devices, r => h('tr', {},
        td(devLink(r.device_id, r.device)), td(n(r.alerts), 'num'), td(n(r.blocks), 'num')), 'Aucun appareil signalé')),
      card("Domaines signalés aujourd'hui", table(['Domaine', 'Catégorie', '#Fois'], d.top_domains, r => h('tr', {},
        td(r.domain, 'mono'), td(catBadge(r.category)), td(n(r.n), 'num')), 'Aucun domaine signalé'))));
    main.append(h('div', { style: 'height:16px' }));
    main.append(card('14 derniers jours', table(['Jour', '#Requêtes', '#Alertes', '#Bloqués'], [...d.per_day].reverse(), r => h('tr', {},
      td(r.day), td(n(r.queries), 'num'), td(n(r.alerts), 'num'), td(n(r.blocks), 'num')))));
  };
  await draw();
  S.timer = setInterval(() => draw().catch(() => {}), 30000);
}

/* ---- appareils ---- */
async function renderDevices() {
  const main = $('#main');
  const f = { q: '', kind: '', online: false, ignored: false };
  const body = h('div');
  const draw = async () => {
    const { devices } = await api('/api/devices');
    const rows = devices.filter(d => (!f.online || d.online) && (f.ignored || !d.ignored) && (!f.kind || d.kind_eff === f.kind)
      && (!f.q || [d.name, d.ip, d.mac, d.owner, d.vendor, d.hostname].join(' ').toLowerCase().includes(f.q.toLowerCase())));
    body.innerHTML = '';
    body.append(card(null, table(['', 'Appareil', 'Type', 'Adresse IP / MAC', 'Fabricant', 'Propriétaire', "#Requêtes auj.", '#Signalées', 'Dernière activité'], rows, d => h('tr', { class: 'clickable', onclick: () => location.hash = '#/appareils/' + d.id },
      td(h('span', { class: 'status-dot' + (d.online ? ' on' : ''), title: d.online ? 'En ligne' : 'Hors ligne' })),
      td([h('b', { class: 'nowrap' }, d.name), d.ignored ? h('span', { class: 'muted small' }, ' (ignoré)') : null, d.agent_user ? h('div', { class: 'muted small nowrap' }, 'Session : ' + d.agent_user) : null]),
      td(kindBadge(d.kind_eff)), td([h('div', { class: 'mono' }, d.ip || '—'), h('div', { class: 'mono muted tiny' }, d.mac || '')]), td(d.vendor || '—'), td(d.owner || '—'),
      td(n(d.queries_today), 'num'), td(d.flagged_today ? h('b', { style: 'color:var(--bad)' }, n(d.flagged_today)) : '0', 'num'),
      td(ago(Math.max(d.last_seen || 0, d.agent_seen || 0)), 'nowrap')), 'Aucun appareil vu. Vérifiez que le DHCP distribue ce serveur comme DNS.')));
  };
  main.append(pageHead('Appareils', 'Tout ce qui envoie des requêtes DNS à NetWatch : PC, téléphones, tablettes, équipements.', null, 'appareils'));
  main.append(h('div', { class: 'filters' },
    h('input', { type: 'text', placeholder: 'Rechercher (nom, IP, MAC, propriétaire)…', oninput: e => { f.q = e.target.value; draw(); } }),
    h('select', { onchange: e => { f.kind = e.target.value; draw(); } }, h('option', { value: '' }, 'Tous les types'), Object.entries(S.kinds).map(([k, l]) => h('option', { value: k }, l))),
    h('label', { class: 'c' }, h('input', { type: 'checkbox', onchange: e => { f.online = e.target.checked; draw(); } }), 'En ligne seulement'),
    h('label', { class: 'c' }, h('input', { type: 'checkbox', onchange: e => { f.ignored = e.target.checked; draw(); } }), 'Afficher les ignorés')));
  main.append(body);
  await draw();
  S.timer = setInterval(() => draw().catch(() => {}), 30000);
}

async function renderDevice(id) {
  const main = $('#main');
  let days = 7, tab = 'flagged';
  const draw = async () => {
    const d = await api(`/api/devices/${id}?days=${days}`);
    main.innerHTML = '';
    main.append(pageHead(d.name, [kindBadge(d.kind_eff), ' ', d.ip || '', d.owner ? ` · ${d.owner}` : ''], h('a', { href: '#/appareils', class: 'btn' }, '← Appareils'), 'fiche-appareil'));
    const info = h('dl', { class: 'info-grid' },
      h('dt', {}, 'Adresse IP'), h('dd', { class: 'mono' }, d.ip || '—'),
      h('dt', {}, 'Adresse MAC'), h('dd', { class: 'mono' }, d.mac || '—'),
      h('dt', {}, 'Fabricant'), h('dd', {}, d.vendor || '—'),
      h('dt', {}, 'Nom réseau'), h('dd', {}, d.hostname || '—'),
      h('dt', {}, 'Première activité'), h('dd', {}, fmtTs(d.first_seen)),
      h('dt', {}, 'Dernière activité'), h('dd', {}, fmtTs(d.last_seen) + ' (' + ago(d.last_seen) + ')'),
      h('dt', {}, 'Requêtes (total)'), h('dd', {}, n(d.queries_total)),
      d.agent_seen ? [h('dt', {}, 'Agent PC'), h('dd', {}, `${d.agent_host} · session ${d.agent_user || '?'} · contact ${ago(d.agent_seen)}`)] : null);
    const label = h('input', { type: 'text', value: d.label || '', placeholder: d.hostname || d.ip });
    const owner = h('input', { type: 'text', value: d.owner || '', placeholder: 'ex. Marc (production)' });
    const kind = h('select', {}, h('option', { value: '' }, `Automatique (${S.kinds[d.kind_auto] || 'inconnu'})`), Object.entries(S.kinds).map(([k, l]) => h('option', { value: k, selected: d.kind === k }, l)));
    const ignored = h('input', { type: 'checkbox', checked: !!d.ignored });
    const form = h('div', { class: 'stack' },
      h('div', { class: 'form-grid' }, h('label', { class: 'f' }, 'Nom affiché', label), h('label', { class: 'f' }, 'Propriétaire / utilisateur', owner), h('label', { class: 'f' }, 'Type', kind)),
      h('label', { class: 'c' }, ignored, 'Ignorer cet appareil (masqué des listes, toujours journalisé)'),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { await api(`/api/devices/${id}`, { body: { label: label.value, owner: owner.value, kind: kind.value, ignored: ignored.checked } }); toast('Appareil enregistré', 'ok'); draw(); } }, 'Enregistrer'),
        h('span', { class: 'spacer' }),
        h('button', { class: 'btn danger', onclick: async () => { if (await confirmDlg("Oublier cet appareil et tout son historique ? Il réapparaîtra s'il se reconnecte.", 'Oublier')) { await api(`/api/devices/${id}`, { method: 'DELETE', body: {} }); location.hash = '#/appareils'; } } }, 'Oublier')));
    main.append(h('div', { class: 'grid two' }, card('Identité', info), card('Fiche', form)));
    main.append(h('div', { style: 'height:16px' }));
    const tabs = h('div', { class: 'tabs' }, [['flagged', `Domaines signalés (${d.flagged.length})`], ['all', `Tous les domaines (${d.top_domains.length})`], ['events', `Événements (${d.events.length})`]]
      .map(([k, l]) => h('button', { class: k === tab ? 'active' : '', onclick: () => { tab = k; draw(); } }, l)));
    const period = h('select', { onchange: e => { days = +e.target.value; draw(); } }, [[1, "Aujourd'hui"], [7, '7 jours'], [30, '30 jours'], [90, '90 jours']].map(([v, l]) => h('option', { value: v, selected: v === days }, l)));
    let content;
    if (tab === 'events') content = table(['Heure', 'Domaine', 'Catégorie', 'Action', ''], d.events, e => h('tr', {}, td(fmtTs(e.ts), 'nowrap'), td(e.domain, 'mono'), td(catBadge(e.category)), td(actionBadge(e.action)), td(ruleButtons(e.domain, draw))), 'Aucun événement');
    else {
      const rows = tab === 'flagged' ? d.flagged : d.top_domains;
      content = table(['Domaine', 'Catégorie', '#Requêtes', '#Bloquées', 'Dernière', ''], rows, r => h('tr', {}, td(r.domain, 'mono'), td(catBadge(r.category)), td(n(r.c), 'num'), td(n(r.b), 'num'), td(fmtTs(r.last_ts), 'nowrap'), td(ruleButtons(r.domain, draw))), tab === 'flagged' ? 'Aucun domaine signalé sur la période' : 'Aucune requête sur la période');
    }
    main.append(card([h('span', {}, 'Activité'), period], tabs, content));
    if (d.days.length) main.append(h('div', { style: 'height:16px' }), card('Par jour', table(['Jour', '#Requêtes', '#Bloquées'], [...d.days].reverse(), r => h('tr', {}, td(r.day), td(n(r.c), 'num'), td(n(r.b), 'num')))));
  };
  await draw();
}

/* ---- alertes ---- */
async function renderAlerts() {
  const main = $('#main');
  const f = { device: '', cat: '', action: '', q: '', period: '7', offset: 0 };
  const { devices } = await api('/api/devices');
  const body = h('div');
  const draw = async (more) => {
    if (!more) f.offset = 0;
    const r = periodRange(f.period);
    const { events } = await api('/api/events?' + qs({ device: f.device, cat: f.cat, action: f.action, q: f.q, from: r.from, to: r.to, limit: 200, offset: f.offset }));
    if (!more) body.innerHTML = '';
    const tbl = table(['Heure', 'Appareil', 'Domaine', 'Catégorie', 'Action', ''], events, e => h('tr', {},
      td(fmtTs(e.ts), 'nowrap'), td(devLink(e.device_id, e.device)), td(e.domain, 'mono'), td(catBadge(e.category)), td(actionBadge(e.action)), td(ruleButtons(e.domain, () => draw()))), 'Aucune alerte sur la période');
    if (more && body.firstChild) { const tb = body.querySelector('tbody'); if (tb && tbl.querySelector) { const nt = tbl.querySelector('tbody'); if (nt) tb.append(...nt.children); } }
    else body.append(card(null, tbl));
    const moreBtn = $('#moreBtn');
    if (moreBtn) moreBtn.disabled = events.length < 200;
  };
  main.append(pageHead('Alertes', 'Chaque accès à un domaine classé « alerte » ou « bloqué » (une entrée par appareil et domaine par minute).', null, 'alertes'));
  main.append(h('div', { class: 'filters' },
    h('select', { onchange: e => { f.device = e.target.value; draw(); } }, h('option', { value: '' }, 'Tous les appareils'), devices.map(d => h('option', { value: d.id }, d.name))),
    catSelect('', [h('option', { value: '' }, 'Toutes les catégories')]).cloneNode(true),
    h('select', { onchange: e => { f.action = e.target.value; draw(); } }, h('option', { value: '' }, 'Alertes et blocages'), h('option', { value: 'alert' }, 'Alertes seulement'), h('option', { value: 'block' }, 'Blocages seulement')),
    periodSelect('7'),
    h('input', { type: 'text', placeholder: 'Domaine contient…', oninput: e => { f.q = e.target.value; draw(); } })));
  const filters = main.querySelector('.filters');
  filters.children[1].addEventListener('change', e => { f.cat = e.target.value; draw(); });
  filters.children[3].addEventListener('change', e => { f.period = e.target.value; draw(); });
  main.append(body, h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { id: 'moreBtn', class: 'btn', onclick: () => { f.offset += 200; draw(true); } }, 'Afficher plus')));
  await draw();
}

/* ---- journal ---- */
async function renderJournal() {
  const main = $('#main');
  const f = { device: '', cat: '', q: '', period: 'today', flagged: false };
  const { devices } = await api('/api/devices');
  const body = h('div');
  const query = () => { const r = periodRange(f.period); return qs({ device: f.device, cat: f.cat, q: f.q, from: r.from, to: r.to, flagged: f.flagged ? 1 : '', limit: 500 }); };
  const draw = async () => {
    const { rows } = await api('/api/journal?' + query());
    body.innerHTML = '';
    body.append(card(null, table(['Jour', 'Appareil', 'Domaine', 'Catégorie', '#Requêtes', '#Bloquées', 'Dernière', ''], rows, r => h('tr', {},
      td(r.day, 'nowrap'), td(devLink(r.device_id, r.device)), td(r.domain, 'mono'), td(catBadge(r.category)), td(n(r.count), 'num'), td(n(r.blocked), 'num'), td(fmtTime(r.last_ts)), td(ruleButtons(r.domain, draw))), 'Aucune requête sur la période'),
      rows.length >= 500 ? h('div', { class: 'muted small', style: 'padding:8px' }, 'Affichage limité à 500 lignes : affinez les filtres ou exportez en CSV.') : null));
  };
  main.append(pageHead('Journal', 'Domaines consultés par appareil et par jour (comptage, pas le contenu des pages).',
    h('button', { class: 'btn', onclick: () => { location.href = '/api/journal.csv?' + query(); } }, 'Exporter CSV'), 'journal'));
  const catSel = catSelect('', [h('option', { value: '' }, 'Toutes les catégories')]);
  catSel.addEventListener('change', e => { f.cat = e.target.value; draw(); });
  const per = periodSelect('today'); per.addEventListener('change', e => { f.period = e.target.value; draw(); });
  main.append(h('div', { class: 'filters' },
    h('select', { onchange: e => { f.device = e.target.value; draw(); } }, h('option', { value: '' }, 'Tous les appareils'), devices.map(d => h('option', { value: d.id }, d.name))),
    catSel, per,
    h('input', { type: 'text', placeholder: 'Domaine contient…', oninput: e => { f.q = e.target.value; draw(); } }),
    h('label', { class: 'c' }, h('input', { type: 'checkbox', onchange: e => { f.flagged = e.target.checked; draw(); } }), 'Classés seulement')));
  main.append(body);
  await draw();
}

/* ---- listes ---- */
async function renderLists() {
  const main = $('#main');
  const draw = async () => {
    const L = await api('/api/lists');
    // keep the page live while an update runs, stop polling when it ends
    if (L.update.running && !S.timer) S.timer = setInterval(() => { if (location.hash.startsWith('#/listes')) draw().catch(() => {}); }, 3000);
    if (!L.update.running && S.timer) { clearInterval(S.timer); S.timer = null; }
    main.innerHTML = '';
    main.append(pageHead('Listes et règles', `${n(L.listed)} domaines classés. L'action d'une catégorie s'applique immédiatement à tout le réseau.`, null, 'listes'));
    const actionSel = c => h('select', { class: 'compact', onchange: async e => { await api('/api/lists/categories', { body: { key: c.key, action: e.target.value } }); toast(`${c.label} : ${ACTION_FR[e.target.value]}`, 'ok'); } },
      [['ignore', 'Ignorer'], ['log', 'Journal seulement'], ['alert', 'Alerter'], ['block', 'Bloquer']].map(([v, l]) => h('option', { value: v, selected: c.action === v }, l)));
    const upd = L.update;
    const srcCard = card(['Sources', h('button', { class: 'btn primary small', disabled: upd.running, onclick: async () => { await api('/api/lists/update', { body: {} }); toast('Mise à jour lancée (quelques minutes)'); setTimeout(draw, 1500); } }, upd.running ? 'Mise à jour en cours…' : 'Mettre à jour les listes')],
      upd.running ? h('div', {}, h('div', { class: 'small' }, `${upd.step} — ${upd.message}`), h('div', { class: 'progress' }, h('div', { style: `width:${upd.pct}%` }))) : null,
      upd.error ? h('div', { class: 'note warn' }, upd.error) : null,
      table(['Source', 'État', '#Entrées', 'Dernière mise à jour'], L.sources, s => h('tr', {}, td([s.name, s.url ? h('div', { class: 'muted tiny mono break' }, s.url) : null]), td(s.status, 'break'), td(n(s.count), 'num'), td(s.last_update ? fmtTs(s.last_update) : '—'))),
      h('p', { class: 'muted small' }, `Mise à jour automatique tous les ${L.auto_update_days} jours (Réglages). Les listes UT1 (Université Toulouse Capitole) sont la référence des filtres scolaires et d'entreprise en France.`));
    main.append(h('div', { class: 'grid two lists-grid' },
      card('Catégories', table(['Catégorie', '#Domaines', 'Action'], L.categories, c => h('tr', {}, td(catBadge(c.key)), td(n(c.count), 'num'), td(actionSel(c)))),
        h('p', { class: 'muted small' }, 'Bloquer = le domaine ne se résout pas (page « accès bloqué » en HTTP). Alerter = accès permis mais signalé. Journal = compté sans alerte.')),
      h('div', { class: 'stack' }, srcCard, testCard(), rulesCard(L, draw), keywordsCard(L))));
  };
  await draw();
}
function testCard() {
  const inp = h('input', { type: 'text', placeholder: 'ex. pornhub.com', style: 'flex:1' });
  const out = h('div', { style: 'margin-top:10px' });
  const run = async () => {
    if (!inp.value.trim()) return;
    const r = await api('/api/lists/test?domain=' + encodeURIComponent(inp.value.trim()));
    out.innerHTML = '';
    if (!r.result) out.append(h('div', { class: 'note' }, `${r.domain} : aucune classification (accès normal, journalisé).`));
    else out.append(h('div', { class: 'note' + (r.result.action === 'block' ? ' warn' : '') }, r.domain, ' → ', catBadge(r.result.category), ' ', actionBadge(r.result.action), ` (via ${r.result.source === 'rule' ? 'règle manuelle' : r.result.source === 'list' ? 'liste' : 'mot-clé'} : ${r.result.matched})`));
    if (r.listed.length) out.append(h('div', { class: 'muted small', style: 'margin-top:6px' }, 'Présent dans : ' + r.listed.map(x => `${x.domain} [${x.category}] (${x.source})`).join(' ; ')));
  };
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  return card('Tester un domaine', h('div', { class: 'row' }, inp, h('button', { class: 'btn', onclick: run }, 'Tester')), out);
}
function rulesCard(L, draw) {
  const dom = h('input', { type: 'text', placeholder: 'domaine.com', style: 'flex:1' });
  const cat = catSelect('blocked', [h('option', { value: 'allow' }, 'Autoriser (jamais signalé)')]);
  const note = h('input', { type: 'text', placeholder: 'Note (facultatif)' });
  return card('Règles manuelles',
    h('div', { class: 'row' }, dom, cat, note, h('button', { class: 'btn primary', onclick: async () => { await addRule(dom.value, cat.value, note.value); draw(); } }, 'Ajouter')),
    h('div', { style: 'height:8px' }),
    table(['Domaine', 'Effet', 'Note', ''], L.rules, r => h('tr', {}, td(r.domain, 'mono'), td(r.category === 'allow' ? h('span', { class: 'badge ok' }, 'Autorisé') : catBadge(r.category)), td(r.note || ''),
      td(h('button', { class: 'btn small', onclick: async () => { await api('/api/rules/' + r.id, { method: 'DELETE', body: {} }); draw(); } }, 'Retirer'))), 'Aucune règle manuelle'));
}
function keywordsCard(L) {
  const ta = h('textarea', { value: (L.keywords || []).join('\n') });
  return card('Mots-clés suspects', h('p', { class: 'muted small' }, 'Repli quand un domaine n\'est dans aucune liste : si un mot apparaît dans le nom (ex. « porn »), le domaine est classé « Mot-clé suspect ». Un mot par ligne, 3 lettres minimum.'), ta,
    h('div', { class: 'row end', style: 'margin-top:8px' }, h('button', { class: 'btn primary', onclick: async () => { const r = await api('/api/keywords', { body: { keywords: ta.value } }); ta.value = r.keywords.join('\n'); toast('Mots-clés enregistrés', 'ok'); } }, 'Enregistrer')));
}

/* ---- PC (agents) ---- */
async function renderAgents() {
  const main = $('#main');
  const A = await api('/api/agents');
  main.append(pageHead('PC de l\'entreprise (agents)', 'Les PC avec l\'agent remontent la session ouverte, leurs serveurs DNS et l\'état des politiques anti-contournement.', null, 'pc'));
  const via = a => a.via_netwatch === true ? h('span', { class: 'badge ok' }, 'Oui') : a.via_netwatch === false ? h('span', { class: 'badge alert', title: (a.agent_info.dns || []).join(', ') }, 'Non') : h('span', { class: 'muted' }, '?');
  main.append(card('PC avec agent', table(['PC', 'Session ouverte', 'Adresse IP / MAC', 'Dernier contact', 'DNS via NetWatch', 'Politiques DoH', 'Windows', 'Agent'], A.agents, a => h('tr', { class: 'clickable', onclick: () => location.hash = '#/appareils/' + a.id },
    td(h('b', { class: 'nowrap' }, a.name)), td(a.agent_user || '—'), td([h('div', { class: 'mono' }, a.ip), h('div', { class: 'mono muted tiny' }, a.mac || '')]), td(ago(a.agent_seen), 'nowrap'), td(via(a)),
    td(a.agent_info.doh_policy ? h('span', { class: 'badge ok' }, 'Appliquées') : h('span', { class: 'badge warn' }, 'Non')), td((a.agent_info.os || '—').replace(/^Microsoft\s+/, '')), td(a.agent_info.version || '—')), 'Aucun agent installé pour le moment')));
  main.append(h('div', { style: 'height:16px' }));
  main.append(card('Installer l\'agent sur un PC',
    h('p', {}, 'Sur chaque PC de l\'entreprise, ouvrez PowerShell en administrateur et collez cette commande :'),
    h('pre', { class: 'code' }, A.install.command),
    h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => { navigator.clipboard.writeText(A.install.command); toast('Commande copiée', 'ok'); } }, 'Copier la commande'),
      h('a', { class: 'btn', href: A.install.url, download: 'Install-NetWatchAgent.ps1' }, 'Télécharger le script')),
    h('ul', { class: 'small', style: 'line-height:1.7' },
      h('li', {}, 'Crée la tâche planifiée « NetWatch Agent » (à l\'ouverture de session, puis toutes les 5 minutes) qui signale le PC et l\'utilisateur connecté.'),
      h('li', {}, 'Désactive le DNS chiffré (DoH) dans Chrome, Edge, Firefox et Windows pour que le filtre ne soit pas contourné.'),
      h('li', {}, 'Laisse le DNS fourni par le DHCP ; ajoutez ', h('span', { class: 'mono' }, '-DnsMode Static'), ' pour forcer ce serveur comme DNS du PC.'),
      h('li', {}, 'Désinstallation : même commande avec ', h('span', { class: 'mono' }, '-Uninstall'), '.'))));
}

/* ---- réglages ---- */
async function renderSettings() {
  const main = $('#main');
  const [s, st] = await Promise.all([api('/api/settings'), api('/api/status')]);
  main.append(pageHead('Réglages', 'Enregistrés dans config.json sur le serveur. Les changements de port demandent un redémarrage de NetWatch.', null, 'reglages'));
  const F = {};
  const fld = (key, label, type = 'text', attrs = {}) => { F[key] = h('input', { type, ...attrs }); return h('label', { class: 'f' }, label, F[key]); };
  F.site_name = h('input', { type: 'text', value: s.site_name });
  F.contact = h('input', { type: 'text', value: s.contact });
  F.upstreams = h('input', { type: 'text', value: (s.dns.upstreams || []).join(', '), placeholder: 'automatique : ' + s.dns.upstreams_auto.join(', ') });
  F.dns_port = h('input', { type: 'number', value: s.dns.port });
  F.log_local = h('input', { type: 'checkbox', checked: !!s.dns.log_local });
  F.bp_enabled = h('input', { type: 'checkbox', checked: !!s.blockpage.enabled });
  F.bp_port = h('input', { type: 'number', value: s.blockpage.port });
  F.retention = h('input', { type: 'number', value: s.retention_days });
  F.online = h('input', { type: 'number', value: s.online_minutes });
  F.auto_days = h('input', { type: 'number', value: s.lists.auto_update_days });
  const a = s.alerts;
  F.email_enabled = h('input', { type: 'checkbox', checked: !!a.email_enabled });
  F.to = h('input', { type: 'text', value: a.to || '', placeholder: 'it@example.com, direction@…' });
  F.smtp_host = h('input', { type: 'text', value: a.smtp_host || '' });
  F.smtp_port = h('input', { type: 'number', value: a.smtp_port || 587 });
  F.smtp_user = h('input', { type: 'text', value: a.smtp_user || '', placeholder: 'compte Gmail' });
  F.smtp_password = h('input', { type: 'password', placeholder: a.has_password ? '•••••••• (inchangé)' : 'mot de passe d\'application Gmail' });
  F.cooldown = h('input', { type: 'number', value: a.cooldown_min });
  F.digest_enabled = h('input', { type: 'checkbox', checked: !!a.digest_enabled });
  F.digest_hour = h('input', { type: 'number', value: a.digest_hour, min: 0, max: 23 });
  const save = async () => {
    const body = { site_name: F.site_name.value, contact: F.contact.value,
      dns: { upstreams: F.upstreams.value, port: +F.dns_port.value, log_local: F.log_local.checked },
      blockpage: { enabled: F.bp_enabled.checked, port: +F.bp_port.value }, retention_days: +F.retention.value, online_minutes: +F.online.value,
      lists: { auto_update_days: +F.auto_days.value },
      alerts: { email_enabled: F.email_enabled.checked, to: F.to.value, smtp_host: F.smtp_host.value, smtp_port: +F.smtp_port.value, smtp_user: F.smtp_user.value, smtp_password: F.smtp_password.value, cooldown_min: +F.cooldown.value, digest_enabled: F.digest_enabled.checked, digest_hour: +F.digest_hour.value } };
    const r = await api('/api/settings', { body });
    toast(r.restart_needed ? 'Enregistré. Redémarrez NetWatch pour appliquer les ports.' : 'Réglages enregistrés', 'ok');
    F.smtp_password.value = '';
  };
  main.append(h('div', { class: 'grid two' },
    h('div', { class: 'stack' },
      card('Général', h('div', { class: 'form-grid' }, h('label', { class: 'f' }, 'Nom du site', F.site_name), h('label', { class: 'f' }, 'Contact affiché sur la page de blocage', F.contact), h('label', { class: 'f' }, 'Rétention du journal (jours)', F.retention), h('label', { class: 'f' }, 'Appareil « actif » si vu depuis (minutes)', F.online), h('label', { class: 'f' }, 'Mise à jour des listes (jours, 0 = manuelle)', F.auto_days))),
      card('DNS', h('div', { class: 'form-grid' }, h('label', { class: 'f' }, 'Serveurs DNS en amont (vide = automatique)', F.upstreams), h('label', { class: 'f' }, 'Port DNS (redémarrage)', F.dns_port)),
        h('label', { class: 'c', style: 'margin-top:10px' }, F.log_local, 'Journaliser aussi les noms locaux (.local, .arpa)'),
        h('p', { class: 'muted small' }, `Amont actuel : ${st.dns.upstreams.join(', ')}. Sur SRV-APP, l'amont automatique est le DNS du domaine (DC01) : les noms internes continuent de fonctionner.`)),
      card('Blocage', h('div', { class: 'form-grid' }, h('label', { class: 'c' }, F.bp_enabled, 'Page « accès bloqué » (HTTP)'), h('label', { class: 'f' }, 'Port de la page (redémarrage)', F.bp_port)),
        h('p', { class: 'muted small' }, `Les domaines bloqués répondent actuellement ${st.block_ip}` + (st.blockpage.running ? ' (page de blocage active).' : ' (page de blocage inactive : le port est occupé ou désactivé).'))),
      card('Courriels d\'alerte',
        h('label', { class: 'c' }, F.email_enabled, 'Envoyer un courriel à chaque alerte (regroupées par appareil et catégorie)'),
        h('div', { class: 'form-grid', style: 'margin-top:10px' }, h('label', { class: 'f' }, 'Destinataires', F.to), h('label', { class: 'f' }, 'Serveur SMTP', F.smtp_host), h('label', { class: 'f' }, 'Port', F.smtp_port), h('label', { class: 'f' }, 'Compte (expéditeur)', F.smtp_user), h('label', { class: 'f' }, 'Mot de passe d\'application', F.smtp_password), h('label', { class: 'f' }, 'Regroupement (minutes)', F.cooldown)),
        h('div', { class: 'row', style: 'margin-top:10px' }, h('label', { class: 'c' }, F.digest_enabled, 'Rapport quotidien à'), F.digest_hour, h('span', { class: 'muted small' }, 'h')),
        h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn', onclick: async () => { await save(); await api('/api/settings/test-email', { body: {} }); toast('Courriel de test envoyé', 'ok'); } }, 'Enregistrer et envoyer un test'))),
      h('div', { class: 'row end' }, h('button', { class: 'btn primary', onclick: save }, 'Enregistrer les réglages'))),
    h('div', { class: 'stack' },
      card('État du système', h('dl', { class: 'info-grid' },
        h('dt', {}, 'Version'), h('dd', {}, st.version), h('dt', {}, 'Serveur'), h('dd', {}, `${st.hostname} (${st.ip})`),
        h('dt', {}, 'Démarré'), h('dd', {}, fmtTs(st.started) + ' (' + ago(st.started) + ')'),
        h('dt', {}, 'DNS'), h('dd', {}, st.dns.listening ? h('span', { class: 'badge ok' }, `en écoute ${st.dns.bind}:${st.dns.port}`) : h('span', { class: 'badge alert' }, st.dns.error)),
        h('dt', {}, 'Relais'), h('dd', {}, st.dns.upstreams.join(', ')),
        h('dt', {}, 'Requêtes'), h('dd', {}, `${n(st.dns.stats.queries)} (cache ${n(st.dns.stats.cache_hits)}, bloquées ${n(st.dns.stats.blocked)}, délais amont ${n(st.dns.stats.upstream_timeouts)})`),
        h('dt', {}, 'Cache'), h('dd', {}, `${n(st.dns.cache_entries)} entrées`),
        h('dt', {}, 'Listes'), h('dd', {}, `${n(st.listed)} domaines, ${n(st.oui)} fabricants`),
        h('dt', {}, 'Base'), h('dd', {}, `${(st.db_size / 1048576).toFixed(1)} Mo`),
        h('dt', {}, 'ARP'), h('dd', {}, `${st.arp_entries} voisins`),
        h('dt', {}, 'Interface'), h('dd', {}, `http://${st.ip}:${st.web_port}/`))),
      card('Mot de passe administrateur', (() => {
        const cur = h('input', { type: 'password', placeholder: 'Actuel' }), nw = h('input', { type: 'password', placeholder: 'Nouveau (8 min.)' });
        return h('div', { class: 'row' }, cur, nw, h('button', { class: 'btn', onclick: async () => { await api('/api/settings/password', { body: { current: cur.value, new: nw.value } }); toast('Mot de passe modifié', 'ok'); cur.value = nw.value = ''; } }, 'Changer'));
      })()),
      card('Documents', h('ul', { style: 'line-height:1.9;margin:0;padding-left:18px' },
        h('li', {}, h('a', { href: '/docs/README.fr.md', target: '_blank' }, 'Guide d\'installation et d\'exploitation (README)')),
        h('li', {}, h('a', { href: '/docs/AVIS-SURVEILLANCE-RESEAU.md', target: '_blank' }, 'Avis aux employés – politique d\'utilisation du réseau (modèle)')),
        h('li', {}, h('a', { href: '/docs/ROUTEUR-ET-TELEPHONES.md', target: '_blank' }, 'Routeur, DHCP et téléphones : comment tout passe par NetWatch')))),
      card(['Journal système', h('button', { class: 'btn small', onclick: async () => { const r = await api('/api/syslog?limit=200'); const box = $('#syslog'); box.innerHTML = ''; r.rows.forEach(l => box.append(h('div', { class: l.level }, `${fmtTs(l.ts)}  ${l.msg}`))); } }, 'Rafraîchir')],
        h('div', { id: 'syslog', class: 'syslog' })))));
  const r = await api('/api/syslog?limit=200');
  r.rows.forEach(l => $('#syslog').append(h('div', { class: l.level }, `${fmtTs(l.ts)}  ${l.msg}`)));
}

/* ---- manuel ---- */
let MANUAL_HTML = null;
async function renderManual(section) {
  const main = $('#main');
  if (!MANUAL_HTML) {
    const r = await fetch('/static/manuel.html', { cache: 'no-cache' });
    if (!r.ok) throw new Error('manuel introuvable');
    MANUAL_HTML = await r.text();
  }
  store('nw-welcome-done', '1');
  const body = h('article', { class: 'manual-body', html: MANUAL_HTML });
  const toc = h('nav', { class: 'manual-toc' }, h('div', { class: 'toc-title' }, 'Sommaire'),
    [...body.querySelectorAll('section[id] > h2')].map(t => h('a', { href: '#/manuel/' + t.parentElement.id, class: t.parentElement.id === section ? 'active' : '' }, t.textContent)));
  main.append(pageHead('Manuel', 'Comment lire et utiliser NetWatch, page par page.'), h('div', { class: 'manual' }, toc, body));
  body.querySelectorAll('img').forEach(img => img.addEventListener('click', () => window.open(img.src, '_blank')));
  const target = section && document.getElementById(section);
  if (target) target.scrollIntoView({ block: 'start' }); else window.scrollTo(0, 0);
}

boot().catch(e => { console.error(e); showLogin(false); });
