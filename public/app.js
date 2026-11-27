const state = {
  digest: null,
  presets: [],
  profile: null,
  hours: 168,
  viewMode: 'tldr', // 'tldr' | 'detailed'
  verdictFilter: 'ALL',
  bucketFilter: 'ALL',
  search: '',
  expandedIds: new Set(),
  checkedActions: {},
  pollTimer: null
};

const els = {
  rolePresetSelect: document.getElementById('rolePresetSelect'),
  roleTitleInput: document.getElementById('roleTitleInput'),
  roleStackInput: document.getElementById('roleStackInput'),
  applyRoleBtn: document.getElementById('applyRoleBtn'),
  briefingTitle: document.getElementById('briefingTitle'),
  briefingMeta: document.getElementById('briefingMeta'),
  digestNotice: document.getElementById('digestNotice'),
  demoBanner: document.getElementById('demoBanner'),
  demoSnapshotDate: document.getElementById('demoSnapshotDate'),
  executiveSummary: document.getElementById('executiveSummary'),
  kpiAll: document.getElementById('kpiAll'),
  kpiActNow: document.getElementById('kpiActNow'),
  kpiWatch: document.getElementById('kpiWatch'),
  kpiCustomer: document.getElementById('kpiCustomer'),
  kpiBriefLabel: document.getElementById('kpiBriefLabel'),
  kpiNA: document.getElementById('kpiNA'),
  kpiKev: document.getElementById('kpiKev'),
  bucketChips: document.getElementById('bucketChips'),
  incidentList: document.getElementById('incidentList'),
  lockdownList: document.getElementById('lockdownList'),
  checklistProgress: document.getElementById('checklistProgress'),
  rootCauseBars: document.getElementById('rootCauseBars'),
  rootCauseTotal: document.getElementById('rootCauseTotal'),
  ransomTotal: document.getElementById('ransomTotal'),
  ransomGroups: document.getElementById('ransomGroups'),
  ransomRecent: document.getElementById('ransomRecent'),
  searchInput: document.getElementById('searchInput'),
  engineSelect: document.getElementById('engineSelect'),
  refreshBtn: document.getElementById('refreshBtn'),
  exportBtn: document.getElementById('exportBtn'),
  configBtn: document.getElementById('configBtn'),
  jobBanner: document.getElementById('jobBanner'),
  jobLogText: document.getElementById('jobLogText'),
  drawerBackdrop: document.getElementById('drawerBackdrop'),
  configDrawer: document.getElementById('configDrawer'),
  closeDrawerBtn: document.getElementById('closeDrawerBtn'),
  sourceHealthTable: document.getElementById('sourceHealthTable'),
  profileEditor: document.getElementById('profileEditor'),
  saveProfileBtn: document.getElementById('saveProfileBtn'),
  profileSaveStatus: document.getElementById('profileSaveStatus')
};

function esc(str = '') {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Links come from feeds. Only http(s) may become an href.
function safeHref(u) {
  return /^https?:\/\//i.test(String(u || '')) ? String(u) : '#';
}

const BASIS = {
  DISCLOSED: { label: 'stated by source', cls: 'basis-disclosed', tip: 'The source text states this cause. The supporting quote was checked against it.' },
  INFERRED: { label: 'inferred', cls: 'basis-inferred', tip: 'The sources do not state the cause. This is the model reasoning from the pattern.' },
  UNKNOWN: { label: 'not disclosed', cls: 'basis-unknown', tip: 'The cause is not public.' }
};

const COVERAGE = {
  full: { dot: 'dot-ok', label: 'full window' },
  partial: { dot: 'dot-warn', label: 'partial' },
  stale: { dot: 'dot-err', label: 'stale feed' },
  empty: { dot: 'dot-err', label: 'no items' },
  error: { dot: 'dot-err', label: 'error' },
  unconfigured: { dot: 'dot-off', label: 'not configured' },
  disabled: { dot: 'dot-off', label: 'disabled' }
};

function fmtRelative(iso) {
  if (!iso) return '';
  const diffMin = Math.round((Date.now() - Date.parse(iso)) / 60000);
  if (diffMin < 60) return `${Math.max(1, diffMin)}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 48) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}

function briefLabel() {
  return state.digest?.briefLabel || state.profile?.briefLabel || 'Industry Brief';
}

function verdictMeta(v) {
  switch (v) {
    case 'ACT_NOW': return { label: 'ACT NOW', cls: 'badge-red' };
    case 'WATCH_HARDEN': return { label: 'WATCH', cls: 'badge-amber' };
    case 'CUSTOMER_BRIEF': return { label: briefLabel().toUpperCase(), cls: 'badge-cyan' };
    case 'UNANALYZED': return { label: 'NOT ANALYSED', cls: 'badge-muted' };
    default: return { label: 'SKIP', cls: 'badge-muted' };
  }
}

function severityBadge(s) {
  if (s === 'CRITICAL') return 'badge-red';
  if (s === 'HIGH') return 'badge-amber';
  if (s === 'MEDIUM') return 'badge-cyan';
  return 'badge-muted';
}

function actionKey(incidentId, text) {
  return `${incidentId}::${text.slice(0, 64)}`;
}

// Static demo mode: the same dashboard served as plain files with a pre-built snapshot (no server, read-only).
// The build step marks the page with data-static; everything the server would answer comes from snapshot/ files,
// and checklist ticks are kept in this browser only.
const STATIC = Boolean(document.documentElement?.dataset?.static);
const STATIC_FILES = { '/api/presets': 'snapshot/presets.json', '/api/profile': 'snapshot/profile.json' };
const LOCAL_STATE_KEY = 'blastradius-demo-state';

function readLocalState() {
  try { return JSON.parse(localStorage.getItem(LOCAL_STATE_KEY)) || { checkedActions: {} }; } catch { return { checkedActions: {} }; }
}

async function fetchStatic(url, opts) {
  if (url === '/api/state') {
    const current = readLocalState();
    if (opts?.method === 'POST') {
      Object.assign(current.checkedActions, JSON.parse(opts.body).checkedActions || {});
      try { localStorage.setItem(LOCAL_STATE_KEY, JSON.stringify(current)); } catch { /* private browsing: ticks last for this page view */ }
    }
    return current;
  }
  const digest = url.match(/^\/api\/digest\?hours=(\d+)$/);
  const file = digest ? `snapshot/digest-${digest[1]}h.json` : STATIC_FILES[url];
  if (!file) throw new Error('Not available in the read-only demo.');
  const res = await fetch(file);
  if (!res.ok) throw new Error(digest ? 'This demo does not include a snapshot for that window.' : `HTTP ${res.status}`);
  return res.json();
}

async function fetchJson(url, opts) {
  if (STATIC) return fetchStatic(url, opts);
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function loadPresetsAndProfile() {
  try {
    const [{ presets }, profile] = await Promise.all([
      fetchJson('/api/presets'),
      fetchJson('/api/profile')
    ]);
    state.presets = presets || [];
    state.profile = profile;

    const options = [
      ...state.presets.map((p) => `<option value="${esc(p.id)}">${esc(p.roleTitle)}</option>`),
      `<option value="custom">Custom role...</option>`
    ];
    els.rolePresetSelect.innerHTML = options.join('');

    const matched = state.presets.find((p) => p.id === profile.roleId);
    els.rolePresetSelect.value = matched ? matched.id : 'custom';
    els.roleTitleInput.value = profile.roleTitle || profile.role || '';
    els.roleStackInput.value = profile.stackContext || '';
  } catch (err) {
    console.error('Failed loading presets/profile:', err);
  }
}

async function loadState() {
  try {
    const s = await fetchJson('/api/state');
    state.checkedActions = s.checkedActions || {};
  } catch {
    state.checkedActions = {};
  }
}

async function toggleAction(key, checked) {
  state.checkedActions[key] = checked;
  renderLockdownChecklist();
  renderIncidents();
  try {
    await fetchJson('/api/state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ checkedActions: { [key]: checked } })
    });
  } catch (err) {
    console.error('Failed saving checklist state:', err);
  }
}

async function loadDigest(hours = state.hours) {
  state.hours = hours;
  try {
    const digest = await fetchJson(`/api/digest?hours=${hours}`);
    state.digest = digest;
    syncWindowPills();
    renderAll();
  } catch (err) {
    // No digest for this window: say so and stay on the window the user picked. Never show another window's data.
    state.digest = null;
    syncWindowPills();
    const label = hours === 168 ? '7-day' : `${hours}h`;
    els.briefingTitle.textContent = `No ${label} digest yet`;
    els.executiveSummary.textContent = err.message;
    els.briefingMeta.innerHTML = '';
    els.digestNotice.classList.add('hidden');
    for (const el of [els.kpiAll, els.kpiActNow, els.kpiWatch, els.kpiCustomer, els.kpiNA, els.kpiKev]) el.textContent = '—';
    els.bucketChips.innerHTML = '';
    els.lockdownList.innerHTML = '';
    els.checklistProgress.textContent = '0/0';
    els.rootCauseBars.innerHTML = '';
    els.rootCauseTotal.textContent = '';
    els.incidentList.innerHTML = STATIC
      ? `<div class="empty-state">No ${esc(label)} snapshot in this demo. Pick another window.</div>`
      : `<div class="empty-state">Click <strong>Refresh Digest</strong> to build the ${esc(label)} digest.</div>`;
  }
}

function syncWindowPills() {
  document.querySelectorAll('.pill[data-hours]').forEach((btn) => {
    btn.classList.toggle('active', Number(btn.dataset.hours) === Number(state.hours));
  });
}

function renderAll() {
  const d = state.digest;
  if (!d) return;

  const windowLabel = d.hours === 168 ? 'Last 7 Days' : `Last ${d.hours}h`;
  const roleName = d.roleTitle || 'Security Pro';
  els.briefingTitle.textContent = `${windowLabel} · Tailored for ${roleName}`;
  els.executiveSummary.textContent = d.executiveSummary || '';

  const st = d.stats;
  els.briefingMeta.innerHTML = [
    `<span class="meta-chip">${esc(fmtRelative(d.generatedAt))}</span>`,
    `<span class="meta-chip">engine: ${esc(d.analysisEngine)}</span>`,
    `<span class="meta-chip" title="Sources whose feed reaches back to the start of this window">${Number(st.sourcesFullCoverage)}/${Number(st.sourcesEnabled)} sources cover full window</span>`,
    `<span class="meta-chip">${Number(st.rawItemsKept)} items → ${Number(st.clustersTotal)} incidents</span>`,
    `<span class="meta-chip" title="How the root cause is known">cause: ${Number(st.disclosed)} stated · ${Number(st.inferred)} inferred · ${Number(st.unknownCause)} not disclosed</span>`,
    st.newSinceLast ? `<span class="meta-chip chip-new">${Number(st.newSinceLast)} new since last run</span>` : '',
    d.inventory ? `<span class="meta-chip" title="Package manifests scanned on this machine">inventory: ${Number(d.inventory.packages)} packages</span>` : ''
  ].join('');

  // Anything that limits how far this digest can be trusted is said up front, not buried in a drawer.
  const notices = [];
  if (st.unanalyzed) notices.push(`${Number(st.unanalyzed)} of ${Number(st.clustersTotal)} incidents were not analysed${d.fallbackReason ? ` (${d.fallbackReason})` : ''}. They are listed with sources only.`);
  else if (d.fallbackReason) notices.push(d.fallbackReason);
  const gaps = (d.sourceHealth || []).filter((s) => ['partial', 'stale', 'empty', 'error'].includes(s.coverage));
  if (gaps.length) notices.push(`${gaps.length} source${gaps.length === 1 ? '' : 's'} did not cover the whole window (${gaps.slice(0, 4).map((s) => s.name).join(', ')}${gaps.length > 4 ? ', …' : ''}). Open Sources for details.`);
  els.digestNotice.classList.toggle('hidden', !notices.length);
  els.digestNotice.innerHTML = notices.map((n) => `<div>${esc(n)}</div>`).join('');

  els.kpiBriefLabel.textContent = briefLabel();
  els.kpiAll.textContent = d.incidents?.length ?? 0;
  els.kpiActNow.textContent = d.stats.actNow ?? 0;
  els.kpiWatch.textContent = d.stats.watchHarden ?? 0;
  els.kpiCustomer.textContent = d.stats.customerBrief ?? 0;
  els.kpiNA.textContent = d.stats.notApplicable ?? 0;
  els.kpiKev.textContent = d.stats.kevCount ?? 0;

  renderBucketChips();
  renderIncidents();
  renderLockdownChecklist();
  renderRootCauseBars();
  renderRansomware();
  renderSourceHealth();
}

function renderBucketChips() {
  const buckets = state.digest?.rootCauseBreakdown || [];
  const chips = [
    `<button class="chip ${state.bucketFilter === 'ALL' ? 'active' : ''}" data-bucket="ALL">All Root Causes</button>`,
    ...buckets.map(
      (b) => `<button class="chip ${state.bucketFilter === b.bucket ? 'active' : ''}" data-bucket="${esc(b.bucket)}">${esc(b.bucket)} (${b.count})</button>`
    )
  ];
  els.bucketChips.innerHTML = chips.join('');
  els.bucketChips.querySelectorAll('.chip').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.bucketFilter = btn.dataset.bucket;
      renderBucketChips();
      renderIncidents();
    });
  });
}

function getFilteredIncidents() {
  const all = state.digest?.incidents || [];
  const q = state.search.trim().toLowerCase();
  return all.filter((inc) => {
    if (state.verdictFilter === 'KEV_ONLY' && !inc.isKev) return false;
    if (state.verdictFilter !== 'ALL' && state.verdictFilter !== 'KEV_ONLY' && inc.verdict !== state.verdictFilter) {
      return false;
    }
    if (state.bucketFilter !== 'ALL' && inc.rootCauseBucket !== state.bucketFilter) return false;
    if (q) {
      const hay = [
        inc.title,
        inc.rootCauseBucket,
        inc.attackSurface,
        inc.tldrRootCause,
        inc.realisticRootCause,
        inc.couldThisHappenToMe,
        inc.howItCouldHitYou,
        inc.roleAngle,
        inc.customerAngle,
        ...(inc.cves || []),
        ...(inc.lockItDown || []),
        ...(inc.sources || []).map((s) => s.name)
      ].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderIncidents() {
  const list = getFilteredIncidents();
  if (!list.length) {
    els.incidentList.innerHTML = `<div class="empty-state">No incidents match the current filter.</div>`;
    return;
  }

  els.incidentList.innerHTML = list.map((inc) => {
    const vm = verdictMeta(inc.verdict);
    const expanded = state.viewMode === 'detailed' || state.expandedIds.has(inc.id);
    const cveBadges = (inc.cves || []).slice(0, 2).map((c) => `<span class="badge badge-muted">${esc(c)}</span>`).join('');
    const kevBadge = inc.isKev ? `<span class="badge badge-violet">KEV${inc.kevRansomware ? ' · RW' : ''}</span>` : '';
    const happenedLine = inc.tldrRootCause || (inc.realisticRootCause || '').split(/(?<=[.!?])\s+/)[0] || '';
    const actions = (inc.lockItDown || []).filter((a) => a && !/^(none|no personal action|n\/a)\.?$/i.test(a.trim()));

    const inlineActionsHtml = (inc.verdict === 'ACT_NOW' || inc.verdict === 'WATCH_HARDEN') && actions.length
      ? `<div class="tldr-row">
           <span class="tldr-k">Do</span>
           <div class="inline-do">
             ${actions.map((act) => {
               const k = actionKey(inc.id, act);
               const checked = Boolean(state.checkedActions[k]);
               return `<label class="action-item ${checked ? 'checked' : ''}">
                 <input type="checkbox" data-action-key="${esc(k)}" ${checked ? 'checked' : ''} />
                 <span>${esc(act)}</span>
               </label>`;
             }).join('')}
           </div>
         </div>`
      : '';

    const sourcesHtml = (inc.sources || []).map((s) => `
      <a class="source-link" href="${esc(safeHref(s.url))}" target="_blank" rel="noopener noreferrer">
        <span class="mono-dim">T${Number(s.tier)}</span>
        <span>${esc(s.name)}</span>
      </a>`).join('');

    const angleText = inc.roleAngle || inc.customerAngle || '';
    const newBadge = inc.isNew ? `<span class="badge badge-green">NEW</span>` : '';
    const srcCount = `${Number(inc.corroborationCount)} independent source${inc.corroborationCount === 1 ? '' : 's'}`;

    // Not analysed: show what we have (headline and sources) and nothing we do not.
    if (inc.verdict === 'UNANALYZED') {
      return `
      <article class="incident-card verdict-UNANALYZED" data-id="${esc(inc.id)}">
        <div class="inc-top">
          <div class="badges"><span class="badge ${vm.cls}">${esc(vm.label)}</span>${kevBadge}${cveBadges}${newBadge}</div>
          <span class="mono-dim">${esc(srcCount)} · ${esc(fmtRelative(inc.latestAt))}</span>
        </div>
        <h3 class="inc-title">${esc(inc.title)}</h3>
        <div class="sources-row">${sourcesHtml}</div>
      </article>`;
    }

    const basis = BASIS[inc.rootCauseBasis] || BASIS.INFERRED;
    const inv = inc.inventory?.checked
      ? `<div class="tldr-row">
           <span class="tldr-k">Inventory</span>
           <span class="${inc.inventory.matches.length ? 'inv-hit' : 'inv-miss'}">${inc.inventory.matches.length
             ? `Found on this machine: ${esc(inc.inventory.matches.join(', '))}`
             : `Not found in ${esc(inc.inventory.basis || 'your inventory')}`}</span>
         </div>`
      : '';

    return `
      <article class="incident-card verdict-${esc(inc.verdict)}" data-id="${esc(inc.id)}">
        <div class="inc-top">
          <div class="badges">
            <span class="badge ${vm.cls}">${esc(vm.label)}</span>
            <span class="badge ${severityBadge(inc.severity)}">${esc(inc.severity)}</span>
            ${kevBadge}
            <span class="badge badge-muted">${esc(inc.rootCauseBucket)}</span>
            ${cveBadges}
            ${newBadge}
          </div>
          <span class="mono-dim">${esc(srcCount)} · ${esc(fmtRelative(inc.latestAt))}</span>
        </div>

        <h3 class="inc-title">${esc(inc.title)}</h3>

        <div class="tldr-lines">
          <div class="tldr-row">
            <span class="tldr-k">Happened</span>
            <span class="tldr-happened">${esc(happenedLine)} <span class="basis ${basis.cls}" title="${esc(basis.tip)}">${esc(basis.label)}</span></span>
          </div>
          <div class="tldr-row tldr-row-me">
            <span class="tldr-k">Hit me?</span>
            <span class="tldr-me">${esc(inc.couldThisHappenToMe)}</span>
          </div>
          ${inv}
          ${inlineActionsHtml}
        </div>

        <div class="inc-meta-row">
          <span><strong>Surface:</strong> ${esc(inc.attackSurface)}</span>
          <button class="expand-btn" data-toggle-id="${esc(inc.id)}">${expanded ? 'Less ▲' : 'Details & Sources ▾'}</button>
        </div>

        <div class="inc-details ${expanded ? '' : 'hidden'}">
          ${inc.evidenceQuote ? `
          <div class="detail-block">
            <h4>What the source says</h4>
            <p class="evidence-quote">“${esc(inc.evidenceQuote)}”</p>
          </div>` : ''}
          ${(inc.validationNotes || []).length ? `
          <div class="detail-block">
            <h4>Automatic corrections</h4>
            <p>${esc(inc.validationNotes.join('; '))}</p>
          </div>` : ''}
          ${inc.realisticRootCause && inc.realisticRootCause !== happenedLine ? `
          <div class="detail-block">
            <h4>Full Root Cause</h4>
            <p>${esc(inc.realisticRootCause)}</p>
          </div>` : ''}
          ${inc.howItCouldHitYou ? `
          <div class="detail-block">
            <h4>Exposure Path</h4>
            <p>${esc(inc.howItCouldHitYou)}</p>
          </div>` : ''}
          ${angleText ? `
          <div class="detail-block">
            <h4>${esc(briefLabel())} Angle</h4>
            <p>${esc(angleText)}</p>
          </div>` : ''}
          <div class="detail-block">
            <h4>Primary Sources (${inc.corroborationCount})</h4>
            <div class="sources-row">${sourcesHtml}</div>
          </div>
        </div>
      </article>`;
  }).join('');

  els.incidentList.querySelectorAll('[data-toggle-id]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.toggleId;
      const card = btn.closest('.incident-card');
      const details = card.querySelector('.inc-details');
      const isHidden = details.classList.toggle('hidden');
      if (isHidden) {
        state.expandedIds.delete(id);
        btn.textContent = 'Details & Sources ▾';
      } else {
        state.expandedIds.add(id);
        btn.textContent = 'Less ▲';
      }
    });
  });

  els.incidentList.querySelectorAll('input[data-action-key]').forEach((cb) => {
    cb.addEventListener('change', (e) => toggleAction(cb.dataset.actionKey, e.target.checked));
  });
}

function renderLockdownChecklist() {
  const items = state.digest?.topLockdownChecklist || [];
  if (!items.length) {
    els.checklistProgress.textContent = '0/0';
    els.lockdownList.innerHTML = `<div class="mono-dim">Nothing urgent to lock down in this window.</div>`;
    return;
  }

  let done = 0;
  const html = items.map((item) => {
    const k = actionKey(item.incidentId, item.action);
    const checked = Boolean(state.checkedActions[k]);
    if (checked) done++;
    return `
      <label class="lockdown-row ${checked ? 'checked' : ''}">
        <input type="checkbox" data-action-key="${esc(k)}" ${checked ? 'checked' : ''} />
        <div>
          <div class="lockdown-text">${esc(item.action)}</div>
          <span class="lockdown-src">${item.verdict === 'ACT_NOW' ? '🔴' : '🟠'} ${esc(item.incidentTitle.slice(0, 68))}</span>
        </div>
      </label>`;
  }).join('');

  els.checklistProgress.textContent = `${done}/${items.length} done`;
  els.lockdownList.innerHTML = html;
  els.lockdownList.querySelectorAll('input[data-action-key]').forEach((cb) => {
    cb.addEventListener('change', (e) => toggleAction(cb.dataset.actionKey, e.target.checked));
  });
}

function renderRootCauseBars() {
  const rows = state.digest?.rootCauseBreakdown || [];
  const max = Math.max(1, ...rows.map((r) => r.count));
  const total = rows.reduce((a, b) => a + b.count, 0);
  els.rootCauseTotal.textContent = `${total} total`;

  els.rootCauseBars.innerHTML = rows.map((r) => `
    <div class="bar-row">
      <div class="bar-labels">
        <span>${esc(r.bucket)}</span>
        <span class="mono-dim">${r.count}</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${Math.round((r.count / max) * 100)}%"></div>
      </div>
    </div>`).join('');
}

function renderRansomware() {
  const rw = state.digest?.ransomware;
  if (!rw) return;
  els.ransomTotal.textContent = `${rw.totalVictims || 0}${rw.capped ? '+' : ''} victims`;
  els.ransomTotal.title = rw.capped ? 'The feed only returns the most recent posts, so this window is not fully counted yet.' : '';
  els.ransomGroups.innerHTML = (rw.topGroups || []).slice(0, 8)
    .map((g) => `<span class="badge badge-muted">${esc(g.group)} · ${g.count}</span>`)
    .join('');

  els.ransomRecent.innerHTML = (rw.recent || []).slice(0, 12).map((v) => `
    <div class="ransom-item">
      <div>
        <strong>${esc(v.victim)}</strong>
        <div class="mono-dim">${esc(v.sector)} · ${esc(v.country)}</div>
      </div>
      <span class="badge badge-red">${esc(v.group)}</span>
    </div>`).join('');
}

function renderSourceHealth() {
  const sources = state.digest?.sourceHealth || [];
  els.sourceHealthTable.innerHTML = sources.map((s) => {
    const cov = COVERAGE[s.coverage] || COVERAGE.error;
    const counts = s.status === 'ok' ? `${Number(s.inStoreWindowCount ?? s.keptCount)} in window` : '';
    return `
      <div class="source-row">
        <div>
          <span class="dot ${cov.dot}"></span>
          <strong>${esc(s.name)}</strong>
          <span class="mono-dim"> · T${Number(s.tier)} · ${esc(s.category)}</span>
          ${s.coverageNote ? `<div class="source-note">${esc(s.coverageNote)}</div>` : ''}
        </div>
        <span class="mono-dim">${esc(cov.label)}${counts ? ` · ${esc(counts)}` : ''}</span>
      </div>`;
  }).join('');
}

function getSelectedRolePayload() {
  const presetId = els.rolePresetSelect.value;
  const preset = state.presets.find((p) => p.id === presetId);
  return {
    roleId: presetId,
    roleTitle: els.roleTitleInput.value.trim() || preset?.roleTitle || 'Cybersecurity Professional',
    stackContext: els.roleStackInput.value.trim(),
    briefLabel: preset?.briefLabel || 'Industry Brief'
  };
}

async function triggerRefresh() {
  els.refreshBtn.disabled = true;
  els.applyRoleBtn.disabled = true;
  els.jobBanner.classList.remove('hidden');
  const rolePayload = getSelectedRolePayload();
  els.jobLogText.textContent = `Refreshing ${state.hours}h digest for "${rolePayload.roleTitle}"...`;

  try {
    await fetchJson('/api/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hours: state.hours,
        engine: els.engineSelect.value,
        ...rolePayload
      })
    });
    pollRefreshStatus();
  } catch (err) {
    els.jobLogText.textContent = `Refresh error: ${err.message}`;
    els.refreshBtn.disabled = false;
    els.applyRoleBtn.disabled = false;
  }
}

function pollRefreshStatus() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    try {
      const { activeJob } = await fetchJson('/api/status');
      if (!activeJob) return;
      const lastLog = activeJob.logs?.[activeJob.logs.length - 1] || 'Working...';
      els.jobLogText.textContent = lastLog;
      if (!activeJob.running) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        els.refreshBtn.disabled = false;
        els.applyRoleBtn.disabled = false;
        if (!activeJob.error) {
          await loadPresetsAndProfile();
          await loadDigest(state.hours);
          setTimeout(() => els.jobBanner.classList.add('hidden'), 1500);
        }
      }
    } catch {
      clearInterval(state.pollTimer);
      els.refreshBtn.disabled = false;
      els.applyRoleBtn.disabled = false;
    }
  }, 1500);
}

async function openDrawer() {
  els.drawerBackdrop.classList.remove('hidden');
  els.configDrawer.classList.remove('hidden');
  try {
    const profile = await fetchJson('/api/profile');
    els.profileEditor.value = JSON.stringify(profile, null, 2);
  } catch (err) {
    els.profileEditor.value = `// Failed to load profile: ${err.message}`;
  }
}

function closeDrawer() {
  els.drawerBackdrop.classList.add('hidden');
  els.configDrawer.classList.add('hidden');
}

// Wire events
els.rolePresetSelect.addEventListener('change', () => {
  const preset = state.presets.find((p) => p.id === els.rolePresetSelect.value);
  if (preset) {
    els.roleTitleInput.value = preset.roleTitle;
    els.roleStackInput.value = preset.stackContext;
  }
});

els.roleTitleInput.addEventListener('input', () => {
  const match = state.presets.find((p) => p.roleTitle === els.roleTitleInput.value.trim());
  els.rolePresetSelect.value = match ? match.id : 'custom';
});

els.applyRoleBtn.addEventListener('click', triggerRefresh);
els.refreshBtn.addEventListener('click', triggerRefresh);

document.querySelectorAll('.pill[data-hours]').forEach((btn) => {
  btn.addEventListener('click', () => {
    state.hours = Number(btn.dataset.hours);
    syncWindowPills();
    loadDigest(state.hours);
  });
});

document.querySelectorAll('.pill[data-view]').forEach((btn) => {
  btn.addEventListener('click', () => {
    state.viewMode = btn.dataset.view;
    document.querySelectorAll('.pill[data-view]').forEach((b) => b.classList.toggle('active', b === btn));
    renderIncidents();
  });
});

document.querySelectorAll('.kpi[data-verdict]').forEach((btn) => {
  btn.addEventListener('click', () => {
    state.verdictFilter = btn.dataset.verdict;
    document.querySelectorAll('.kpi[data-verdict]').forEach((k) => k.classList.remove('active-filter'));
    btn.classList.add('active-filter');
    renderIncidents();
  });
});

els.searchInput.addEventListener('input', (e) => {
  state.search = e.target.value;
  renderIncidents();
});

els.exportBtn.addEventListener('click', () => {
  window.location.href = STATIC ? `snapshot/digest-${Number(state.hours)}h.md` : `/api/export/markdown?hours=${state.hours}`;
});
els.configBtn.addEventListener('click', openDrawer);
els.closeDrawerBtn.addEventListener('click', closeDrawer);
els.drawerBackdrop.addEventListener('click', closeDrawer);

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('sourcesTab').classList.toggle('hidden', btn.dataset.tab !== 'sourcesTab');
    document.getElementById('profileTab').classList.toggle('hidden', btn.dataset.tab !== 'profileTab');
  });
});

els.saveProfileBtn.addEventListener('click', async () => {
  try {
    const parsed = JSON.parse(els.profileEditor.value);
    await fetchJson('/api/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(parsed)
    });
    await loadPresetsAndProfile();
    els.profileSaveStatus.textContent = 'Saved to data/profile.local.json! Click Refresh Digest to apply.';
  } catch (err) {
    els.profileSaveStatus.textContent = `Invalid JSON: ${err.message}`;
  }
});

// Boot
await Promise.all([loadPresetsAndProfile(), loadState()]);
await loadDigest(168);

if (STATIC) {
  // Read-only: nothing here can start a run or change a profile.
  for (const el of [els.refreshBtn, els.applyRoleBtn, els.rolePresetSelect, els.roleTitleInput, els.roleStackInput, els.engineSelect, els.saveProfileBtn, els.profileEditor]) {
    el.disabled = true;
    el.title = 'Disabled in the read-only demo. Run BlastRadius locally to use this.';
  }
  els.demoSnapshotDate.textContent = state.digest ? new Date(state.digest.generatedAt).toISOString().slice(0, 10) : 'unknown date';
  els.demoBanner.classList.remove('hidden');
}
