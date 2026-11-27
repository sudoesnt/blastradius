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
    .replace(/"/g, '&quot;');
}

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

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json();
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
  try {
    const digest = await fetchJson(`/api/digest?hours=${hours}`);
    state.digest = digest;
    state.hours = digest.hours || hours;
    syncWindowPills();
    renderAll();
  } catch (err) {
    els.briefingTitle.textContent = 'No digest generated yet';
    els.executiveSummary.textContent = err.message;
    els.incidentList.innerHTML = `<div class="empty-state">Pick your role above and click <strong>Refresh Digest</strong> to build your threat TL;DR.</div>`;
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
  const roleName = d.roleTitle || d.persona || 'Security Pro';
  els.briefingTitle.textContent = `${windowLabel} · Tailored for ${roleName}`;
  els.executiveSummary.textContent = d.executiveSummary || '';

  els.briefingMeta.innerHTML = [
    `<span class="meta-chip">${esc(fmtRelative(d.generatedAt))}</span>`,
    `<span class="meta-chip">${esc(d.analysisEngine)}</span>`,
    `<span class="meta-chip">${d.stats.sourcesOk}/${d.stats.sourcesTotal} feeds live</span>`,
    `<span class="meta-chip">${d.stats.rawItemsKept} signals → ${d.stats.incidentsAnalyzed} items</span>`
  ].join('');

  els.kpiBriefLabel.textContent = briefLabel();
  els.kpiAll.textContent = d.stats.incidentsAnalyzed ?? 0;
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
      <a class="source-link" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">
        <span class="mono-dim">T${s.tier}</span>
        <span>${esc(s.name)}</span>
      </a>`).join('');

    const angleText = inc.roleAngle || inc.customerAngle || '';

    return `
      <article class="incident-card verdict-${esc(inc.verdict)}" data-id="${esc(inc.id)}">
        <div class="inc-top">
          <div class="badges">
            <span class="badge ${vm.cls}">${esc(vm.label)}</span>
            <span class="badge ${severityBadge(inc.severity)}">${esc(inc.severity)}</span>
            ${kevBadge}
            <span class="badge badge-muted">${esc(inc.rootCauseBucket)}</span>
            ${cveBadges}
          </div>
          <span class="mono-dim">${inc.corroborationCount} src · ${esc(fmtRelative(inc.latestAt))}</span>
        </div>

        <h3 class="inc-title">${esc(inc.title)}</h3>

        <div class="tldr-lines">
          <div class="tldr-row">
            <span class="tldr-k">Happened</span>
            <span class="tldr-happened">${esc(happenedLine)}</span>
          </div>
          <div class="tldr-row tldr-row-me">
            <span class="tldr-k">Hit me?</span>
            <span class="tldr-me">${esc(inc.couldThisHappenToMe)}</span>
          </div>
          ${inlineActionsHtml}
        </div>

        <div class="inc-meta-row">
          <span><strong>Surface:</strong> ${esc(inc.attackSurface)}</span>
          <button class="expand-btn" data-toggle-id="${esc(inc.id)}">${expanded ? 'Less ▲' : 'Details & Sources ▾'}</button>
        </div>

        <div class="inc-details ${expanded ? '' : 'hidden'}">
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
  els.ransomTotal.textContent = `${rw.totalVictims || 0} victims`;
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
    const dotCls = s.status === 'ok' ? 'dot-ok' : (s.status === 'unconfigured' || s.status === 'disabled' ? 'dot-warn' : 'dot-err');
    const detail = s.status === 'ok' ? `${s.keptCount} kept (${s.durationMs}ms)` : (s.error || s.status);
    return `
      <div class="source-row">
        <div>
          <span class="dot ${dotCls}"></span>
          <strong>${esc(s.name)}</strong>
          <span class="mono-dim"> · T${s.tier} · ${esc(s.category)}</span>
        </div>
        <span class="mono-dim">${esc(detail)}</span>
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
  window.location.href = `/api/export/markdown?hours=${state.hours}`;
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
