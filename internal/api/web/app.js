// Policy Console UI. No build step: plain ES modules served from the binary.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const state = {
  status: null, tenants: [], tenant: null, templates: [],
  tokens: JSON.parse(localStorage.getItem('pc.tokens') || '{}'),
  caState: localStorage.getItem('pc.caState') || 'enabledForReportingButNotEnforced',
  rollout: localStorage.getItem('pc.rollout') || 'pilot',
  pilotGroup: localStorage.getItem('pc.pilotGroup') || '',
  comparison: null, score: null, objects: [], selected: new Set(), benchmarks: null, secureNote: '',
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (res.status === 401) {
    location.href = '/auth/login?returnTo=' + encodeURIComponent(location.pathname);
    throw new Error('session expired, signing in again');
  }
  if (!res.ok) {
    const err = new Error(data?.error || `${res.status} ${res.statusText}`);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

function toast(msg, bad = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('bad', bad);
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 6000);
}

// confirm gate: every write passes through here with the exact consequence spelled out
function confirmAction(title, bodyHTML, okLabel = 'CONFIRM') {
  return new Promise(resolve => {
    $('#modalTitle').textContent = title;
    $('#modalBody').innerHTML = bodyHTML;
    $('#modalOk').textContent = okLabel;
    $('#modal').hidden = false;
    const done = (v) => { $('#modal').hidden = true; $('#modalOk').onclick = null; $('#modalCancel').onclick = null; resolve(v); };
    $('#modalOk').onclick = () => done(true);
    $('#modalCancel').onclick = () => done(false);
  });
}

const tenantId = () => state.tenant?.id;
function requireTenant() {
  if (!tenantId()) { toast('Pick a tenant first', true); return false; }
  return true;
}

// ---------- shell ----------

function showTab(name) {
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === name));
  $$('.tab').forEach(t => t.classList.toggle('on', t.id === 'tab-' + name));
  render(name);
}
$$('.tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));

$('#tenantPicker').onchange = (e) => {
  state.tenant = state.tenants.find(t => t.id === e.target.value) || null;
  localStorage.setItem('pc.tenant', e.target.value);
  state.comparison = state.score = null;
  render(currentTab());
};

const currentTab = () => $$('.tabs button').find(b => b.classList.contains('on'))?.dataset.tab;

async function boot() {
  state.status = await api('/api/status');
  state.templates = await api('/api/templates');
  try { state.benchmarks = await api('/api/benchmarks'); } catch { state.benchmarks = null; }
  await loadTenants();
  const badge = $('#modeBadge');
  badge.textContent = state.status.readOnly ? 'READ-ONLY' : 'WRITE ENABLED';
  badge.className = 'badge ' + (state.status.readOnly ? 'ro' : 'live');
  const who = state.status.user?.upn || state.status.user?.name || 'not signed in';
  $('#statusLine').textContent =
    `${state.status.templates} templates · snapshots every ${state.status.snapshotEvery} · ${state.status.credentialsSet ? 'app credentials set' : 'NO APP CREDENTIALS'} · ${who}`;
  const signIn = $('#signIn');
  if (state.status.signInActive) {
    signIn.innerHTML = `<a href="/auth/logout" class="dim">SIGN OUT</a>`;
  } else {
    signIn.innerHTML = `<span class="badge ro" title="${esc(state.status.signInReason || '')}">SIGN-IN OFF</span>`;
  }
  render('tenants');
}

async function loadTenants() {
  state.tenants = await api('/api/tenants');
  const sel = $('#tenantPicker');
  const want = state.tenant?.id || localStorage.getItem('pc.tenant') || '';
  sel.innerHTML = '<option value="">Pick a client</option>' +
    state.tenants.map(t => `<option value="${esc(t.id)}">${esc(t.name)} (${t.status})</option>`).join('');
  sel.value = state.tenants.some(t => t.id === want) ? want : '';
  state.tenant = state.tenants.find(t => t.id === sel.value) || null;
}

function render(tab) {
  ({ tenants: renderTenants, baseline: renderBaseline, compare: renderCompare,
     deploy: renderDeploy, history: renderHistory, runs: renderRuns, settings: renderSettings,
     fleet: renderFleet, drift: renderDrift, impact: renderImpact, consent: renderConsent, assess: renderAssess,
     buildout: renderBuildout, profile: renderProfile, rollouts: renderRollouts, reports: renderReports })[tab]?.();
}

// ---------- tenants ----------

function renderTenants() {
  const el = $('#tab-tenants');
  el.innerHTML = `
    <h2>TENANTS</h2>
    ${state.status.credentialsSet ? '' : `<div class="note bad">No app registration configured. Set PC_CLIENT_ID and PC_CLIENT_SECRET, then restart. Until then nothing can reach a tenant.</div>`}
    <p class="dim">A tenant becomes reachable once its admin has granted consent to your app registration. Add it here, then press CHECK to confirm consent landed.</p>
    <div class="row">
      <input id="newTenantId" placeholder="tenant id or domain" size="40">
      <input id="newTenantName" placeholder="client name (optional)" size="26">
      <button class="act" id="addTenant">ADD</button>
      <button class="ghost" id="consentLink">CONSENT LINK</button>
    </div>
    <table><thead><tr><th>Client</th><th>Tenant</th><th>Status</th><th>Last seen</th><th></th></tr></thead><tbody>
    ${state.tenants.map(t => `<tr>
      <td>${esc(t.name)}</td>
      <td class="mono-sm">${esc(t.id)}</td>
      <td><span class="chip ${t.status === 'connected' ? 'c-ok' : t.status === 'unreachable' ? 'c-bad' : 'c-warn'}">${esc(t.status)}</span></td>
      <td class="dim">${esc(t.lastSeenAt || 'never')}</td>
      <td class="row" style="margin:0">
        <button class="ghost" data-probe="${esc(t.id)}">CHECK</button>
        <button class="ghost" data-snap="${esc(t.id)}">SNAPSHOT</button>
        <button class="ghost" data-rm="${esc(t.id)}">REMOVE</button>
      </td></tr>`).join('') || '<tr><td colspan="5" class="dim">No tenants yet.</td></tr>'}
    </tbody></table>`;

  $('#addTenant').onclick = async () => {
    const id = $('#newTenantId').value.trim();
    if (!id) return toast('Tenant id or domain required', true);
    await api('/api/tenants', { method: 'POST', body: JSON.stringify({ id, name: $('#newTenantName').value.trim() || id }) });
    await loadTenants(); renderTenants(); toast('Tenant added');
  };
  $('#consentLink').onclick = () => {
    const cid = state.status.clientId;
    if (!cid) return toast('No client id configured', true);
    const url = `https://login.microsoftonline.com/common/adminconsent?client_id=${encodeURIComponent(cid)}`;
    navigator.clipboard?.writeText(url);
    toast('Consent link copied. Send it to the client admin.');
  };
  $$('[data-probe]', el).forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { const t = await api(`/api/tenants/${encodeURIComponent(b.dataset.probe)}/probe`, { method: 'POST' });
      toast(`Connected to ${t.name}`); } catch (e) { toast(e.message, true); }
    await loadTenants(); renderTenants();
  });
  $$('[data-snap]', el).forEach(b => b.onclick = async () => {
    b.disabled = true; toast('Snapshotting...');
    try { const r = await api(`/api/tenants/${encodeURIComponent(b.dataset.snap)}/snapshot`, { method: 'POST' });
      toast(`${r.captured} objects read, ${r.changed} new versions stored`); } catch (e) { toast(e.message, true); }
    await loadTenants(); renderTenants();
  });
  $$('[data-rm]', el).forEach(b => b.onclick = async () => {
    if (!await confirmAction('Remove tenant from console',
      `<p>This removes <b>${esc(b.dataset.rm)}</b> and its stored history from this console.</p>
       <p class="note">Nothing in the client tenant is changed or deleted. Policies stay exactly as they are.</p>`, 'REMOVE')) return;
    await api(`/api/tenants/${encodeURIComponent(b.dataset.rm)}`, { method: 'DELETE' });
    await loadTenants(); renderTenants(); toast('Removed');
  });
}

// ---------- baseline ----------

function renderBaseline() {
  const el = $('#tab-baseline');
  const byCat = {};
  state.templates.filter(t => t.category !== 'microsoft' && t.category !== 'praxis').forEach(t => (byCat[t.category] ||= []).push(t));
  const flagged = state.templates.filter(t => (t.warnings || []).length);
  el.innerHTML = `<h2>HOUSE BASELINE — ${state.templates.filter(t => t.category !== 'microsoft' && t.category !== 'praxis').length} TEMPLATES</h2>
    <p class="dim">The client-neutral policy set shipped inside this binary. Placeholders are filled at deploy time.</p>
    ${flagged.length ? `<div class="note bad">${flagged.length} template${flagged.length > 1 ? 's do' : ' does'} not do what ${flagged.length > 1 ? 'their names say' : 'its name says'}: ${flagged.map(t => esc(t.code || t.name)).join(', ')}. Details below.</div>` : ''}
    ${Object.entries(byCat).map(([cat, list]) => `
      <h3>${esc(cat)} (${list.length})</h3>
      <table><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Needs</th><th></th></tr></thead><tbody>
      ${list.map(t => `<tr>
        <td>${esc(t.code || '')}</td>
        <td>${esc(t.name)}${t.does ? `<div class="mono-sm">does: ${esc(t.does)}</div>` : ''}
          ${(t.warnings || []).map(w => `<div class="c-bad mono-sm">\u26a0 ${esc(w)}</div>`).join('')}</td>
        <td class="dim">${esc(t.kind)}</td>
        <td class="mono-sm">${t.placeholders?.length ? t.placeholders.map(p => `<span class="chip c-warn">${esc(p)}</span>`).join(' ') : '<span class="dim">nothing</span>'}</td>
        <td><button class="ghost" data-view="${esc(t.id)}">VIEW</button></td></tr>`).join('')}
      </tbody></table>`).join('')}`;
  el.insertAdjacentHTML('afterbegin', `<div id="praxisBlock"></div>`);
  Promise.all([api('/api/praxis/provenance'), api('/api/whatif').catch(() => null)])
    .then(([p, w]) => { $('#praxisBlock').innerHTML = praxisBlock(p, w); })
    .catch(e => { $('#praxisBlock').innerHTML = `<div class="note">${esc(e.message)}</div>`; });
  el.insertAdjacentHTML('beforeend', `<div id="msCAAudit"></div><div id="msTplAudit"><p class="dim">Loading comparison with Microsoft's baselines...</p></div>`);
  el.insertAdjacentHTML('beforeend', `<div id="tplOverlaps"></div>`);
  api('/api/templates-overlaps').then(r => { $('#tplOverlaps').innerHTML = overlapBlock(r); }).catch(() => {});
  api('/api/mstemplates/compare')
    .then(r => { $('#msCAAudit').innerHTML = msCABlock(r, '', 'templates'); })
    .catch(e => { $('#msCAAudit').innerHTML = `<h3>MICROSOFT CONDITIONAL ACCESS TEMPLATES</h3><div class="note">${esc(e.message)}</div>`; });
  api('/api/baselines/templates')
    .then(r => { $('#msTplAudit').innerHTML = msBaselineBlock(r, '', 'templates'); })
    .catch(e => { $('#msTplAudit').innerHTML = `<h3>MICROSOFT SECURITY BASELINES</h3><div class="note">${esc(e.message)}</div>`; });
  $$('[data-view]', el).forEach(b => b.onclick = async () => {
    const d = await api('/api/templates/' + encodeURIComponent(b.dataset.view));
    await confirmAction(d.template.name, `<pre>${esc(JSON.stringify(d.body, null, 2))}</pre>`, 'CLOSE');
  });
}

// ---------- compare and score ----------

function renderCompare() {
  const el = $('#tab-compare');
  el.innerHTML = `<h2>COMPARE &amp; SCORE</h2>
    ${tenantId() ? '' : '<div class="note">Pick a tenant in the top bar.</div>'}
    <div class="row">
      <button class="act" id="runCompare" ${tenantId() ? '' : 'disabled'}>COMPARE TENANT TO BASELINE</button>
      <span class="dim">Read-only. Nothing is changed.</span>
    </div>
    <div id="cmpOut"></div>`;
  el.onclick = async (ev) => {
    const en = ev.target.closest('[data-enforce]');
    const wi = ev.target.closest('[data-widen]');
    if (en) {
      const row = (state.reportOnly?.policies || []).find(p => p.objectId === en.dataset.enforce);
      const early = row && !row.ready;
      let override = '';
      if (early) {
        override = prompt(`${row.name} has been report-only for ${row.hours.toFixed(1)} hours; the minimum is ${state.reportOnly.minimumHours}. Type a reason to enforce early, or cancel.`) || '';
        if (!override.trim()) return;
      }
      if (!await confirmAction('Enforce a Conditional Access policy',
        `<p>This switches <b>${esc(row?.name || en.dataset.enforce)}</b> from report-only to <b>on</b> in <b>${esc(state.tenant.name)}</b>. Users it targets are affected immediately.</p>
         <p>The current state is snapshotted first, so this can be reverted from HISTORY.</p>`, 'ENFORCE')) return;
      try {
        const r = await api(`/api/tenants/${encodeURIComponent(tenantId())}/enforce`, { method: 'POST', body: JSON.stringify({ objectId: en.dataset.enforce, override }) });
        toast(`Enforced after ${r.reportOnlyHours.toFixed(1)} hours in report-only`);
      } catch (e) { toast(e.message, true); }
    }
    if (wi) {
      const [kind, objectId] = wi.dataset.widen.split('|');
      if (!state.pilotGroup) return toast('Set the pilot group id on DEPLOY first', true);
      if (!await confirmAction('Widen from pilot to everyone',
        `<p>This removes the pilot group and applies the policy to everyone in <b>${esc(state.tenant.name)}</b>.</p><p>The current state is snapshotted first.</p>`, 'WIDEN')) return;
      try {
        await api(`/api/tenants/${encodeURIComponent(tenantId())}/widen`, { method: 'POST', body: JSON.stringify({ kind, objectId, pilotGroupId: state.pilotGroup }) });
        toast('Widened to everyone');
      } catch (e) { toast(e.message, true); }
    }
  };
  $('#runCompare').onclick = async () => {
    toast('Reading tenant...');
    try {
      const r = await api(`/api/tenants/${encodeURIComponent(tenantId())}/score`,
        { method: 'POST', body: JSON.stringify({ tokens: state.tokens, state: state.caState }) });
      state.comparison = r.comparison; state.score = r.score; state.secureNote = r.secureScoreNote || '';
      state.msBaselines = r.microsoftBaselines || []; state.msNote = r.microsoftNote || '';
      state.msCA = r.microsoftCA || []; state.msCANote = r.microsoftCANote || '';
      state.overlaps = r.overlaps || [];
      try { state.reportOnly = await api(`/api/tenants/${encodeURIComponent(tenantId())}/report-only`); } catch { state.reportOnly = null; }
      drawCompare();
      toast('Comparison complete');
    } catch (e) { toast(e.message, true); }
  };
  if (state.comparison) drawCompare();
}

function drawCompare() {
  const s = state.score, c = state.comparison;
  const chip = (st) => ({ matches: 'c-ok', drifted: 'c-warn', equivalent: 'c-info', missing: 'c-dim', error: 'c-bad' })[st] || 'c-dim';
  const stateWord = (it) => it.state === 'equivalent' ? (it.exact ? 'equivalent' : 'covered, broader') : it.state;
  $('#cmpOut').innerHTML = `
    <div class="kpis" style="margin-top:14px">
      <div class="kpi"><b>${s.overall}</b><span>overall</span></div>
      <div class="kpi"><b>${s.coverage}%</b><span>deployed</span></div>
      <div class="kpi"><b>${s.enforcement}%</b><span>enforced</span></div>
      <div class="kpi"><b>${s.fidelity}</b><span>fidelity</span></div>
    </div>
    <div class="note ${s.coverage === 100 && s.enforcement === 100 ? 'ok' : ''}">${esc(s.headline)}</div>

    <h3>BY CATEGORY</h3>
    <table><thead><tr><th>Category</th><th>Deployed</th><th>Enforced</th><th>Drifted</th><th>Missing</th></tr></thead><tbody>
    ${s.categories.map(x => `<tr><td>${esc(x.category)}</td><td>${x.deployed}/${x.total}</td><td>${x.enforced}</td>
      <td class="${x.drifted ? 'c-warn' : 'dim'}">${x.drifted}</td><td class="${x.missing ? 'c-dim' : 'dim'}">${x.missing}</td></tr>`).join('')}
    </tbody></table>

    ${secureScoreBlock(s.secureScore)}
    ${reportOnlyBlock(state.reportOnly)}
    ${overlapBlock(state.overlaps)}
    ${msCABlock(state.msCA, state.msCANote, 'tenant')}
    ${msBaselineBlock(state.msBaselines, state.msNote, 'tenant')}
    ${frameworksBlock(s.frameworks)}

    <h3>TEMPLATE BY TEMPLATE</h3>
    <table><thead><tr><th>Status</th><th>Name</th><th>Live state</th><th>Differences</th></tr></thead><tbody>
    ${c.items.map(it => `<tr>
      <td><span class="chip ${chip(it.state)}">${esc(stateWord(it))}</span></td>
      <td>${esc(it.template.name)}
        ${it.coveredBy ? `<div class="c-info mono-sm">\u21b3 done by \u201c${esc(it.coveredBy)}\u201d</div>` : ''}
        ${it.note ? `<div class="mono-sm">${esc(it.note)}</div>` : ''}</td>
      <td class="dim">${esc(it.liveState || '')}</td>
      <td>${it.changeCount ? `<details><summary>${it.changeCount} differences</summary>${diffTable(it.changes)}</details>` : '<span class="dim">—</span>'}</td>
    </tr>`).join('')}
    </tbody></table>

    ${c.items.some(i => i.state === 'equivalent') ? `<div class="note">${c.items.filter(i => i.state === 'equivalent').length} templates are already done by this tenant's own policies under different names. They count as deployed. Deploying the template as well would create a duplicate.</div>` : ''}
    ${c.unmanaged?.length ? `<h3>IN THE TENANT, NOT MATCHING ANY TEMPLATE (${c.unmanaged.length})</h3>
      <table><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>
      ${c.unmanaged.map(u => `<tr><td>${esc(u.name)}</td><td class="dim">${esc(u.kind)}</td></tr>`).join('')}
      </tbody></table>` : ''}`;
}

// Microsoft Secure Score is read straight from the tenant, so it needs no
// mapping on our side and cannot be wrong because of a typo here.
function secureScoreBlock(ss) {
  if (!ss) {
    return state.secureNote
      ? `<h3>MICROSOFT SECURE SCORE</h3><div class="note">Not available: ${esc(state.secureNote)}</div>`
      : '';
  }
  const peers = Object.entries(ss.comparative || {})
    .map(([k, v]) => `${esc(k)} ${v.toFixed(0)}%`).join(' \u00b7 ');
  const worst = (ss.controls || []).filter(c => c.state !== 'Reviewed' && c.max > 0 && c.score < c.max).slice(0, 12);
  return `<h3>MICROSOFT SECURE SCORE <span class="dim">\u2014 read live from the tenant, no mapping involved</span></h3>
    <div class="kpis">
      <div class="kpi"><b>${ss.percent}%</b><span>secure score</span></div>
      <div class="kpi"><b>${Math.round(ss.current)}</b><span>of ${Math.round(ss.max)} points</span></div>
      <div class="kpi"><b>${(ss.controls || []).length}</b><span>controls assessed</span></div>
    </div>
    ${peers ? `<p class="dim">Similar tenants average: ${peers}</p>` : ''}
    ${worst.length ? `<details><summary>Biggest point gaps (${worst.length} shown)</summary>
      <table><thead><tr><th>Control</th><th>Score</th><th>State</th></tr></thead><tbody>
      ${worst.map(c => `<tr><td>${esc(c.title || c.name)}</td>
        <td class="dim">${c.score.toFixed(1)} / ${c.max.toFixed(1)}</td>
        <td class="dim">${esc(c.state || '')}</td></tr>`).join('')}
      </tbody></table></details>` : ''}`;
}

const controlChip = {
  'met': 'c-ok', 'partial': 'c-warn', 'mapped-not-enforced': 'c-info',
  'mapped-not-deployed': 'c-dim', 'no-template': 'c-bad',
};
const controlWords = {
  'met': 'met', 'partial': 'partly met', 'mapped-not-enforced': 'deployed, report-only',
  'mapped-not-deployed': 'not deployed', 'no-template': 'no template covers this',
};

function frameworksBlock(frameworks = []) {
  if (!frameworks.length) return '';
  return `<h3>CONTROL FRAMEWORKS</h3>
    ${frameworks.map(f => {
      const errs = f.mappingErrors || [];
      return `<details>
      <summary>${esc(f.label)} ${f.version ? `<span class="dim">${esc(f.version)}</span>` : ''}
        \u2014 ${f.met} met, ${f.partial} partly met of ${f.total} (${f.percent}%)
        ${f.outOfScope ? `<span class="dim">\u00b7 ${f.outOfScope} more cover products this console does not manage</span>` : ''}
        ${f.verified ? '' : '<span class="chip c-warn">NOT FETCHED, IDS UNVERIFIED</span>'}</summary>
      ${errs.length ? `<div class="note bad">This console claims ${errs.length} control ids the publisher does not list: ${esc(errs.join(', '))}. That is a bug in our mapping, not a finding about the tenant.</div>` : ''}
      ${f.source ? `<p class="mono-sm">Fetched from ${esc(f.source)}</p>` : '<p class="mono-sm">Scored only against what this console declares; nothing was fetched to check the ids against.</p>'}
      <table><thead><tr><th>Control</th><th>Must</th><th>State</th><th>Covered by</th></tr></thead><tbody>
      ${(f.controls || []).map(c => `<tr>
        <td class="mono-sm">${esc(c.id)}<div class="dim">${esc((c.title || '').slice(0, 130))}</div></td>
        <td class="dim">${esc(c.criticality || '')}</td>
        <td><span class="chip ${controlChip[c.state] || 'c-dim'}">${esc(controlWords[c.state] || c.state)}</span></td>
        <td class="mono-sm">${esc(c.via || '')}${c.note ? `<div class="c-warn">${esc(c.note)}</div>` : ''}</td>
      </tr>`).join('')}
      </tbody></table></details>`;
    }).join('')}`;
}

// Microsoft's security baselines, compared setting by setting. The ids are the
// same ones Intune policies use, so there is no interpretation in this table.
const msWords = { met: 'agrees', differs: 'differs', conflict: 'policies disagree', 'not-set': 'not set' };
const msChip = { met: 'c-ok', differs: 'c-warn', conflict: 'c-bad', 'not-set': 'c-dim' };

// Microsoft's own Conditional Access templates, matched by behavior.
const caWords = { covered: 'done', 'covered-broader': 'done, broader', weaker: 'weaker look-alike', missing: 'missing' };
const caChip = { covered: 'c-ok', 'covered-broader': 'c-ok', weaker: 'c-warn', missing: 'c-bad' };

// Report-only policies and how long each has been observing. The library's
// guidance is at least 48 hours of report-only before enforcing.
function reportOnlyBlock(ro) {
  if (!ro || !ro.policies?.length) return '';
  return `<h3>REPORT-ONLY, WAITING TO BE ENFORCED</h3>
    <p class="dim">Minimum ${ro.minimumHours} hours in report-only before a policy starts blocking people, measured from the console's own history.</p>
    <table><thead><tr><th>Policy</th><th>Report-only for</th><th></th></tr></thead><tbody>
    ${ro.policies.map(p => `<tr><td>${esc(p.name)}</td>
      <td class="${p.ready ? 'c-ok' : 'c-warn'}">${p.hours.toFixed(1)} h${p.ready ? '' : ` (${(ro.minimumHours - p.hours).toFixed(1)} h to go)`}</td>
      <td class="row" style="margin:0">
        <button class="${p.ready ? 'danger' : 'ghost'}" data-enforce="${esc(p.objectId)}">ENFORCE</button>
        <button class="ghost" data-widen="policies|${esc(p.objectId)}">WIDEN PILOT</button></td></tr>`).join('')}
    </tbody></table>`;
}

// Settings configured by more than one Intune policy. Conflicts first.
function overlapBlock(list = []) {
  if (!list.length) return '';
  const conflicts = list.filter(o => o.conflict).length;
  return `<h3>SETTINGS SET BY MORE THAN ONE POLICY</h3>
    <div class="note ${conflicts ? 'bad' : ''}">${list.length} settings are configured by two or more policies${conflicts ? `, and ${conflicts} of them disagree, so what devices actually get depends on Intune's conflict handling` : ', all agreeing'}.</div>
    <details><summary>Show them</summary>
    <table><thead><tr><th>Setting</th><th>Policies and values</th><th></th></tr></thead><tbody>
    ${list.map(o => `<tr><td>${esc(o.name)}</td>
      <td class="mono-sm">${o.observed.map(x => `${esc(x.label)} <span class="dim">(${esc(x.policy)})</span>`).join('<br>')}</td>
      <td><span class="chip ${o.conflict ? 'c-bad' : 'c-dim'}">${o.conflict ? 'conflict' : 'duplicate'}</span></td></tr>`).join('')}
    </tbody></table></details>`;
}

// The Praxis set: templates whose settings come from the operator's own
// library, with the source of every setting shown beside it.
const srcChip = { library: 'c-ok', microsoft: 'c-info', judgement: 'c-warn' };
const srcWord = { library: 'your library', microsoft: "Microsoft's value", judgement: 'judgement' };

function praxisBlock(p, w) {
  const tpls = Object.entries(p.templates || {}).sort(([a], [b]) => a.localeCompare(b));
  const all = tpls.flatMap(([, t]) => t.settings);
  const count = (k) => all.filter(x => x.source === k).length;
  const fw = (set, key) => {
    const f = w?.[set]?.frameworks?.[key];
    return f ? `${f.met} met, ${f.partial} partly (${f.percent}%)` : '\u2014';
  };
  return `<h2>PRAXIS \u2014 TEMPLATES BUILT FROM YOUR LIBRARY</h2>
    <p class="dim">${tpls.length} templates, ${all.length} settings: <span class="c-ok">${count('library')} from your library</span>,
      <span class="c-info">${count('microsoft')} where the library gives no value and Microsoft's is used</span>,
      <span class="c-warn">${count('judgement')} judgement call${count('judgement') === 1 ? '' : 's'}</span>. Every setting shows its source.</p>
    ${w ? `<table><thead><tr><th>If a tenant deployed and enforced all of...</th><th>CIS Microsoft 365 (Conditional Access)</th><th>CISA SCuBA</th></tr></thead><tbody>
      ${['house', 'praxis', 'microsoft'].map(k => `<tr><td>${k === 'house' ? 'House templates' : k === 'praxis' ? 'Praxis templates' : "Microsoft's templates"} <span class="dim">(${w[k]?.templates ?? 0})</span></td>
        <td>${fw(k, 'cis-m365')}</td><td>${fw(k, 'scuba')}</td></tr>`).join('')}
      </tbody></table>` : ''}
    ${tpls.map(([name, t]) => `<details><summary>${esc(name)}${t.requires ? ` <span class="chip c-info">${esc(t.requires)}</span>` : ''}</summary>
      ${t.why ? `<p>${esc(t.why)}</p>` : ''}
      <table><thead><tr><th>Setting</th><th>Value</th><th>Source</th></tr></thead><tbody>
      ${t.settings.map(x => `<tr><td>${esc(x.setting)}</td><td class="mono-sm">${esc(x.value)}</td>
        <td><span class="chip ${srcChip[x.source] || 'c-dim'}">${esc(srcWord[x.source] || x.source)}</span>
          ${(x.citations || []).map(c => `<div class="mono-sm"><b>${esc(c.course)}</b> <span class="dim">(passage ${c.passage})</span><br>\u201c${esc(c.quote)}\u201d</div>`).join('')}
          ${x.note ? `<div class="mono-sm dim">${esc(x.note)}</div>` : ''}</td></tr>`).join('')}
      </tbody></table></details>`).join('')}`;
}

function msCABlock(rows = [], note = '', mode = 'tenant') {
  if (!rows.length) return note ? `<h3>MICROSOFT CONDITIONAL ACCESS TEMPLATES</h3><div class="note">Not available: ${esc(note)}</div>` : '';
  const done = rows.filter(r => r.state === 'covered' || r.state === 'covered-broader').length;
  const weak = rows.filter(r => r.state === 'weaker').length;
  const who = mode === 'tenant' ? "this tenant's policies" : 'the House templates';
  return `<h3>MICROSOFT CONDITIONAL ACCESS TEMPLATES <span class="dim">\u2014 Microsoft's own recommendations, against ${esc(who)}</span></h3>
    <div class="note">${done} of ${rows.length} are done${weak ? `, ${weak} have a weaker look-alike` : ''}, ${rows.length - done - weak} are missing. ${rows.filter(r => !r.template.notDeployable).length} can be deployed from DEPLOY \u2192 microsoft's templates, report-only, with the emergency access group excluded${rows.some(r => r.template.notDeployable) ? `; ${rows.filter(r => r.template.notDeployable).length} must be created in the Entra portal, reason shown per row` : ''}.</div>
    <table><thead><tr><th>Microsoft template</th><th>State</th><th>Done by / closest</th><th>Needs</th></tr></thead><tbody>
    ${rows.map(r => `<tr>
      <td>${esc(r.template.name)}<div class="mono-sm">${esc(r.does)}</div></td>
      <td><span class="chip ${caChip[r.state] || 'c-dim'}">${esc(caWords[r.state] || r.state)}</span>${r.liveState && r.liveState !== 'enabled' ? `<div class="mono-sm c-warn">${esc(r.liveState)}</div>` : ''}</td>
      <td class="mono-sm">${esc(r.by || '')}${(r.reasons || []).map(x => `<div class="${r.state === 'weaker' ? 'c-warn' : 'dim'}">${esc(x)}</div>`).join('')}</td>
      <td class="mono-sm c-info">${esc(r.template.requires || '')}${r.template.notDeployable ? `<div class="c-warn">not deployable here: ${esc(r.template.notDeployable)}</div>` : ''}</td></tr>`).join('')}
    </tbody></table>`;
}

function msBaselineBlock(results = [], note = '', mode = 'tenant') {
  if (!results.length) return note ? `<h3>MICROSOFT SECURITY BASELINES</h3><div class="note">Not available: ${esc(note)}</div>` : '';
  const who = mode === 'tenant' ? "this tenant's Intune policies" : 'the House Defender and Intune templates';
  return `<h3>MICROSOFT SECURITY BASELINES <span class="dim">\u2014 ${esc(who)}, compared setting by setting</span></h3>
    <p class="dim">"Set" counts recommendations some policy actually configures. A setting nobody configures falls back to the Windows default, which may or may not match, so it is listed but not counted against the score.</p>
    ${results.map(r => {
      const set = r.met + r.differs + r.conflict;
      const shown = (r.items || []).filter(i => i.state !== 'not-set');
      return `<details><summary>${esc(r.name)} <span class="dim">${esc(r.version)}</span> \u2014
        ${r.fetchError ? '<span class="chip c-bad">COULD NOT FETCH</span>' :
          `${set} of ${r.total} set \u00b7 ${r.met} agree \u00b7 <span class="${r.differs ? 'c-warn' : ''}">${r.differs} differ</span>${r.conflict ? ` \u00b7 <span class="c-bad">${r.conflict} conflicting</span>` : ''}${set ? ` \u00b7 ${r.percent}% agreement` : ''}`}</summary>
        ${r.fetchError ? `<div class="note bad">${esc(r.fetchError)}</div>` : ''}
        ${shown.length ? `<table><thead><tr><th>Setting</th><th>Microsoft</th><th>Configured</th><th></th></tr></thead><tbody>
          ${shown.map(i => `<tr><td>${esc(i.name)}</td><td class="dim">${esc(i.expected)}</td>
            <td class="mono-sm">${(i.observed || []).map(o => `${esc(o.label)} <span class="dim">(${esc(o.policy)})</span>`).join('<br>')}</td>
            <td><span class="chip ${msChip[i.state] || 'c-dim'}">${esc(msWords[i.state] || i.state)}</span></td></tr>`).join('')}
          </tbody></table>` : `<p class="dim">No policy configures any of these ${r.total} settings.</p>`}
      </details>`;
    }).join('')}`;
}

function diffTable(changes = []) {
  return `<table><thead><tr><th>Setting</th><th>Baseline</th><th>In tenant</th></tr></thead><tbody>
    ${changes.map(ch => `<tr><td class="mono-sm">${esc(ch.path)}</td>
      <td class="mono-sm">${esc(fmt(ch.base))}</td>
      <td class="mono-sm ${ch.kind === 'added' ? 'c-info' : ch.kind === 'removed' ? 'c-bad' : 'c-warn'}">${esc(fmt(ch.live))}</td></tr>`).join('')}
  </tbody></table>`;
}
const fmt = (v) => v === undefined ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v);

// ---------- deploy ----------

function renderDeploy() {
  const el = $('#tab-deploy');
  const needed = [...new Set(state.templates.flatMap(t => t.placeholders || []))].sort();
  el.innerHTML = `<h2>DEPLOY</h2>
    ${tenantId() ? '' : '<div class="note">Pick a tenant in the top bar.</div>'}
    ${state.status.readOnly ? '<div class="note">Console is read-only. Preview works; nothing will be written.</div>' : ''}
    <p class="dim">Deploy creates policies that are missing. A policy whose name already exists is left untouched, never overwritten.</p>

    <h3>VALUES THIS TENANT NEEDS</h3>
    <div class="grid">
      ${needed.map(p => `<div class="card"><h4>${esc(p)}</h4>
        <input data-token="${esc(p)}" value="${esc(state.tokens[p] || '')}" placeholder="value" style="width:100%"></div>`).join('')}
    </div>
    <div class="row">
      <label>Conditional Access state
        <select id="caState">
          <option value="enabledForReportingButNotEnforced">report-only (safe default)</option>
          <option value="enabled">on, enforced</option>
          <option value="disabled">off</option>
        </select></label>
      <button class="ghost" id="saveTokens">SAVE VALUES</button>
    </div>
    <div class="row">
      <label>Rollout
        <select id="rollout">
          <option value="pilot">pilot group first (recommended)</option>
          <option value="all">everyone now</option>
          <option value="none">create only, assign nothing</option>
        </select></label>
      <input id="pilotGroup" size="40" placeholder="pilot group object id" value="${esc(state.pilotGroup)}">
      <span class="dim">Pilot: Conditional Access that targets everyone is narrowed to the pilot group, and Intune policies are assigned to it. Widen later from COMPARE.</span>
    </div>

    <h3>TEMPLATES</h3>
    <div class="row">
      <button class="ghost" id="selAll">SELECT ALL</button>
      <button class="ghost" id="selNone">CLEAR</button>
      <button class="ghost" id="selMissing" ${state.comparison ? '' : 'disabled'} title="Requires a comparison first">SELECT MISSING ONLY</button>
      <span class="spacer"></span>
      <button class="act" id="preview" ${tenantId() ? '' : 'disabled'}>PREVIEW</button>
    </div>
    <div class="grid">
      ${['praxis', 'conditional-access', 'defender', 'intune', 'microsoft'].map(cat => `<div class="card"><h4>${esc(cat === 'microsoft' ? "microsoft's templates" : cat === 'praxis' ? 'praxis (from your library)' : cat)}</h4>
        ${state.templates.filter(t => t.category === cat).map(t => `
          <label class="check"><input type="checkbox" data-tpl="${esc(t.id)}" ${state.selected.has(t.id) ? 'checked' : ''}>
          <span>${esc(t.code ? t.code + ' ' : '')}${esc(t.name)}</span></label>`).join('')}
      </div>`).join('')}
    </div>
    <div id="deployOut"></div>`;

  $('#caState').value = state.caState;
  $('#rollout').value = state.rollout;
  $('#rollout').onchange = e => { state.rollout = e.target.value; localStorage.setItem('pc.rollout', e.target.value); };
  $('#pilotGroup').onchange = e => { state.pilotGroup = e.target.value.trim(); localStorage.setItem('pc.pilotGroup', state.pilotGroup); };
  $('#caState').onchange = e => { state.caState = e.target.value; localStorage.setItem('pc.caState', e.target.value); };
  $('#saveTokens').onclick = () => { collectTokens(); toast('Values saved in this browser'); };
  $$('[data-tpl]', el).forEach(cb => cb.onchange = () => cb.checked ? state.selected.add(cb.dataset.tpl) : state.selected.delete(cb.dataset.tpl));
  $('#selAll').onclick = () => { state.templates.forEach(t => state.selected.add(t.id)); renderDeploy(); };
  $('#selNone').onclick = () => { state.selected.clear(); renderDeploy(); };
  $('#selMissing').onclick = () => {
    state.selected.clear();
    // Equivalent templates are already done by another policy; selecting them
    // would deploy a duplicate alongside the tenant's own.
    state.comparison.items.filter(i => i.state === 'missing').forEach(i => state.selected.add(i.template.id));
    renderDeploy();
  };
  $('#preview').onclick = doPreview;
}

function collectTokens() {
  $$('[data-token]').forEach(i => { state.tokens[i.dataset.token] = i.value.trim(); });
  localStorage.setItem('pc.tokens', JSON.stringify(state.tokens));
}

async function doPreview() {
  if (!requireTenant()) return;
  collectTokens();
  const ids = [...state.selected];
  if (!ids.length) return toast('Nothing selected', true);
  try {
    const r = await api(`/api/tenants/${encodeURIComponent(tenantId())}/deploy`,
      { method: 'POST', body: JSON.stringify({ templateIds: ids, tokens: state.tokens, state: state.caState, preview: true, rollout: state.rollout, pilotGroupId: state.pilotGroup }) });
    drawDeployResult(r, true);
  } catch (e) { toast(e.message, true); }
}

function drawDeployResult(r, isPreview) {
  const failed = r.items.filter(i => i.result === 'failed');
  const wouldCreate = r.items.filter(i => i.result === 'preview' && i.detail === 'would be created');
  $('#deployOut').innerHTML = `
    <h3>${isPreview ? 'PREVIEW' : 'RESULT'} — RUN ${r.runId}</h3>
    <table><thead><tr><th>Result</th><th>Name</th><th>Detail</th></tr></thead><tbody>
    ${r.items.map(i => `<tr>
      <td><span class="chip ${i.result === 'failed' ? 'c-bad' : i.result === 'created' || i.result === 'preview' ? 'c-ok' : 'c-dim'}">${esc(i.result)}</span></td>
      <td>${esc(i.name)}</td><td class="mono-sm">${esc(i.detail)}</td></tr>`).join('')}
    </tbody></table>
    ${isPreview ? `<div class="row end">
      <button class="danger" id="confirmDeploy" ${state.status.readOnly || !wouldCreate.length ? 'disabled' : ''}>DEPLOY ${wouldCreate.length} POLICIES FOR REAL</button>
    </div>` : ''}`;
  if (failed.length) toast(`${failed.length} templates could not be rendered. Check the values above.`, true);
  if (isPreview) {
    const btn = $('#confirmDeploy');
    if (btn) btn.onclick = async () => {
      const ok = await confirmAction('Deploy to a live tenant',
        `<p>This creates <b>${wouldCreate.length}</b> policies in <b>${esc(state.tenant.name)}</b>.</p>
         <p>Conditional Access policies will be created as <b>${esc(state.caState === 'enabled' ? 'ON and enforced' : state.caState === 'disabled' ? 'off' : 'report-only')}</b>.</p>
         <p>Rollout: <b>${state.rollout === 'pilot' ? 'pilot group ' + esc(state.pilotGroup || '(none given)') : state.rollout === 'all' ? 'everyone' : 'nothing assigned'}</b>.</p>
         ${state.caState === 'enabled' ? `<p class="note bad">Enforced means users are affected immediately. The recommended path is report-only for at least ${state.status.reportOnlyHours} hours, then ENFORCE from COMPARE. A wrong exclusion group can lock administrators out.</p>` : ''}
         <ul>${wouldCreate.map(i => `<li>${esc(i.name)}</li>`).join('')}</ul>`, 'DEPLOY');
      if (!ok) return;
      try {
        const r2 = await api(`/api/tenants/${encodeURIComponent(tenantId())}/deploy`,
          { method: 'POST', body: JSON.stringify({ templateIds: [...state.selected], tokens: state.tokens, state: state.caState, preview: false, rollout: state.rollout, pilotGroupId: state.pilotGroup }) });
        drawDeployResult(r2, false);
        toast('Deploy finished. See RUNS for the record.');
      } catch (e) { toast(e.message, true); }
    };
  }
}

// ---------- history ----------

async function renderHistory() {
  const el = $('#tab-history');
  if (!tenantId()) { el.innerHTML = '<h2>HISTORY</h2><div class="note">Pick a tenant in the top bar.</div>'; return; }
  el.innerHTML = '<h2>HISTORY</h2><p class="dim">Loading stored versions...</p>';
  try { state.objects = await api(`/api/tenants/${encodeURIComponent(tenantId())}/objects`); }
  catch (e) { el.innerHTML = `<h2>HISTORY</h2><div class="note bad">${esc(e.message)}</div>`; return; }

  el.innerHTML = `<h2>HISTORY</h2>
    <p class="dim">Every captured version of every policy in this tenant. Snapshots run on a schedule and before every change, so history covers changes made in the portal too.</p>
    <div class="row"><button class="act" id="snapNow">SNAPSHOT NOW</button></div>
    <table><thead><tr><th>Name</th><th>Type</th><th>Versions</th><th>Last captured</th><th></th></tr></thead><tbody>
    ${state.objects.map(o => `<tr>
      <td>${esc(o.name)}${o.deleted ? ' <span class="chip c-bad">DELETED IN TENANT</span>' : ''}</td>
      <td class="dim">${esc(o.kind)}</td><td>${o.version}</td><td class="dim">${esc(o.capturedAt)}</td>
      <td><button class="ghost" data-hist="${esc(o.kind)}|${esc(o.objectId)}">VERSIONS</button></td></tr>`).join('')
      || '<tr><td colspan="5" class="dim">Nothing captured yet. Run a snapshot.</td></tr>'}
    </tbody></table><div id="histOut"></div>`;

  $('#snapNow').onclick = async () => {
    toast('Snapshotting...');
    try { const r = await api(`/api/tenants/${encodeURIComponent(tenantId())}/snapshot`, { method: 'POST' });
      toast(`${r.captured} read, ${r.changed} new versions`); renderHistory(); } catch (e) { toast(e.message, true); }
  };
  $$('[data-hist]', el).forEach(b => b.onclick = () => {
    const [kind, objectId] = b.dataset.hist.split('|');
    showVersions(kind, objectId);
  });
}

async function showVersions(kind, objectId) {
  const q = `kind=${encodeURIComponent(kind)}&objectId=${encodeURIComponent(objectId)}`;
  const hist = await api(`/api/tenants/${encodeURIComponent(tenantId())}/history?${q}`);
  const name = hist[0]?.name || objectId;
  $('#histOut').innerHTML = `<h3>${esc(name)}</h3>
    <table><thead><tr><th>Version</th><th>Captured</th><th>Why</th><th>Compare to previous</th><th></th></tr></thead><tbody>
    ${hist.map((v, i) => `<tr>
      <td>v${v.version}${i === 0 ? ' <span class="chip c-ok">CURRENT</span>' : ''}</td>
      <td class="dim">${esc(v.capturedAt)}</td>
      <td class="dim">${esc(v.source)}${v.deleted ? ' <span class="chip c-bad">deleted</span>' : ''}</td>
      <td>${i < hist.length - 1 ? `<button class="ghost" data-diff="${hist[i + 1].version}|${v.version}">WHAT CHANGED</button>` : '<span class="dim">first capture</span>'}</td>
      <td class="row" style="margin:0">
        <button class="ghost" data-show="${v.version}">VIEW</button>
        ${i === 0 || v.deleted ? '' : `<button class="danger" data-revert="${v.version}">REVERT TO THIS</button>`}
      </td></tr>`).join('')}
    </tbody></table>`;

  $$('#histOut [data-show]').forEach(b => b.onclick = async () => {
    const v = await api(`/api/tenants/${encodeURIComponent(tenantId())}/version?${q}&version=${b.dataset.show}`);
    await confirmAction(`${name} — v${v.version} (${v.capturedAt})`, `<pre>${esc(JSON.stringify(v.body, null, 2))}</pre>`, 'CLOSE');
  });
  $$('#histOut [data-diff]').forEach(b => b.onclick = async () => {
    const [from, to] = b.dataset.diff.split('|');
    const d = await api(`/api/tenants/${encodeURIComponent(tenantId())}/versiondiff?${q}&from=${from}&to=${to}`);
    await confirmAction(`${name}: v${from} → v${to}`,
      d.changes.length ? diffTable(d.changes).replace('Baseline', `v${from}`).replace('In tenant', `v${to}`)
                       : '<p class="dim">No meaningful differences.</p>', 'CLOSE');
  });
  $$('#histOut [data-revert]').forEach(b => b.onclick = async () => {
    const version = Number(b.dataset.revert);
    const d = await api(`/api/tenants/${encodeURIComponent(tenantId())}/versiondiff?${q}&from=0&to=${version}`);
    const ok = await confirmAction('Revert a live policy',
      `<p>This writes version <b>${version}</b> back over <b>${esc(name)}</b> in <b>${esc(state.tenant.name)}</b>.</p>
       <p>The current state is snapshotted first, so this itself can be undone.</p>
       <p class="note">These settings change:</p>${d.changes.length ? diffTable(d.changes).replace('Baseline', 'now').replace('In tenant', `v${version}`) : '<p class="dim">No differences; reverting would change nothing.</p>'}`,
      'REVERT');
    if (!ok) return;
    try {
      await api(`/api/tenants/${encodeURIComponent(tenantId())}/revert`,
        { method: 'POST', body: JSON.stringify({ kind, objectId, version }) });
      toast('Reverted. The change is in RUNS.');
      showVersions(kind, objectId);
    } catch (e) { toast(e.message, true); }
  });
}

// ---------- runs ----------

async function renderRuns() {
  const el = $('#tab-runs');
  const runs = await api('/api/runs?limit=100' + (tenantId() ? `&tenantId=${encodeURIComponent(tenantId())}` : ''));
  el.innerHTML = `<h2>RUNS</h2>
    <p class="dim">Everything this console has done, and who did it.</p>
    <table><thead><tr><th>When</th><th>Action</th><th>Mode</th><th>Who</th><th>Tenant</th><th>Summary</th><th></th></tr></thead><tbody>
    ${runs.map(r => `<tr>
      <td class="dim">${esc(r.startedAt)}</td>
      <td><span class="chip ${r.action === 'revert' ? 'c-warn' : r.action === 'deploy' ? 'c-ok' : 'c-dim'}">${esc(r.action)}</span></td>
      <td class="dim">${esc(r.mode)}</td><td>${esc(r.actor)}</td>
      <td class="mono-sm">${esc(nameFor(r.tenantId))}</td>
      <td>${esc(r.summary)}</td>
      <td><button class="ghost" data-run="${r.id}">ITEMS</button></td></tr>`).join('')
      || '<tr><td colspan="7" class="dim">Nothing yet.</td></tr>'}
    </tbody></table>`;
  $$('[data-run]', el).forEach(b => b.onclick = async () => {
    const items = await api('/api/runs/' + b.dataset.run);
    await confirmAction('Run ' + b.dataset.run,
      `<table><thead><tr><th>Result</th><th>Name</th><th>Detail</th><th>Versions</th></tr></thead><tbody>
       ${items.map(i => `<tr><td>${esc(i.result)}</td><td>${esc(i.name)}</td><td class="mono-sm">${esc(i.detail)}</td>
         <td class="dim">${i.beforeVersion ? 'v' + i.beforeVersion + ' → ' : ''}${i.afterVersion ? 'v' + i.afterVersion : ''}</td></tr>`).join('')}
       </tbody></table>`, 'CLOSE');
  });
}
const nameFor = (id) => state.tenants.find(t => t.id === id)?.name || id;

// ---------- settings ----------

function renderSettings() {
  $('#tab-settings').innerHTML = `<h2>SETTINGS</h2>
    <div class="grid">
      <div class="card"><h4>Mode</h4><p>${state.status.readOnly ? 'Read-only. Writes are refused by the server.' : 'Writes enabled.'}</p>
        <p class="mono-sm">Set PC_READ_ONLY=true to lock writes.</p></div>
      <div class="card"><h4>App registration</h4><p class="mono-sm">${esc(state.status.clientId || 'not set')}</p>
        <p class="mono-sm">PC_CLIENT_ID and PC_CLIENT_SECRET</p></div>
      <div class="card"><h4>Scheduled snapshots</h4><p>Every ${esc(state.status.snapshotEvery)}</p>
        <p class="mono-sm">PC_SNAPSHOT_INTERVAL</p></div>
      <div class="card"><h4>Signed in as</h4><p>${esc(state.status.user?.upn || state.status.actor)}</p>
        <p class="mono-sm">Recorded against every run.</p></div>
      <div class="card"><h4>Entra sign-in</h4>
        <p>${state.status.signInActive ? 'Active' : 'Not active'}</p>
        <p class="mono-sm">${esc(state.status.signInActive ? 'Who may use it: ' + state.status.accessGate : state.status.signInReason || '')}</p></div>
    </div>
    <h3>CONTROL FRAMEWORKS</h3>
    <p class="dim">Frameworks are fetched from the publisher so a control number can never be mistyped or invented here. Any id this console claims that the publisher does not list is reported as our bug.</p>
    <div class="row">
      <button class="act" id="refreshMs" title="Reads Microsoft's Conditional Access templates and Intune security baselines through the tenant picked in the top bar">FETCH MICROSOFT LATEST</button>
      <button class="act" id="refreshBm">FETCH CISA LATEST</button>
      <input id="cisDir" size="60" placeholder="folder of CIS benchmark PDFs" value="${esc(state.benchmarks?.cisDir || '')}">
      <button class="act" id="importCis">IMPORT CIS PDFS</button>
    </div>
    <div id="bmOut">${benchmarkPanel()}</div>

    <h3>SAVED VALUES (THIS BROWSER ONLY)</h3>
    <pre>${esc(JSON.stringify(state.tokens, null, 2))}</pre>`;

  $('#refreshMs').onclick = async () => {
    if (!requireTenant()) return;
    toast("Reading Microsoft's templates and baselines, about a minute...");
    try {
      const a = await api('/api/mstemplates/refresh', { method: 'POST', body: JSON.stringify({ tenantId: tenantId() }) });
      const b = await api('/api/baselines/refresh', { method: 'POST', body: JSON.stringify({ tenantId: tenantId() }) });
      state.templates = await api('/api/templates');
      toast(`${a.templates} Conditional Access templates, ${b.baselines} Intune baselines`);
    } catch (e) { toast(e.message, true); }
  };
  $('#importCis').onclick = async () => {
    toast('Reading the PDFs, this takes a minute...');
    try {
      const r = await api('/api/benchmarks/import-cis', { method: 'POST', body: JSON.stringify({ dir: $('#cisDir').value.trim() }) });
      state.benchmarks = await api('/api/benchmarks');
      $('#bmOut').innerHTML = benchmarkPanel();
      toast(`${r.imported.length} CIS benchmarks imported`);
    } catch (e) { toast(e.message, true); }
  };
  $('#refreshBm').onclick = async () => {
    toast('Fetching from the publisher...');
    try {
      const r = await api('/api/benchmarks/refresh', { method: 'POST' });
      state.benchmarks = await api('/api/benchmarks');
      $('#bmOut').innerHTML = benchmarkPanel();
      toast(`${r.source} ${r.version}: ${r.controls} controls`);
    } catch (e) { toast(e.message, true); }
  };
}

function benchmarkPanel() {
  const b = state.benchmarks;
  if (!b) return '<div class="note">Nothing fetched yet.</div>';
  const cached = Object.entries(b.cached || {});
  return `
    ${cached.length ? `<table><thead><tr><th>Framework</th><th>Version</th><th>Controls</th><th>Fetched</th></tr></thead><tbody>
      ${cached.map(([k, v]) => `<tr><td>${esc(v.label || k)}</td><td>${esc(v.version)}</td><td>${v.controls}</td>
        <td class="dim">${esc(String(v.fetchedAt).slice(0, 19))}</td></tr>`).join('')}
      </tbody></table>` : '<div class="note">Nothing cached yet. Press FETCH LATEST.</div>'}
    ${b.mapping ? `<pre>${esc(b.mapping)}</pre>` : ''}
    ${Object.entries(b.notFetchable || {}).map(([k, why]) =>
      `<div class="note"><b>${esc(k)}</b> cannot be fetched automatically. ${esc(why)}</div>`).join('')}`;
}

// ---------- shared helpers for the client screens ----------

// friendly turns a server error into one calm sentence for the owner, with the
// raw text kept underneath for whoever supports the console.
function friendly(e) {
  const raw = String(e?.message || e || '');
  const low = raw.toLowerCase();
  let say;
  if (e instanceof TypeError || low.includes('failed to fetch') || low.includes('networkerror')) {
    say = 'The console did not answer. Check that it is still running, then try again.';
  } else if (low.includes('no app credentials') || low.includes('not configured') || low.includes('pc_')) {
    say = 'This console is not connected to Microsoft yet, so it cannot reach this client. Nothing is wrong with the client.';
  } else if (low.includes('read-only')) {
    say = 'The console is in read-only mode, so it will not change anything in a client.';
  } else if (e?.status === 403) {
    say = 'Your account is not allowed to do this. Ask someone who can approve changes.';
  } else if (e?.status === 409) {
    say = 'Something changed since the preview. Preview again, then try once more.';
  } else if (e?.status === 412) {
    say = 'The console could not get a sign-in for this client that is allowed to do this. Sign in as an admin of the client and try again.';
  } else if (e?.status === 404) {
    say = 'The console does not know this client or item any more. Refresh the page.';
  } else if (e?.status === 400) {
    say = 'The console could not accept that. Check what was typed and try again.';
  } else if (e?.status >= 500) {
    say = 'Microsoft or the console did not answer as expected. Try again in a minute.';
  } else {
    say = 'That did not work.';
  }
  return { say, raw };
}
function errNote(e, bad = false) {
  const f = friendly(e);
  return `<div class="note ${bad ? 'bad' : ''}">${esc(f.say)}<div class="mono-sm">Details: ${esc(f.raw)}</div></div>`;
}
function toastErr(e) { toast(friendly(e).say, true); }

const tpath = (suffix = '') => `/api/tenants/${encodeURIComponent(tenantId())}${suffix}`;
const pickClientNote = '<div class="note">Pick a client in the top bar first.</div>';
const when = (s) => s ? esc(String(s).replace('T', ' ').slice(0, 16)) : '<span class="dim">never</span>';
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
const tplName = (id) => state.templates.find(t => t.id === id)?.name || id;
// EMERGENCY_ACCESS_GROUP_ID becomes "Emergency access group id"
const prettyKey = (k) => { const s = String(k).toLowerCase().replace(/_/g, ' '); return s.charAt(0).toUpperCase() + s.slice(1); };
function pickTenant(id) {
  state.tenant = state.tenants.find(t => t.id === id) || null;
  $('#tenantPicker').value = state.tenant ? id : '';
  localStorage.setItem('pc.tenant', state.tenant ? id : '');
  state.comparison = state.score = null;
}

function findingState(f) {
  if (f.state === 'acknowledged') return `<span class="chip c-dim">seen</span><div class="mono-sm">by ${esc(f.ackedBy)} ${when(f.ackedAt)}${f.ackNote ? `<br>${esc(f.ackNote)}` : ''}</div>`;
  if (f.state === 'snoozed') return `<span class="chip c-info">snoozed</span><div class="mono-sm">until ${when(f.snoozedUntil)}${f.ackNote ? `<br>${esc(f.ackNote)}` : ''}</div>`;
  return '<span class="chip c-warn">new</span>';
}

// askNote opens the dialog with a note box and, for a snooze, a date. It
// resolves to {note, until} or null when cancelled or the date is missing.
async function askNote(title, introHTML, needDate, noteRequired = false) {
  const ok = await confirmAction(title, `${introHTML}
    ${needDate ? '<label class="dim">Until<input type="date" id="askUntil"></label>' : ''}
    <label class="dim">Note${noteRequired ? ' (required)' : ' (optional)'}<input id="askNote" style="width:100%"></label>`, 'SAVE');
  if (!ok) return null;
  const note = ($('#askNote')?.value || '').trim(), until = $('#askUntil')?.value || '';
  if (needDate && !until) { toast('Pick a date first', true); return null; }
  if (noteRequired && !note) { toast(title.startsWith('Skip') ? 'A reason is required, so the handover report can say why' : 'Say what you checked: a note is required', true); return null; }
  return { note, until };
}

const sevOrder = { critical: 0, warning: 1, info: 2 };
const sevChip = { critical: 'c-bad', warning: 'c-warn', info: 'c-info' };
const sevWord = { critical: 'critical', warning: 'warning', info: 'for information' };
const classWord = { missing: 'missing', changed: 'settings changed', disabled: 'switched off', extra: 'not in the standard' };

// ---------- fleet ----------

async function renderFleet() {
  const el = $('#tab-fleet');
  el.innerHTML = `<h2>FLEET</h2><p class="dim">Loading every client...</p>`;
  let rows;
  try { rows = await api('/api/fleet'); await loadTenants(); } catch (e) { el.innerHTML = `<h2>FLEET</h2>${errNote(e, true)}`; return; }
  if (!rows.length) {
    el.innerHTML = `<h2>FLEET</h2><div class="note">No clients yet. Add one on TENANTS.</div>`;
    return;
  }
  const num = (n, cls) => n ? `<b class="${cls}">${n}</b>` : '<span class="dim">0</span>';
  const g = (r, p) => (r.consentKindsGranted || {})[p] || 0;
  el.innerHTML = `<h2>FLEET</h2>
    <p class="dim">Every client at a glance, the ones needing the most attention first. Counts are open drift that nobody has acknowledged or snoozed yet. Press a client to see its drift.</p>
    <div class="scroll"><table><thead><tr><th>Client</th><th>Critical</th><th>Warning</th><th>For information</th><th>Seen or snoozed</th><th>Exceptions</th><th>Rollouts running</th><th>Build out</th><th>Permission areas granted</th><th></th></tr></thead><tbody>
    ${rows.map(r => `<tr class="click" data-open="${esc(r.tenantId)}">
      <td>${esc(r.name)}<div class="mono-sm">${esc(r.status)}${r.lastSeen ? ', last reached ' + when(r.lastSeen) : ''}</div></td>
      <td>${num(r.critical, 'c-bad')}</td><td>${num(r.warning, 'c-warn')}</td><td>${num(r.info, 'c-info')}</td>
      <td>${num(r.acknowledgedOrSnoozed, 'c-dim')}</td><td>${num(r.exceptions, '')}</td><td>${num(r.activeRollouts, 'c-info')}</td>
      <td class="mono-sm">${r.buildout ? `${r.buildout.done} of ${r.buildout.of} steps done` : 'not started'}</td>
      <td class="mono-sm">Read: ${g(r, 'read')} of ${r.consentKindsTotal}<br>Change: ${g(r, 'write')} of ${r.consentKindsTotal}</td>
      <td><button class="ghost" data-open="${esc(r.tenantId)}">OPEN DRIFT</button></td></tr>`).join('')}
    </tbody></table></div>
    <div id="fleetApply"></div>`;
  $$('tr[data-open]', el).forEach(tr => tr.onclick = () => { pickTenant(tr.dataset.open); showTab('drift'); });
  renderFleetApply(rows);
}

// Fleet apply: one change to several clients, canary first.
function renderFleetApply(rows) {
  const box = $('#fleetApply');
  const tpls = state.templates;
  box.innerHTML = `<h3>APPLY TO SEVERAL CLIENTS</h3>
    <p class="dim">Create the same policies in several clients at once. It starts with one canary client; if anything fails there, it stops and no other client is touched. Policies are created unassigned, so nobody is affected until they are assigned.</p>
    <details><summary>Choose policies and clients</summary>
      <div class="grid">
        <div class="card"><h4>Policies</h4><div class="pick">${tpls.map(t => `<label class="check"><input type="checkbox" data-fat="${esc(t.id)}"><span>${esc(t.name)}</span></label>`).join('')}</div></div>
        <div class="card"><h4>Clients</h4>${rows.map(r => `<label class="check"><input type="checkbox" data-fac="${esc(r.tenantId)}"><span>${esc(r.name)}</span></label>`).join('')}
          <label class="dim">Canary client (goes first)<select id="faCanary"><option value="">Choose one of the clients</option>${rows.map(r => `<option value="${esc(r.tenantId)}">${esc(r.name)}</option>`).join('')}</select></label></div>
      </div>
      <div class="row"><button class="act" id="faPreview">PREVIEW</button></div>
      <div id="faOut"></div>
    </details>`;
  const pick = () => ({
    templateIds: $$('[data-fat]:checked', box).map(i => i.dataset.fat),
    tenantIds: $$('[data-fac]:checked', box).map(i => i.dataset.fac),
    canaryTenantId: $('#faCanary').value,
  });
  $('#faPreview').onclick = async () => {
    const q = pick(), out = $('#faOut');
    if (!q.templateIds.length || !q.tenantIds.length) return toast('Choose at least one policy and one client', true);
    if (q.tenantIds.length > 1 && !q.canaryTenantId) return toast('Choose a canary client: a change to several clients starts with one', true);
    if (q.canaryTenantId && !q.tenantIds.includes(q.canaryTenantId)) return toast('The canary must be one of the chosen clients', true);
    out.innerHTML = '<p class="dim">Working out what would be created...</p>';
    let p;
    try { p = await api('/api/fleet/apply/preview', { method: 'POST', body: JSON.stringify(q) }); }
    catch (e) { out.innerHTML = errNote(e); return; }
    const n = (p.clients || []).length, total = (p.clients || []).reduce((a, c) => a + c.wouldCreate, 0);
    const cannot = (p.clients || []).some(c => c.failed);
    out.innerHTML = `<div class="note">${plural(total, 'policy', 'policies')} would be created across ${plural(n, 'client')}, starting with ${esc(p.clients?.[0]?.name || '')}.</div>
      ${cannot ? '<div class="note bad">Some policies cannot be made yet. Usually a client value is not filled in on DRIFT, or the console is not connected to Microsoft. Fix that first: if the canary has a failure, nothing else is touched.</div>' : ''}
      <div class="scroll"><table><thead><tr><th>Order</th><th>Client</th><th>Would create</th><th>Already there</th><th>Cannot be made</th></tr></thead><tbody>
      ${(p.clients || []).map((c, i) => `<tr><td>${i === 0 && q.canaryTenantId ? 'canary' : i + 1}</td><td>${esc(c.name)}</td><td>${c.wouldCreate}</td><td class="dim">${c.skipped}</td><td class="${c.failed ? 'c-bad' : 'dim'}">${c.failed}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="card"><label class="dim">Type the number of clients, <b>${n}</b>, to confirm<input id="faConfirm" autocomplete="off" inputmode="numeric"></label>
        <div class="row"><button class="danger" id="faApply" disabled>APPLY TO ${n} CLIENTS</button></div>
        ${state.status.readOnly ? '<div class="note">The console is in read-only mode, so it will not create anything. Preview still works.</div>' : ''}</div>
      <div id="faResult"></div>`;
    $('#faConfirm').oninput = (e) => { $('#faApply').disabled = state.status.readOnly || e.target.value.trim() !== String(n); };
    $('#faApply').onclick = async () => {
      $('#faApply').disabled = true;
      try {
        const r = await api('/api/fleet/apply', { method: 'POST', body: JSON.stringify({ ...q, hash: p.hash, confirm: true }) });
        $('#faResult').innerHTML = `<div class="note ${r.stoppedAtCanary ? 'bad' : 'ok'}">${r.stoppedAtCanary ? 'Stopped after the canary had a failure. No other client was touched.' : 'Applied to every chosen client.'}</div>
          <div class="scroll"><table><thead><tr><th>Client</th><th>Created</th><th>Already there</th><th>Failed</th><th>Detail</th></tr></thead><tbody>
          ${(r.clients || []).map(c => `<tr><td>${esc(c.name)}</td><td>${c.created}</td><td class="dim">${c.alreadyThere}</td><td class="${c.failed ? 'c-bad' : 'dim'}">${c.failed}</td><td class="mono-sm">${esc(c.detail || '')}</td></tr>`).join('')}
          </tbody></table></div>`;
      } catch (e) {
        $('#faResult').innerHTML = e.status === 409 ? '<div class="note bad">The choice or a client\'s values changed since the preview. Press PREVIEW again.</div>' : errNote(e, true);
      }
    };
  };
}

// ---------- drift ----------

async function renderDrift() {
  const el = $('#tab-drift');
  if (!tenantId()) { el.innerHTML = `<h2>DRIFT</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>DRIFT: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let d, tok;
  try {
    [d, tok] = await Promise.all([api(tpath('/drift')), api(tpath('/tokens'))]);
  } catch (e) { el.innerHTML = `<h2>DRIFT: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  const open = (d.open || []).slice().sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9) || a.name.localeCompare(b.name));
  const exceptions = d.exceptions || [];
  const tokens = tok.tokens || {};
  const keys = [...new Set([...(state.status.placeholders || []), ...Object.keys(tokens)])].sort();
  const extras = open.filter(f => f.class === 'extra');

  el.innerHTML = `<h2>DRIFT: ${esc(name)}</h2>
    <p class="dim">Drift is anything in this client that no longer matches the standard: a policy that is missing, switched off, or has different settings, and policies the standard does not know about. The console checks on a schedule; press CHECK NOW to check straight away.</p>
    <div class="row"><button class="act" id="driftCheck">CHECK NOW</button><span class="dim">Checking only reads the client. Nothing is changed.</span></div>
    <div id="driftCheckOut"></div>

    <h3>OPEN FINDINGS (${open.length})</h3>
    <p class="dim">Acknowledge a finding to say you have seen it, or snooze it until a date. Either way it stops counting on FLEET but stays listed here. Reopen puts it back.</p>
    ${open.length ? `<div class="scroll"><table><thead><tr><th>Severity</th><th>What</th><th>Policy</th><th>Detail</th><th>First seen</th><th>State</th><th></th></tr></thead><tbody>
      ${open.map(f => `<tr>
        <td><span class="chip ${sevChip[f.severity] || 'c-dim'}">${esc(sevWord[f.severity] || f.severity)}</span></td>
        <td>${esc(classWord[f.class] || f.class)}</td>
        <td>${esc(f.name)}</td>
        <td class="mono-sm">${esc(f.detail)}</td>
        <td class="dim">${when(f.firstSeen)}</td>
        <td>${findingState(f)}</td>
        <td class="row" style="margin:0">${f.state === 'new' || !f.state
          ? `<button class="ghost" data-fack="${esc(f.id)}">ACKNOWLEDGE</button><button class="ghost" data-fsnz="${esc(f.id)}">SNOOZE</button>`
          : `<button class="ghost" data-freo="${esc(f.id)}">REOPEN</button>`}</td></tr>`).join('')}
      </tbody></table></div>` : '<div class="note ok">Nothing open. Either everything matches, or no check has run yet for this client.</div>'}

    <h3>EXCEPTIONS (${exceptions.length})</h3>
    <p class="dim">An exception tells the console a difference is approved, so it stops being reported. Every exception needs a reason so it can be reviewed later.</p>
    ${exceptions.length ? `<div class="scroll"><table><thead><tr><th>Covers</th><th>Reason</th><th>Owner</th><th>Added</th><th>Ends</th><th></th></tr></thead><tbody>
      ${exceptions.map(x => `<tr>
        <td>${x.templateId.startsWith('extra:') ? `A policy not in the standard<div class="mono-sm">${esc(x.templateId)}</div>` : esc(tplName(x.templateId))}</td>
        <td>${esc(x.reason)}</td><td class="dim">${esc(x.owner)}</td>
        <td class="dim">${when(x.createdAt)}</td>
        <td class="dim">${x.expiresAt ? when(x.expiresAt) : 'no end date'}</td>
        <td><button class="ghost" data-exdel="${esc(x.id)}">DELETE</button></td></tr>`).join('')}
      </tbody></table></div>` : '<p class="dim">No exceptions for this client.</p>'}
    <div class="card">
      <h4>Add an exception</h4>
      <div class="form">
        <label>Policy it covers
          <select id="exTpl">
            <option value="">Choose a policy</option>
            ${extras.length ? `<optgroup label="Found in the client, not in the standard">${extras.map(f => `<option value="${esc(f.templateId)}">${esc(f.name)}</option>`).join('')}</optgroup>` : ''}
            <optgroup label="Policies in the standard">${state.templates.map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}</optgroup>
          </select></label>
        <label>Reason (required)<input id="exReason" placeholder="why this difference is approved"></label>
        <label>Owner<input id="exOwner" placeholder="you, if left empty"></label>
        <label>End date (optional)<input id="exEnd" type="date"></label>
      </div>
      <div class="row"><button class="act" id="exAdd">ADD EXCEPTION</button></div>
    </div>

    <h3>CLIENT VALUES</h3>
    <p class="dim">The standard has blanks that are different for every client, such as the id of the emergency access group. Fill them in here so checks compare the standard exactly as it would be deployed for ${esc(name)}. Leave a box empty if it does not apply.</p>
    <div class="grid">
      ${keys.map(k => `<div class="card"><h4>${esc(prettyKey(k))}</h4><div class="mono-sm">${esc(k)}</div>
        <input data-ctoken="${esc(k)}" value="${esc(tokens[k] || '')}" placeholder="not filled in" style="width:100%"></div>`).join('') || '<p class="dim">The standard has no blanks to fill.</p>'}
    </div>
    <div class="row"><button class="act" id="saveClientValues">SAVE CLIENT VALUES</button></div>`;

  $('#driftCheck').onclick = async (ev) => {
    const b = ev.currentTarget; b.disabled = true;
    $('#driftCheckOut').innerHTML = '<p class="dim">Checking the client, this can take a minute...</p>';
    try {
      const r = await api(tpath('/drift/check'), { method: 'POST' });
      // The check result has no JSON field names on the server side, so accept both spellings.
      const g = (k) => r[k] ?? r[k.charAt(0).toUpperCase() + k.slice(1)] ?? 0;
      const unchecked = g('unchecked') || [];
      await renderDrift();
      $('#driftCheckOut').innerHTML = `<div class="note ok">Check finished: ${plural(g('open'), 'finding')} open, ${g('opened')} new, ${g('resolved')} fixed since the last check, ${g('excepted')} silenced by exceptions.</div>
        ${unchecked.length ? `<div class="note">${plural(unchecked.length, 'policy', 'policies')} could not be checked because client values are not filled in: ${esc(unchecked.join(', '))}.</div>` : ''}`;
    } catch (e) { $('#driftCheckOut').innerHTML = errNote(e); b.disabled = false; }
  };
  const findingAct = async (id, action, payload, done) => {
    try { await api(`/api/findings/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: JSON.stringify(payload) }); toast(done); renderDrift(); }
    catch (e) { toast(/future date|past/i.test(e.message) ? 'Pick a date in the future.' : friendly(e).say, true); }
  };
  $$('[data-fack]', el).forEach(b => b.onclick = async () => {
    const note = await askNote('Acknowledge a finding', '<p>This records that you have seen it. It stops counting on FLEET but stays here until it is fixed.</p>', false);
    if (note !== null) findingAct(b.dataset.fack, 'acknowledge', { note: note.note }, 'Acknowledged');
  });
  $$('[data-fsnz]', el).forEach(b => b.onclick = async () => {
    const note = await askNote('Snooze a finding', '<p>The finding stops counting on FLEET until the date you pick, then comes back on its own.</p>', true);
    if (note !== null) findingAct(b.dataset.fsnz, 'snooze', { note: note.note, until: note.until }, 'Snoozed');
  });
  $$('[data-freo]', el).forEach(b => b.onclick = () => findingAct(b.dataset.freo, 'reopen', {}, 'Reopened'));
  $('#exAdd').onclick = async () => {
    const templateId = $('#exTpl').value, reason = $('#exReason').value.trim();
    if (!templateId) return toast('Choose the policy the exception covers', true);
    if (!reason) return toast('A reason is required, so the exception can be reviewed later', true);
    try {
      await api(tpath('/exceptions'), { method: 'POST', body: JSON.stringify({ templateId, reason, owner: $('#exOwner').value.trim(), expiresAt: $('#exEnd').value }) });
      toast('Exception added');
      renderDrift();
    } catch (e) {
      toast(/past/i.test(e.message) ? 'The end date has already passed. Pick a later date.' : friendly(e).say, true);
    }
  };
  $$('[data-exdel]', el).forEach(b => b.onclick = async () => {
    if (!await confirmAction('Delete an exception',
      `<p>The difference it covers will be reported again from the next check.</p><p class="note">Nothing in the client is changed.</p>`, 'DELETE')) return;
    try { await api('/api/exceptions/' + encodeURIComponent(b.dataset.exdel), { method: 'DELETE' }); toast('Exception deleted'); renderDrift(); }
    catch (e) { toastErr(e); }
  });
  $('#saveClientValues').onclick = async () => {
    const out = {};
    $$('[data-ctoken]', el).forEach(i => { const v = i.value.trim(); if (v) out[i.dataset.ctoken] = v; });
    try { await api(tpath('/tokens'), { method: 'PUT', body: JSON.stringify({ tokens: out }) }); toast('Client values saved'); }
    catch (e) { toastErr(e); }
  };
}

// ---------- impact ----------

const imp = {
  templateId: localStorage.getItem('pc.impactTpl') || '', tenant: null,
  overrides: {}, typed: {}, original: {}, res: null, sample: false, hideStale: true, seq: 0, err: null,
};

function renderImpact() {
  const el = $('#tab-impact');
  const tpls = state.templates.filter(t => t.kind === 'compliance-policies');
  if (!tenantId()) { el.innerHTML = `<h2>IMPACT</h2>${pickClientNote}`; return; }
  if (!tpls.length) { el.innerHTML = `<h2>IMPACT</h2><div class="note">There are no device compliance policies in the standard to preview.</div>`; return; }
  if (!tpls.some(t => t.id === imp.templateId)) imp.templateId = tpls[0].id;
  el.innerHTML = `<h2>IMPACT: WHO WILL THIS HIT</h2>
    <p class="dim">Pick a device compliance policy and see which of ${esc(state.tenant.name)}'s devices would pass it, which would fail and why, before anything is deployed. Switch settings on or off to try things out. This only reads the device list; nothing is changed in the client.</p>
    <div class="row"><label>Policy
      <select id="impTpl">${tpls.map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}</select></label>
      <button class="ghost" id="impReset">BACK TO THE POLICY AS WRITTEN</button></div>
    <div id="impOut"><p class="dim">Reading devices...</p></div>`;
  $('#impTpl').value = imp.templateId;
  $('#impTpl').onchange = (e) => { imp.templateId = e.target.value; localStorage.setItem('pc.impactTpl', imp.templateId); resetImpact(); };
  $('#impReset').onclick = resetImpact;
  if (imp.res && imp.tenant === tenantId() && imp.forTpl === imp.templateId) drawImpact(); else resetImpact();
}

function resetImpact() { imp.overrides = {}; imp.typed = {}; imp.original = {}; imp.res = null; fetchImpact(true); }

async function fetchImpact(first = false) {
  const seq = ++imp.seq, tid = tenantId(), tpl = imp.templateId;
  try {
    const r = await api(`/api/tenants/${encodeURIComponent(tid)}/impact`, { method: 'POST', body: JSON.stringify({ templateId: tpl, overrides: imp.overrides }) });
    if (seq !== imp.seq) return; // a newer request is on its way
    imp.res = r.result; imp.sample = !!r.sample; imp.tenant = tid; imp.forTpl = tpl; imp.err = null;
    if (first) (r.result.settings || []).forEach(s => { if (s.on) imp.original[s.key] = s.value; });
  } catch (e) {
    if (seq !== imp.seq) return;
    imp.err = e; imp.res = null;
  }
  if ($('#tab-impact').classList.contains('on')) drawImpact();
}

const verdictWord = { ok: 'Compliant', fail: 'Would fail', unknown: 'Cannot tell', stale: 'Not seen' };
const verdictCls = { ok: 'c-ok', fail: 'c-bad', unknown: 'c-warn', stale: 'c-dim' };

function namesLine(names = []) {
  if (!names.length) return '';
  return ': ' + esc(names.slice(0, 4).join(', ')) + (names.length > 4 ? ` and ${names.length - 4} more` : '');
}

function settingImpactLine(s) {
  const who = (n) => plural(n, 'device');
  if (s.hypothetical) {
    const at = s.kind === 'version' ? ` at ${esc(imp.typed[s.key] || s.recommended)}` : '';
    const what = s.fails ? `${who(s.fails)} would fail${namesLine(s.failNames)}` : 'every device would pass';
    const off = s.key in imp.original ? 'Switched off in this preview.' : 'Not in the policy.';
    return `<div class="mono-sm">${off} If switched on${at}: ${what}${s.unknown ? `, ${s.unknown} cannot be checked` : ''}.</div>`;
  }
  if (!s.fails && !s.unknown) return `<div class="mono-sm c-ok">Every active device passes this one.</div>`;
  return `<div class="mono-sm ${s.fails ? 'c-bad' : 'c-warn'}">${s.fails ? `${who(s.fails)} would fail${namesLine(s.failNames)}` : ''}${s.fails && s.unknown ? '. ' : ''}${s.unknown ? `${who(s.unknown)} cannot be checked` : ''}.</div>`;
}

function fleetLine(s) {
  const f = s.fleet || {};
  if (s.kind === 'version') {
    return f.oldest ? `Your devices: oldest ${esc(f.oldest)}, middle ${esc(f.median)}, newest ${esc(f.newest)}.` : 'No device has reported its version.';
  }
  return `Your devices: ${f.yes} meet it, ${f.no} do not, ${f.unknown} have not reported.`;
}

function drawImpact() {
  const out = $('#impOut');
  if (!out) return;
  if (imp.err) { out.innerHTML = errNote(imp.err, true); return; }
  const r = imp.res;
  if (!r) { out.innerHTML = '<p class="dim">Reading devices...</p>'; return; }
  const c = r.counts || {};
  const total = (c.judged || 0) + (c.notSeen || 0);
  const pct = (n) => total ? (100 * n / total).toFixed(1) + '%' : '0';
  const o = r.oldestActiveDevice;
  const settings = r.settings || [];
  const notPred = r.notPredictable || [];
  const devices = (r.devices || []).filter(d => !(imp.hideStale && d.verdict === 'stale'));

  out.innerHTML = `
    ${imp.sample ? '<div class="note bad sample"><b>SAMPLE DATA, nothing real.</b> These devices are invented so the screen can be tried out. Connect a real client to see its devices.</div>' : ''}
    <p class="dim">This policy is for ${esc(r.platform)} devices, so only those are counted.</p>
    <div class="kpis">
      <div class="kpi"><b class="c-ok">${c.compliant ?? 0}</b><span>would be compliant</span></div>
      <div class="kpi"><b class="c-bad">${c.fail ?? 0}</b><span>would fail</span></div>
      <div class="kpi"><b class="c-warn">${c.cannotTell ?? 0}</b><span>cannot tell yet</span></div>
      <div class="kpi"><b class="c-dim">${c.notSeen ?? 0}</b><span>not seen in 30+ days</span></div>
    </div>
    <div class="impbar" aria-hidden="true"><i class="b-ok" style="width:${pct(c.compliant || 0)}"></i><i class="b-warn" style="width:${pct(c.cannotTell || 0)}"></i><i class="b-bad" style="width:${pct(c.fail || 0)}"></i><i class="b-dim" style="width:${pct(c.notSeen || 0)}"></i></div>
    <p class="dim">${c.judged ? `${c.percentCompliant}% of the ${plural(c.judged, 'active device')} would be compliant.` : 'No active devices to judge.'}
      ${o ? `Oldest active device: <b>${esc(o.name)}</b> on ${esc(o.osVersion)}.` : ''}</p>

    <h3>SETTINGS IN THIS POLICY</h3>
    <p class="dim">Every setting is optional. Switch one on or off and the counts and the device list follow.</p>
    <div class="sets">
      ${settings.map(s => `<div class="set">
        <label class="check"><input type="checkbox" data-iset="${esc(s.key)}" ${s.on ? 'checked' : ''}>
          <span><b>${esc(s.label)}</b>${s.hypothetical ? ' <span class="chip c-dim">off</span>' : ' <span class="chip c-ok">on</span>'}${(s.key in imp.original) === s.on ? '' : ' <span class="chip c-info">changed in this preview</span>'}</span></label>
        ${s.kind === 'version' ? `<div class="row tight"><label class="dim">Version at least
          <input data-iver="${esc(s.key)}" value="${esc(imp.typed[s.key] ?? (s.on ? s.value : s.recommended) ?? '')}" size="16"></label>
          <span class="mono-sm">Recommended: ${esc(s.recommended)}</span></div>` : ''}
        <div class="mono-sm">${fleetLine(s)}${s.kind === 'version' && o ? ` Oldest active device: ${esc(o.name)} on ${esc(o.osVersion)}.` : ''}</div>
        ${settingImpactLine(s)}
      </div>`).join('')}
    </div>

    <h3>DEVICES (${devices.length})</h3>
    <label class="check dim"><input type="checkbox" id="impHideStale" ${imp.hideStale ? 'checked' : ''}>
      <span>Leave out devices not seen in 30+ days (they are counted above, not judged)</span></label>
    <div class="scroll"><table><thead><tr><th>Device</th><th class="hide-sm">User</th><th>Result</th><th>Why</th></tr></thead><tbody>
      ${devices.map(d => `<tr><td>${esc(d.name)}<div class="mono-sm">${esc(d.osVersion)}</div></td>
        <td class="hide-sm dim">${esc(d.user)}</td>
        <td><span class="chip ${verdictCls[d.verdict] || 'c-dim'}">${esc(verdictWord[d.verdict] || d.verdict)}</span></td>
        <td>${(d.reasons || []).length ? d.reasons.map(x => `<div class="${verdictCls[d.verdict] || ''} mono-sm">${esc(x)}</div>`).join('') : '<span class="dim">Meets every setting that is switched on</span>'}</td></tr>`).join('')
        || '<tr><td colspan="4" class="dim">No devices to show.</td></tr>'}
    </tbody></table></div>

    <h3>SETTINGS THE CONSOLE CANNOT PREDICT YET</h3>
    ${notPred.length ? `<p class="dim">These are switched on in the policy, but the device list does not show whether a device meets them, so they are not part of the counts above. A device that passes here could still fail on one of these.</p>
      <ul class="plain">${notPred.map(k => `<li class="mono-sm">${esc(k)}</li>`).join('')}</ul>` : '<p class="dim">None. Every setting switched on in this policy is counted above.</p>'}`;

  $$('[data-iset]', out).forEach(cb => cb.onchange = () => {
    const s = settings.find(x => x.key === cb.dataset.iset);
    if (!cb.checked) imp.overrides[s.key] = null;
    else if (s.kind === 'version') imp.overrides[s.key] = (imp.typed[s.key] || imp.original[s.key] || s.recommended);
    else imp.overrides[s.key] = true;
    fetchImpact();
  });
  $$('[data-iver]', out).forEach(inp => inp.onchange = () => {
    const key = inp.dataset.iver, v = inp.value.trim();
    if (v && !/^\d+(\.\d+)*$/.test(v)) { toast('A version is numbers separated by dots, like 10.0.22621', true); return; }
    imp.typed[key] = v;
    const s = settings.find(x => x.key === key);
    if (s.on || v) { imp.overrides[key] = v || null; fetchImpact(); }
  });
  $('#impHideStale').onchange = (e) => { imp.hideStale = e.target.checked; drawImpact(); };
}

// ---------- consent ----------

const kindWord = {
  tenant: 'Basic connection', 'conditional-access': 'Conditional Access (sign-in rules)',
  'configuration-policies': 'Intune device policies', score: 'Microsoft Secure Score', apps: 'Apps',
  enrollment: 'Device enrollment', devices: 'Device list', groups: 'Groups', audit: 'Audit log (who changed what)',
};
const kindState = { granted: ['c-ok', 'granted'], partial: ['c-warn', 'partly granted'], none: ['c-dim', 'not granted'] };
const profileWord = { read: 'READ ACCESS (look, never change)', write: 'CHANGE ACCESS (deploy and fix)' };

async function renderConsent() {
  const el = $('#tab-consent');
  if (!tenantId()) { el.innerHTML = `<h2>CONSENT</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>CONSENT: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let c;
  try { c = await api(tpath('/consent')); } catch (e) { el.innerHTML = `<h2>CONSENT: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  el.innerHTML = `<h2>CONSENT: ${esc(name)}</h2>
    <p class="dim">Consent is the client's permission for this console to read or change their Microsoft 365 settings. Each part of the console needs its own permissions, so one refused permission only stops that part.</p>
    <div class="note">Granting permissions is a change to the client's own Microsoft tenant, so it only happens after a preview and after you type the client's name.</div>
    ${['read', 'write'].map(p => {
      const prof = c[p] || { configured: false, kinds: [] };
      return `<h3>${profileWord[p]}</h3>
      ${prof.configured ? '' : `<div class="note">No app is set up for this kind of access yet, so there is nothing to grant. The kinds below show what it would need.</div>`}
      <div class="scroll"><table><thead><tr><th>Part of the console</th><th>State</th><th>Still missing</th></tr></thead><tbody>
        ${(prof.kinds || []).map(k => `<tr><td>${esc(kindWord[k.kind] || k.kind)}</td>
          <td><span class="chip ${(kindState[k.state] || ['c-dim'])[0]}">${esc((kindState[k.state] || [, k.state])[1])}</span></td>
          <td class="mono-sm">${esc((k.missing || []).join(', ')) || '<span class="dim">nothing</span>'}</td></tr>`).join('')}
      </tbody></table></div>
      <p class="dim">This is the state the console last saw. PREVIEW reads the client again.</p>
      <div class="row"><button class="act" data-cplan="${p}" ${prof.configured ? '' : 'disabled'}>PREVIEW</button></div>
      <div id="cplan-${p}"></div>`;
    }).join('')}`;
  $$('[data-cplan]', el).forEach(b => b.onclick = () => consentPreview(b.dataset.cplan, b));
}

async function consentPreview(profile, btn) {
  const out = $('#cplan-' + profile);
  btn.disabled = true;
  out.innerHTML = '<p class="dim">Reading the client...</p>';
  let plan;
  try { plan = await api(tpath('/consent/plan'), { method: 'POST', body: JSON.stringify({ profile }) }); }
  catch (e) { out.innerHTML = errNote(e); btn.disabled = false; return; }
  btn.disabled = false;
  const name = state.tenant.name;
  const ro = state.status.readOnly;
  out.innerHTML = `
    <div class="note ${plan.missing ? '' : 'ok'}">${plan.missing ? `${plural(plan.missing, 'permission')} would be granted.` : 'Everything this access needs is already granted. Nothing to do.'}</div>
    <div class="scroll"><table><thead><tr><th>Permission</th><th>Why it is wanted</th><th>State</th></tr></thead><tbody>
      ${(plan.items || []).map(i => `<tr><td class="mono-sm">${esc(i.permission)}</td><td>${esc(i.why)}</td>
        <td><span class="chip ${i.granted ? 'c-ok' : 'c-warn'}">${i.granted ? 'already granted' : 'missing'}</span></td></tr>`).join('')}
    </tbody></table></div>
    ${(plan.unresolved || []).length ? `<div class="note">Microsoft does not offer ${plan.unresolved.length === 1 ? 'one of these permissions' : plan.unresolved.length + ' of these permissions'} under that name, so ${plan.unresolved.length === 1 ? 'it' : 'they'} will be skipped: ${esc(plan.unresolved.join(', '))}.</div>` : ''}
    ${plan.missing ? `<div class="card">
      <h4>Grant these permissions in ${esc(name)}</h4>
      ${ro ? '<div class="note">The console is in read-only mode, so it will not grant anything. Preview still works.</div>' : ''}
      <label class="dim">Type the client's name, <b>${esc(name)}</b>, to confirm
        <input id="cconfirm-${profile}" autocomplete="off" style="width:100%" ${ro ? 'disabled' : ''}></label>
      <div class="row"><button class="danger" id="capply-${profile}" disabled>APPLY</button></div>
    </div>` : ''}
    <div id="cresult-${profile}"></div>`;
  const box = $('#cconfirm-' + profile), apply = $('#capply-' + profile);
  if (!box) return;
  box.oninput = () => { apply.disabled = ro || box.value.trim() !== name; };
  apply.onclick = async () => {
    apply.disabled = true; box.disabled = true;
    const res = $('#cresult-' + profile);
    res.innerHTML = '<p class="dim">Granting, then checking it worked...</p>';
    try {
      const r = await api(tpath('/consent/apply'), { method: 'POST', body: JSON.stringify({ profile, hash: plan.hash, confirm: true }) });
      res.innerHTML = consentResult(r);
      toast('Permissions granted. See RUNS for the record.');
    } catch (e) {
      const msg = e.status === 409
        ? '<div class="note bad">The client changed since the preview, so nothing was granted from it. Press PREVIEW again.</div>'
        : errNote(e, true);
      res.innerHTML = msg + (e.data?.result ? consentResult(e.data.result) : '');
      box.disabled = false;
    }
  };
}

function consentResult(r) {
  const word = { granted: ['c-ok', 'granted now'], already: ['c-dim', 'was already granted'], failed: ['c-bad', 'failed'] };
  const v = r.verified;
  return `<h3>WHAT HAPPENED</h3>
    <div class="scroll"><table><thead><tr><th>Permission</th><th>Outcome</th><th>Detail</th></tr></thead><tbody>
      ${(r.outcomes || []).map(o => `<tr><td class="mono-sm">${esc(o.permission)}</td>
        <td><span class="chip ${(word[o.result] || ['c-dim'])[0]}">${esc((word[o.result] || [, o.result])[1])}</span></td>
        <td class="mono-sm">${esc(o.detail || '')}</td></tr>`).join('') || '<tr><td colspan="3" class="dim">Nothing was attempted.</td></tr>'}
    </tbody></table></div>
    ${v ? `<div class="note ${v.missing ? 'bad' : 'ok'}">Checked afterwards: ${v.missing ? `${plural(v.missing, 'permission')} still missing.` : 'every permission is now in place.'}</div>` : '<div class="note">The console could not check the result afterwards.</div>'}`;
}

// ---------- assess ----------

const assessWord = {
  matches: ['c-ok', 'matches'], drifted: ['c-warn', 'different settings'], equivalent: ['c-info', 'done by another policy'],
  missing: ['c-dim', 'missing'], error: ['c-bad', 'could not check'],
};
function assessExplain(it) {
  const parts = [];
  switch (it.state) {
    case 'matches': parts.push('The client has this policy with the same settings.'); break;
    case 'drifted': parts.push(`The client has this policy, but ${plural(it.changeCount || 0, 'setting is', 'settings are')} different.`); break;
    case 'equivalent': parts.push(`Already done by the client's own policy${it.coveredBy ? ` "${esc(it.coveredBy)}"` : ''}${it.exact ? '' : ', which covers more'}.`); break;
    case 'missing': parts.push('No policy with this name was found. Check whether the client has the same settings under another name before deploying a copy.'); break;
    case 'error': parts.push('Could not be checked, usually because a client value is not filled in on DRIFT or the console may not read this kind of policy.'); break;
  }
  if (it.note) parts.push(esc(it.note));
  return parts.join(' ');
}

const assessState = { baseline: '', res: null, forTenant: null, baselines: null };

async function renderAssess() {
  const el = $('#tab-assess');
  if (!tenantId()) { el.innerHTML = `<h2>ASSESS</h2>${pickClientNote}`; return; }
  if (!assessState.baselines) {
    try { assessState.baselines = await api('/api/assessment/baselines'); }
    catch (e) { el.innerHTML = `<h2>ASSESS</h2>${errNote(e, true)}`; return; }
  }
  if (assessState.forTenant !== tenantId()) assessState.res = null;
  el.innerHTML = `<h2>ASSESS: ${esc(state.tenant.name)}</h2>
    <p class="dim">Measure this client against a baseline and see what it already has and what is missing.</p>
    <div class="note ok">This only reads the client. Nothing is deployed or changed.</div>
    <div class="row"><label>Baseline
      <select id="assessBase">${assessState.baselines.map(b => `<option value="${esc(b.id)}">${esc(b.label)} (${b.count} policies)</option>`).join('')}</select></label>
      <button class="act" id="assessRun">ASSESS</button></div>
    <p class="dim">A policy can show as missing when the client has the same settings under a different policy name. The console matches by name, so check before deploying a copy.</p>
    <div id="assessOut"></div>`;
  $('#assessBase').value = assessState.baseline;
  $('#assessBase').onchange = (e) => { assessState.baseline = e.target.value; };
  $('#assessRun').onclick = async (ev) => {
    const b = ev.currentTarget; b.disabled = true;
    $('#assessOut').innerHTML = '<p class="dim">Reading the client, this can take a minute...</p>';
    try {
      const tok = await api(tpath('/tokens')).catch(() => ({ tokens: {} }));
      assessState.res = await api(tpath('/compare'), { method: 'POST', body: JSON.stringify({ baseline: assessState.baseline, tokens: tok.tokens || {} }) });
      assessState.forTenant = tenantId();
      drawAssess();
    } catch (e) { $('#assessOut').innerHTML = errNote(e); }
    b.disabled = false;
  };
  if (assessState.res) drawAssess();
}

function drawAssess() {
  const r = assessState.res, items = r.items || [];
  const counts = {};
  items.forEach(i => { counts[i.state] = (counts[i.state] || 0) + 1; });
  const order = ['matches', 'equivalent', 'drifted', 'missing', 'error'];
  const sorted = items.slice().sort((a, b) => order.indexOf(b.state) - order.indexOf(a.state));
  $('#assessOut').innerHTML = `
    <div class="kpis">${order.filter(s => counts[s]).map(s => `<div class="kpi"><b class="${assessWord[s][0]}">${counts[s]}</b><span>${assessWord[s][1]}</span></div>`).join('') || '<p class="dim">The baseline has no policies.</p>'}</div>
    ${(r.unreadable || []).length ? `<div class="note">The console is not allowed to read some kinds of policy in this client (${esc(r.unreadable.join(', '))}), so those show as could not check rather than missing. CONSENT shows what to grant.</div>` : ''}
    <div class="scroll"><table><thead><tr><th>Policy</th><th>State</th><th>What this means</th></tr></thead><tbody>
      ${sorted.map(it => `<tr><td>${esc(it.template?.name)}</td>
        <td><span class="chip ${(assessWord[it.state] || ['c-dim'])[0]}">${esc((assessWord[it.state] || [, it.state])[1])}</span></td>
        <td>${assessExplain(it)}</td></tr>`).join('')}
    </tbody></table></div>`;
}

// ---------- build out ----------

const stepType = {
  deploy: ['c-ok', 'the console does it'], manual: ['c-warn', 'you do it'],
  gate: ['c-info', 'you confirm it'], check: ['c-dim', 'the console checks'],
};
const stepStateWord = { pending: ['c-dim', 'to do'], done: ['c-ok', 'done'], skipped: ['c-dim', 'skipped'], failed: ['c-bad', 'failed'] };
const bo = { answers: null, preview: null };

function questionnaire(a) {
  a = a || { platforms: ['Windows'], ownership: 'corporate' };
  const has = (p) => (a.platforms || []).includes(p);
  const own = a.ownership || 'corporate';
  return `<div class="card">
    <h4>About this client</h4>
    <p class="dim">Which devices do they use?</p>
    <div class="row">${['Windows', 'macOS', 'iOS', 'Android'].map(p => `<label class="check"><input type="checkbox" data-qplat="${p}" ${has(p) ? 'checked' : ''}><span>${p}</span></label>`).join('')}</div>
    <p class="dim">Who owns the phones and tablets?</p>
    <div class="row">${[['corporate', 'the company'], ['byod', 'the staff (personal phones)'], ['both', 'both']].map(([v, l]) =>
      `<label class="check"><input type="radio" name="qown" value="${v}" ${own === v ? 'checked' : ''}><span>${l}</span></label>`).join('')}</div>
    <label class="check"><input type="checkbox" id="qEdr" ${a.thirdPartyEDR ? 'checked' : ''}><span>They use another company's antivirus or endpoint protection, not Microsoft Defender</span></label>
    <label class="check"><input type="checkbox" id="qRmm" ${a.rmmPatching ? 'checked' : ''}><span>A management tool already installs their Windows updates</span></label>
    <label class="check"><input type="checkbox" id="qReg" ${a.regulated ? 'checked' : ''}><span>They are regulated (for example HIPAA or CMMC)</span></label>
    <label class="check"><input type="checkbox" id="qBrown" ${a.brownfield ? 'checked' : ''}><span>Their Microsoft 365 already has policies set up</span></label>
    <div class="row"><button class="act" id="qPreview">SHOW THE PLAN</button></div>
  </div>`;
}

function readAnswers() {
  return {
    platforms: $$('[data-qplat]:checked').map(i => i.dataset.qplat),
    ownership: $('input[name=qown]:checked')?.value || 'corporate',
    thirdPartyEDR: $('#qEdr').checked, rmmPatching: $('#qRmm').checked,
    regulated: $('#qReg').checked, brownfield: $('#qBrown').checked,
  };
}

async function renderBuildout() {
  const el = $('#tab-buildout');
  if (!tenantId()) { el.innerHTML = `<h2>BUILD OUT</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>BUILD OUT: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let list;
  try { list = await api(tpath('/buildouts')); } catch (e) { el.innerHTML = `<h2>BUILD OUT: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  const cur = list[0];
  el.innerHTML = `<h2>BUILD OUT: ${esc(name)}</h2>
    <p class="dim">A build out is the ordered list of everything needed to bring a client up to the standard. Answer a few questions, check the plan, save it, then work through it step by step.</p>
    ${cur ? `<div id="boPlan"></div><details><summary>Start a new plan for this client</summary>${questionnaire(bo.answers)}<div id="boPreview"></div></details>`
          : `${questionnaire(bo.answers)}<div id="boPreview"></div>`}`;
  $('#qPreview').onclick = buildPreview;
  if (bo.preview && bo.preview.tenant === tenantId()) drawBuildPreview();
  if (cur) drawBuildout(cur);
}

async function buildPreview() {
  const a = readAnswers();
  if (!a.platforms.length) return toast('Pick at least one kind of device', true);
  bo.answers = a;
  $('#boPreview').innerHTML = '<p class="dim">Working out the plan...</p>';
  try {
    const r = await api('/api/buildplan/preview', { method: 'POST', body: JSON.stringify({ answers: a }) });
    bo.preview = { tenant: tenantId(), plan: r.plan, answers: r.answers };
    drawBuildPreview();
  } catch (e) { $('#boPreview').innerHTML = errNote(e); }
}

function drawBuildPreview() {
  const p = bo.preview.plan, c = p.counts || {};
  $('#boPreview').innerHTML = `<h3>THE PLAN</h3>
    <div class="note">${plural(c.steps || 0, 'step')}: ${c.deploy || 0} the console does, ${c.manual || 0} done by a person, ${plural(c.templates || 0, 'policy', 'policies')} in all. Nothing happens until you save it and run each step.</div>
    ${(p.notes || []).map(n => `<p class="dim">${esc(n)}</p>`).join('')}
    <ol class="steps">${(p.steps || []).map(s => `<li><b>${esc(s.title)}</b> <span class="chip ${(stepType[s.type] || ['c-dim'])[0]}">${esc((stepType[s.type] || [, s.type])[1])}</span>
      <div class="mono-sm">${esc(s.why)}</div></li>`).join('')}</ol>
    <div class="row"><button class="act" id="boSave">SAVE PLAN</button><span class="dim">Saving only stores the plan in this console. Nothing changes in the client.</span></div>`;
  $('#boSave').onclick = async () => {
    try {
      await api(tpath('/buildouts'), { method: 'POST', body: JSON.stringify({ answers: bo.preview.answers }) });
      toast('Plan saved'); bo.preview = null; renderBuildout();
    } catch (e) { toastErr(e); }
  };
}

// Planner: post the plan once, then it keeps itself up to date as steps change.
async function drawPlannerRow(b, ro) {
  const row = $('#boPlanner');
  if (!row) return;
  let ps, pv;
  try {
    ps = await api('/api/planner/status');
    if (!ps.configured) { row.innerHTML = '<span class="dim">Planner is not connected to this console yet, so use the download above.</span>'; return; }
    pv = await api(`/api/buildouts/${encodeURIComponent(b.id)}/planner/preview`, { method: 'POST', body: '{}' });
  } catch (e) { row.innerHTML = errNote(e); return; }
  const todo = pv.wouldCreate + pv.wouldUpdate;
  const word = pv.posted ? 'UPDATE PLANNER' : 'POST TO PLANNER';
  row.innerHTML = `<button class="act" id="boPost" ${ro ? 'disabled' : ''}>${word}</button>
    <span class="dim">${pv.posted ? (todo ? `${plural(todo, 'task')} out of date in Planner. It also updates by itself when a step changes.` : 'Planner is up to date. It updates by itself when a step changes.')
      : `Creates ${plural(pv.wouldCreate, 'task')} in Planner (${ps.mode}). Nothing in the client changes.`}</span>`;
  $('#boPost').onclick = async () => {
    try {
      const r = await api(`/api/buildouts/${encodeURIComponent(b.id)}/planner/sync`, { method: 'POST', body: '{}' });
      const extra = [(r.completedInPlanner || []).length && `${r.completedInPlanner.length} already ticked off in Planner`, (r.removedInPlanner || []).length && `${r.removedInPlanner.length} deleted in Planner and left deleted`, (r.failed || []).length && `${r.failed.length} failed`].filter(Boolean);
      toast(`Planner: ${r.created} created, ${r.updated} updated${extra.length ? ', ' + extra.join(', ') : ''}`, !!(r.failed || []).length);
      drawPlannerRow(b, ro);
    } catch (e) { toastErr(e); }
  };
}

function drawBuildout(b) {
  const box = $('#boPlan'), name = state.tenant.name, ro = state.status.readOnly;
  const pr = b.progress || { done: 0, total: 0 };
  box.innerHTML = `<h3>SAVED PLAN, ${pr.done} OF ${pr.total} STEPS FINISHED</h3>
    <div class="impbar"><i class="b-ok" style="width:${pr.total ? 100 * pr.done / pr.total : 0}%"></i></div>
    <p class="dim">Saved by ${esc(b.createdBy)} ${when(b.createdAt)}. <a href="/api/buildouts/${encodeURIComponent(b.id)}/planner" download>Download Planner tasks</a> if you would rather import them by hand.</p>
    <div id="boPlanner" class="row tight"></div>
    <div class="note">Deploy steps create policies <b>unassigned</b>, so nobody is affected until they are assigned, and Conditional Access policies start in <b>report-only</b>, so they watch and do not block anyone.</div>
    <ol class="steps">${(b.steps || []).map(s => {
      const st = s.progress?.state || 'pending', [tc, tw] = stepType[s.type] || ['c-dim', s.type];
      const finished = st === 'done' || st === 'skipped';
      return `<li class="${finished ? 'finished' : ''}">
        <b>${esc(s.title)}</b> <span class="chip ${tc}">${esc(tw)}</span> <span class="chip ${(stepStateWord[st] || ['c-dim'])[0]}">${esc((stepStateWord[st] || [, st])[1])}</span>
        <div class="mono-sm">${esc(s.why)}</div>
        ${(s.notes || []).map(n => `<div class="mono-sm">${esc(n)}</div>`).join('')}
        ${(s.blockedBy || []).length && !finished ? `<div class="mono-sm c-warn">Waits for: ${esc(s.blockedBy.join('; '))}</div>` : ''}
        ${s.progress?.by ? `<div class="mono-sm">${esc(st === 'skipped' ? 'Skipped' : 'Marked')} by ${esc(s.progress.by)} ${when(s.progress.at)}${s.progress.note ? `: ${esc(s.progress.note)}` : ''}${s.progress.detail ? `. ${esc(s.progress.detail)}` : ''}</div>` : ''}
        ${finished ? '' : `<div class="row tight">
          ${s.type === 'deploy' ? `<button class="act" data-spre="${esc(s.id)}" ${s.ready ? '' : 'disabled'}>PREVIEW</button>`
            : `<button class="act" data-sdone="${esc(s.id)}" data-stype="${esc(s.type)}" ${s.ready ? '' : 'disabled'}>MARK DONE</button>`}
          <button class="ghost" data-sskip="${esc(s.id)}">SKIP</button></div>
          <div id="sout-${esc(s.id)}"></div>`}
      </li>`;
    }).join('')}</ol>`;

  drawPlannerRow(b, ro);
  const step = (id, action, payload) => api(`/api/buildouts/${encodeURIComponent(b.id)}/steps/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: JSON.stringify(payload || {}) });
  $$('[data-sdone]', box).forEach(btn => btn.onclick = async () => {
    const gate = btn.dataset.stype === 'gate';
    const n = await askNote('Mark a step done', gate ? '<p>Say what you checked. This step needs a note.</p>' : '<p>This records that the step is finished and who finished it.</p>', false, gate);
    if (n === null) return;
    try { await step(btn.dataset.sdone, 'complete', { note: n.note }); toast('Step done'); renderBuildout(); } catch (e) { toastErr(e); }
  });
  $$('[data-sskip]', box).forEach(btn => btn.onclick = async () => {
    const n = await askNote('Skip a step', '<p>Say why this step is not needed. The reason goes in the handover report.</p>', false, true);
    if (n === null) return;
    try { await step(btn.dataset.sskip, 'skip', { reason: n.note }); toast('Step skipped'); renderBuildout(); } catch (e) { toastErr(e); }
  });
  $$('[data-spre]', box).forEach(btn => btn.onclick = async () => {
    const id = btn.dataset.spre, out = $('#sout-' + id);
    out.innerHTML = '<p class="dim">Working out what would be created...</p>';
    let p;
    try { p = await step(id, 'preview'); } catch (e) { out.innerHTML = errNote(e); return; }
    const would = (p.items || []).filter(i => i.result === 'preview').length;
    out.innerHTML = `<div class="scroll"><table><thead><tr><th>Policy</th><th>What would happen</th></tr></thead><tbody>
      ${(p.items || []).map(i => `<tr><td>${esc(i.name)}</td><td class="mono-sm ${i.result === 'failed' ? 'c-bad' : ''}">${esc(i.detail || i.result)}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="card"><p>${plural(would, 'policy', 'policies')} would be created in ${esc(name)}, unassigned, with Conditional Access in report-only.</p>
        ${ro ? '<div class="note">The console is in read-only mode, so it will not create anything. Preview still works.</div>' : ''}
        <label class="dim">Type the client's name, <b>${esc(name)}</b>, to run this step<input data-sconf autocomplete="off" style="width:100%"></label>
        <div class="row"><button class="danger" data-srun disabled>RUN</button></div></div>
      <div data-sres></div>`;
    const conf = $('[data-sconf]', out), run = $('[data-srun]', out);
    conf.oninput = () => { run.disabled = ro || conf.value.trim() !== name; };
    run.onclick = async () => {
      run.disabled = true;
      try {
        const r = await step(id, 'run', { hash: p.hash, confirm: true });
        toast(r.state === 'done' ? 'Step finished' : 'Some policies failed. See the step for details.', r.state !== 'done');
        renderBuildout();
      } catch (e) { $('[data-sres]', out).innerHTML = errNote(e, true); run.disabled = false; }
    };
  });
}

// ---------- client profile and tailoring ----------

const tailorWord = { included: ['c-ok', 'included'], modified: ['c-info', 'changed for this client'], excluded: ['c-dim', 'left out'] };

async function renderProfile() {
  const el = $('#tab-profile');
  if (!tenantId()) { el.innerHTML = `<h2>CLIENT PROFILE</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>CLIENT PROFILE: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let p, tl, ovs;
  try { [p, tl, ovs] = await Promise.all([api(tpath('/profile')), api(tpath('/tailoring')), api(tpath('/overlays'))]); }
  catch (e) { el.innerHTML = `<h2>CLIENT PROFILE: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  const rows = tl.rows || [], counts = tl.counts || {};
  const ovFor = (id) => (ovs || []).filter(o => o.templateId === id);
  const flag = (id, on, text) => `<label class="check"><input type="checkbox" id="${id}" ${on ? 'checked' : ''}><span>${text}</span></label>`;
  el.innerHTML = `<h2>CLIENT PROFILE: ${esc(name)}</h2>
    <p class="dim">The profile describes this client so the standard fits them. Tailoring is where single policies are left out or changed for this client, each with a reason someone can review later.</p>
    <div class="card"><h4>Profile</h4>
      <label class="dim">Name prefix, put in front of every policy name created in this client<input id="pfPrefix" value="${esc(p.namePrefix || '')}" placeholder="for example ACME | " style="width:100%"></label>
      ${flag('pfEdr', p.thirdPartyEDR, "They use another company's antivirus or endpoint protection, not Microsoft Defender")}
      ${flag('pfRmm', p.rmmPatching, 'A management tool already installs their Windows updates')}
      ${flag('pfReg', p.regulated, 'They are regulated (for example HIPAA or CMMC)')}
      ${flag('pfByod', p.byod, 'Staff use their own phones')}
      <p class="dim">Devices they use</p>
      <div class="row">${['Windows', 'macOS', 'iOS', 'Android'].map(x => `<label class="check"><input type="checkbox" data-pfplat="${x}" ${(p.platforms || []).includes(x) ? 'checked' : ''}><span>${x}</span></label>`).join('')}</div>
      <label class="dim">Notes<input id="pfNotes" value="${esc(p.notes || '')}" style="width:100%"></label>
      <div class="row"><button class="act" id="pfSave">SAVE PROFILE</button><span class="dim">Saved in this console only. Nothing changes in the client.</span></div>
    </div>

    <h3>TAILORING</h3>
    <div class="kpis">${['included', 'modified', 'excluded'].map(s => `<div class="kpi"><b class="${tailorWord[s][0]}">${counts[s] || 0}</b><span>${tailorWord[s][1]}</span></div>`).join('')}</div>
    <div class="scroll"><table><thead><tr><th>Policy</th><th>State</th><th>Why</th><th></th></tr></thead><tbody>
      ${rows.map(r => `<tr><td>${esc(r.name)}<div class="mono-sm">${esc(r.category)}</div></td>
        <td><span class="chip ${(tailorWord[r.state] || ['c-dim'])[0]}">${esc((tailorWord[r.state] || [, r.state])[1])}</span></td>
        <td class="mono-sm">${esc(r.reason || '')}${r.owner ? ` (${esc(r.owner)})` : ''}</td>
        <td>${ovFor(r.templateId).map(o => `<button class="ghost" data-ovdel="${esc(o.id)}">DELETE ${o.op === 'exclude' ? 'LEAVE OUT' : 'CHANGE'}</button>`).join(' ')}</td></tr>`).join('')}
    </tbody></table></div>
    <p class="dim">A policy shown as left out without a delete button is left out by the profile above, not by a single choice.</p>

    <div class="card"><h4>Leave out or change one policy for this client</h4>
      <div class="form">
        <label>Policy<select id="ovTpl"><option value="">Choose a policy</option>${rows.map(r => `<option value="${esc(r.templateId)}">${esc(r.name)}</option>`).join('')}</select></label>
        <label>What to do<select id="ovOp"><option value="exclude">Leave it out for this client</option><option value="modify">Change some of its settings</option></select></label>
        <label>Reason (required)<input id="ovReason"></label>
        <label>Owner (required)<input id="ovOwner" placeholder="who is responsible"></label>
        <label>End date (optional)<input id="ovEnd" type="date"></label>
      </div>
      <div id="ovPatchBox" hidden>
        <p class="dim">Type only the settings that should be different, in the same format as the policy (JSON). Settings you leave out stay as the standard has them, and a setting set to null is removed. Use VIEW on BASELINE to see a policy's settings.</p>
        <textarea id="ovPatch" placeholder='{"settingName": "new value"}' style="min-height:120px"></textarea>
      </div>
      <div class="row"><button class="act" id="ovAdd">SAVE</button></div>
    </div>`;

  $('#ovOp').onchange = (e) => { $('#ovPatchBox').hidden = e.target.value !== 'modify'; };
  $('#pfSave').onclick = async () => {
    const body = { namePrefix: $('#pfPrefix').value.replace(/^\s+/, ''), thirdPartyEDR: $('#pfEdr').checked, rmmPatching: $('#pfRmm').checked,
      regulated: $('#pfReg').checked, byod: $('#pfByod').checked, platforms: $$('[data-pfplat]:checked').map(i => i.dataset.pfplat), notes: $('#pfNotes').value.trim() };
    try { await api(tpath('/profile'), { method: 'PUT', body: JSON.stringify(body) }); toast('Profile saved'); renderProfile(); } catch (e) { toastErr(e); }
  };
  $('#ovAdd').onclick = async () => {
    const q = { templateId: $('#ovTpl').value, op: $('#ovOp').value, reason: $('#ovReason').value.trim(), owner: $('#ovOwner').value.trim(), expiresAt: $('#ovEnd').value, patch: '' };
    if (!q.templateId) return toast('Choose a policy', true);
    if (!q.reason || !q.owner) return toast('A reason and an owner are both required', true);
    if (q.op === 'modify') {
      q.patch = $('#ovPatch').value.trim();
      try { const v = JSON.parse(q.patch); if (!v || typeof v !== 'object' || Array.isArray(v)) throw 0; }
      catch { return toast('The changes must be settings inside { }, for example {"settingName": "value"}', true); }
    }
    try { await api(tpath('/overlays'), { method: 'POST', body: JSON.stringify(q) }); toast('Saved'); renderProfile(); }
    catch (e) {
      toast(/past/i.test(e.message) ? 'The end date has already passed. Pick a later date.'
        : /patch/i.test(e.message) ? 'Those changes do not fit this policy. Check the setting names.' : friendly(e).say, true);
    }
  };
  $$('[data-ovdel]', el).forEach(b => b.onclick = async () => {
    if (!await confirmAction('Delete a tailoring choice', '<p>This client goes back to the standard for this policy.</p><p class="note">Nothing changes in the client until something is deployed.</p>', 'DELETE')) return;
    try { await api('/api/overlays/' + encodeURIComponent(b.dataset.ovdel), { method: 'DELETE' }); toast('Deleted'); renderProfile(); } catch (e) { toastErr(e); }
  });
}

// ---------- rollouts ----------

const ringWord = { waiting: ['c-dim', 'waiting'], activated: ['c-ok', 'started'], error: ['c-bad', 'problem'] };
const kindPlain = { policies: 'Conditional Access policy', 'configuration-policies': 'Intune settings policy', 'compliance-policies': 'Device compliance policy' };
const gateText = (g) => {
  if (!g) return 'no gate';
  const parts = [];
  if (g.manualApproval) parts.push('needs approval');
  if (g.minCompliantPercent) parts.push(`at least ${g.minCompliantPercent}% of devices predicted compliant`);
  return parts.join(', ') || 'starts on its own';
};
const ro = { plans: null };

async function renderRollouts() {
  const el = $('#tab-rollouts');
  if (!tenantId()) { el.innerHTML = `<h2>ROLLOUTS</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>ROLLOUTS: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let list;
  try { if (!ro.plans) ro.plans = await api('/api/rollout-plans'); list = await api(tpath('/rollouts')); }
  catch (e) { el.innerHTML = `<h2>ROLLOUTS: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  const kinds = [...new Set(state.templates.map(t => t.kind))];
  el.innerHTML = `<h2>ROLLOUTS: ${esc(name)}</h2>
    <p class="dim">A rollout gives one policy to people in stages, called rings: a small group first, then more, then everyone. Each ring waits for its time and its gate before it starts.</p>
    ${list.length ? list.map(r => rolloutCard(r)).join('') : '<p class="dim">No rollouts for this client yet.</p>'}
    <h3>START A ROLLOUT</h3>
    <div class="card">
      <div class="form">
        <label>Plan<select id="roPlan">${ro.plans.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></label>
        <label>Kind of policy<select id="roKind">${kinds.map(k => `<option value="${esc(k)}">${esc(kindPlain[k] || k)}</option>`).join('')}</select></label>
        <label>Policy id in the client<input id="roObj" placeholder="the policy's id from HISTORY"></label>
        <label>Policy name (for people reading this)<input id="roName"></label>
        <label>Standard policy it came from (needed for a compliance gate)<select id="roTpl"><option value="">none</option>${state.templates.filter(t => t.kind === 'compliance-policies').map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}</select></label>
        <label>Everyone means<select id="roEvery"><option value="all-users">all users</option><option value="all-devices">all devices</option></select></label>
        <label>Start (empty means now)<input id="roStart" type="datetime-local"></label>
      </div>
      <p class="dim" id="roPlanDesc"></p>
      <div id="roRings"></div>
      <div class="row"><button class="act" id="roPreview">PREVIEW</button></div>
      <div id="roOut"></div>
    </div>`;

  const drawRingInputs = () => {
    const p = ro.plans.find(x => x.id === $('#roPlan').value);
    $('#roPlanDesc').textContent = p?.description || '';
    $('#roRings').innerHTML = (p?.rings || []).map((r, i) => r.everyone
      ? `<p class="mono-sm">Ring ${i + 1}, ${esc(r.name)}: everyone (chosen above), ${esc(gateText(r.gate))}, ${r.waitHours} hours after the ring before.</p>`
      : `<label class="dim">Ring ${i + 1}, ${esc(r.name)}: group ids, separated by commas (${esc(gateText(r.gate))}${i ? `, ${r.waitHours} hours after the ring before` : ''})
          <input data-roring="${i}" style="width:100%"></label>`).join('');
  };
  $('#roPlan').onchange = drawRingInputs;
  drawRingInputs();

  const request = () => {
    const v = $('#roStart').value;
    return {
      planId: $('#roPlan').value, kind: $('#roKind').value, objectId: $('#roObj').value.trim(), objectName: $('#roName').value.trim(),
      templateId: $('#roTpl').value, everyone: $('#roEvery').value,
      ringGroups: $$('[data-roring]', el).map(i => i.value.split(',').map(s => s.trim()).filter(Boolean)),
      startAt: v ? new Date(v).toISOString().replace(/\.\d+Z$/, 'Z') : '',
    };
  };
  $('#roPreview').onclick = async () => {
    const q = request(), out = $('#roOut');
    if (!q.objectId) return toast("Type the policy's id in the client", true);
    out.innerHTML = '<p class="dim">Working out the schedule...</p>';
    let sch;
    try { sch = await api(tpath('/rollouts/preview'), { method: 'POST', body: JSON.stringify(q) }); }
    catch (e) { out.innerHTML = /group|guid/i.test(e.message) ? `<div class="note">Check the group ids: each must look like 00000000-0000-0000-0000-000000000000.<div class="mono-sm">Details: ${esc(e.message)}</div></div>` : errNote(e); return; }
    const ro2 = state.status.readOnly;
    out.innerHTML = `<h3>SCHEDULE</h3><div class="timeline">${(sch.steps || []).map(s => `<div class="ring">
        <b>${s.index + 1}. ${esc(s.name)}</b>
        <div class="mono-sm">Earliest ${when(s.earliestAt)}</div>
        <div class="mono-sm">${esc(gateText(s.gate))}</div>
        <div class="mono-sm">${s.everyone ? `everyone (${esc(s.everyone === 'all-devices' ? 'all devices' : 'all users')})` : esc((s.groups || []).join(', '))}</div></div>`).join('')}</div>
      <p class="dim">Times assume each ring starts as soon as it is allowed to.</p>
      ${ro2 ? '<div class="note">The console is in read-only mode, so it will not start a rollout. Preview still works.</div>' : ''}
      <label class="dim">Type the client's name, <b>${esc(name)}</b>, to create this rollout<input id="roConf" autocomplete="off" style="width:100%"></label>
      <div class="row"><button class="danger" id="roCreate" disabled>CREATE ROLLOUT</button></div>`;
    $('#roConf').oninput = (e) => { $('#roCreate').disabled = ro2 || e.target.value.trim() !== name; };
    $('#roCreate').onclick = async () => {
      try { await api(tpath('/rollouts'), { method: 'POST', body: JSON.stringify({ ...q, hash: sch.hash }) }); toast('Rollout created'); renderRollouts(); }
      catch (e) { toast(/already part/i.test(e.message) ? 'This policy is already in a rollout that is still running.' : friendly(e).say, true); }
    };
  };

  const ctl = async (id, action, payload, done) => {
    try { await api(`/api/rollouts/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: JSON.stringify(payload || {}) }); toast(done); renderRollouts(); }
    catch (e) { toastErr(e); }
  };
  $$('[data-roappr]', el).forEach(b => b.onclick = () => { const [id, ring] = b.dataset.roappr.split('|'); ctl(id, 'approve', { ring: Number(ring) }, 'Ring approved'); });
  $$('[data-ropause]', el).forEach(b => b.onclick = () => ctl(b.dataset.ropause, 'pause', {}, 'Paused'));
  $$('[data-roresume]', el).forEach(b => b.onclick = () => ctl(b.dataset.roresume, 'resume', {}, 'Resumed'));
  $$('[data-rocancel]', el).forEach(b => b.onclick = async () => {
    const ok = await confirmAction('Cancel a rollout', `<p>No more rings will start.</p>
      <label class="check"><input type="checkbox" id="roRevert" checked><span>Put the policy's earlier assignment back, as it was before the rollout</span></label>`, 'CANCEL ROLLOUT');
    if (!ok) return;
    ctl(b.dataset.rocancel, 'cancel', { revert: !!$('#roRevert')?.checked }, 'Rollout cancelled');
  });
}

function rolloutCard(r) {
  const active = !['done', 'cancelled', 'completed', 'failed'].includes(r.state);
  return `<div class="card" style="margin:10px 0">
    <h4>${esc(r.objectName || r.objectId)} <span class="chip c-info">${esc(r.state)}</span></h4>
    <div class="mono-sm">${esc(r.planName)}, ${esc(kindPlain[r.kind] || r.kind)}, started by ${esc(r.createdBy)} ${when(r.createdAt)}${r.note ? `. ${esc(r.note)}` : ''}</div>
    <div class="timeline">${(r.rings || []).map(g => {
      let spec = {}; try { spec = typeof g.spec === 'string' ? JSON.parse(g.spec) : (g.spec || {}); } catch { /* shown without a gate */ }
      const needsApproval = spec.gate?.manualApproval && !g.approvedBy && g.state === 'waiting';
      return `<div class="ring"><b>${g.index + 1}. ${esc(g.name)}</b> <span class="chip ${(ringWord[g.state] || ['c-dim'])[0]}">${esc((ringWord[g.state] || [, g.state])[1])}</span>
        <div class="mono-sm">Earliest ${when(g.eligibleAt)}${g.activatedAt ? `, started ${when(g.activatedAt)}` : ''}</div>
        <div class="mono-sm">Gate: ${esc(gateText(spec.gate))}</div>
        ${g.approvedBy ? `<div class="mono-sm">Approved by ${esc(g.approvedBy)} ${when(g.approvedAt)}</div>` : ''}
        ${g.detail ? `<div class="mono-sm">${esc(g.detail)}</div>` : ''}
        ${needsApproval && active ? `<button class="act" data-roappr="${esc(r.id)}|${g.index}">APPROVE RING</button>` : ''}</div>`;
    }).join('')}</div>
    ${active ? `<div class="row tight">${r.state === 'paused' ? `<button class="ghost" data-roresume="${esc(r.id)}">RESUME</button>` : `<button class="ghost" data-ropause="${esc(r.id)}">PAUSE</button>`}
      <button class="danger" data-rocancel="${esc(r.id)}">CANCEL</button></div>` : ''}
  </div>`;
}

// ---------- reports ----------

const baseLabel = (id) => (assessState.baselines || []).find(b => b.id === (id || ''))?.label || id || 'House standard';

// reportRows works out each saved report's score and its change since the
// previous report against the same baseline. The list arrives newest first.
function reportRows(list) {
  const counts = (r) => { try { return JSON.parse(r.summary || '{}') || {}; } catch { return {}; } };
  const pct = (c) => { const t = (c.inPlace || 0) + (c.differ || 0) + (c.missing || 0); return t ? Math.floor(100 * (c.inPlace || 0) / t) : 0; };
  const rows = [...list].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return rows.map((r, i) => {
    const c = counts(r), prev = rows.slice(i + 1).find(x => (x.baseline || '') === (r.baseline || ''));
    if (!prev) return { ...r, c, pct: pct(c), change: 'First report against this baseline', cls: 'dim' };
    const d = pct(c) - pct(counts(prev));
    return { ...r, c, pct: pct(c), change: d === 0 ? 'No change in score' : `${d > 0 ? 'Up' : 'Down'} ${Math.abs(d)} points`, cls: d > 0 ? 'c-ok' : d < 0 ? 'c-bad' : 'dim' };
  });
}

async function renderReports() {
  const el = $('#tab-reports');
  if (!tenantId()) { el.innerHTML = `<h2>REPORTS</h2>${pickClientNote}`; return; }
  const name = state.tenant.name;
  el.innerHTML = `<h2>REPORTS: ${esc(name)}</h2><p class="dim">Loading...</p>`;
  let list;
  try { list = await api(tpath('/reports')); if (!assessState.baselines) assessState.baselines = await api('/api/assessment/baselines'); }
  catch (e) { el.innerHTML = `<h2>REPORTS: ${esc(name)}</h2>${errNote(e, true)}`; return; }
  el.innerHTML = `<h2>REPORTS: ${esc(name)}</h2>
    <p class="dim">A report is a saved snapshot of how this client measures up, ready to share. Each new report shows the change since the one before. Making a report only reads the client.</p>
    <div class="row"><label>Baseline<select id="rpBase">${assessState.baselines.map(b => `<option value="${esc(b.id)}">${esc(b.label)}</option>`).join('')}</select></label>
      <button class="act" id="rpMake">GENERATE REPORT</button></div>
    <div id="rpOut"></div>
    <h3>SAVED REPORTS (${list.length})</h3>
    ${list.length ? `<div class="scroll"><table><thead><tr><th>When</th><th>Baseline</th><th>Score</th><th>Change since last time</th><th></th></tr></thead><tbody>
      ${reportRows(list).map(r => `<tr><td class="dim">${when(r.createdAt)}</td><td>${esc(baseLabel(r.baseline))}</td>
        <td><b>${r.pct}%</b><div class="mono-sm">${r.c.inPlace || 0} in place, ${r.c.differ || 0} differ, ${r.c.missing || 0} missing</div></td><td class="${r.cls}">${esc(r.change)}</td>
        <td><a href="/api/reports/${encodeURIComponent(r.id)}" target="_blank" rel="noopener">OPEN</a></td></tr>`).join('')}
      </tbody></table></div>` : '<p class="dim">No reports yet.</p>'}`;
  $('#rpMake').onclick = async (ev) => {
    const b = ev.currentTarget; b.disabled = true;
    $('#rpOut').innerHTML = '<p class="dim">Reading the client, this can take a minute...</p>';
    try { await api(tpath('/reports'), { method: 'POST', body: JSON.stringify({ baseline: $('#rpBase').value }) }); toast('Report saved'); renderReports(); }
    catch (e) { $('#rpOut').innerHTML = errNote(e); b.disabled = false; }
  };
}

boot().catch(e => { document.body.insertAdjacentHTML('afterbegin', `<div class="note bad">Could not start: ${esc(e.message)}</div>`); });
