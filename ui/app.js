'use strict';
// ollamawg dashboard. No dependencies, no network calls beyond this server.

const S = {
  overview: null, devices: [], series: null, spark: null, metric: 'requests', window: '1h',
  tab: 'access', paused: false, colors: {}, editing: null, busy: false,
};
const PALETTE = ['#3a6ea5', '#7c5ca8', '#b0558a', '#5e7f2e', '#4f5b8f', '#a3643a', '#3f8fbf', '#6a7c8e'];
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const SVGNS = 'http://www.w3.org/2000/svg';

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtNum(n) {
  n = Number(n) || 0;
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return Math.round(n / 1e3) + 'k';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}
function ago(t) {
  if (!t) return 'never';
  const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
  if (s < 60) return Math.round(s) + ' s ago';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' d ago';
}
function dur(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  return `${m} min`;
}
function clock(t, withSec) {
  const d = new Date(t);
  const o = { hour: '2-digit', minute: '2-digit', hour12: false };
  if (withSec) o.second = '2-digit';
  return d.toLocaleTimeString([], o);
}
function osName(os) {
  return { darwin: 'macOS', linux: 'Linux', windows: 'Windows', android: 'Android', ios: 'iOS', freebsd: 'FreeBSD' }[os] || os || '';
}

async function api(method, path, body) {
  const opt = { method, headers: {}, credentials: 'same-origin', cache: 'no-store' };
  if (method !== 'GET') opt.headers['X-Ollamawg'] = '1';
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401 && path !== '/api/login' && path !== '/api/session') checkSession();
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || (typeof data === 'string' && data.trim()) || r.statusText);
  return data;
}

function toast(msg, isErr) {
  const el = document.createElement('div');
  el.textContent = msg;
  if (isErr) el.className = 'err';
  $('#toast').append(el);
  setTimeout(() => el.remove(), isErr ? 6000 : 3000);
}

function confirmDialog(title, body, okLabel) {
  const d = $('#dlg-confirm');
  $('#confirm-title').textContent = title;
  $('#confirm-body').textContent = body;
  $('#confirm-ok').textContent = okLabel;
  d.returnValue = '';
  d.showModal();
  return new Promise(res => d.addEventListener('close', () => res(d.returnValue === 'ok'), { once: true }));
}

async function act(fn, okMsg) {
  try {
    await fn();
    if (okMsg) toast(okMsg);
    await refresh(true);
  } catch (e) {
    toast(e.message, true);
  }
}

/* ---------- colors ---------- */
function assignColors() {
  const ids = S.devices.map(d => d.id);
  ids.forEach((id, i) => { S.colors[id] = PALETTE[i % PALETTE.length]; });
}
function nameOf(id) {
  const d = S.devices.find(x => x.id === id);
  return d ? d.name : id;
}

/* ---------- header + readout ---------- */
function renderOverview() {
  const o = S.overview;
  if (!o) return;
  $('#f-endpoint').textContent = `${o.public_endpoint || 'endpoint not set'} (udp ${o.listen_port})`;
  $('#f-tunnel').textContent = o.tunnel;
  const up = $('#f-upstream');
  up.innerHTML = `<span class="dot" style="background:${o.upstream_ok ? '#35a07a' : '#ef6a5e'}"></span>` +
    esc(o.upstream_ok ? `reachable${o.upstream_version ? ', v' + o.upstream_version : ''}` : 'not reachable');
  up.title = o.upstream;
  $('#f-uptime').textContent = dur(o.uptime_seconds);
  const l = o.last24h;
  const set = (id, v, title) => {
    const el = $(id);
    el.textContent = fmtNum(v);
    el.parentElement.classList.toggle('zero', !v);
    if (title) el.parentElement.title = title;
  };
  $('#r-online').textContent = `${o.devices_online} of ${o.devices_total}`;
  set('#r-req', l.requests);
  set('#r-tok', l.prompt_tokens + l.completion_tokens, `${fmtNum(l.prompt_tokens)} prompt, ${fmtNum(l.completion_tokens)} generated`);
  set('#r-denied', l.denied);
  set('#r-drop', l.dropped_packets, `${fmtNum(o.packets_dropped)} dropped since start`);
  $('#fw-default').value = o.firewall_default;
  for (const sel of ['#add-role', '#edit-role']) {
    const el = $(sel);
    if (el.options.length !== o.roles.length) el.innerHTML = o.roles.map(r => `<option>${esc(r)}</option>`).join('');
  }
  document.title = `ollamawg: ${o.devices_online}/${o.devices_total} connected`;
}

/* ---------- traffic chart ---------- */
function allowedValue(p) {
  return S.metric === 'tokens' ? p.prompt_tokens + p.completion_tokens : p.requests - p.denied;
}

function renderChart() {
  const box = $('#chart');
  const se = S.series;
  if (!se) return;
  const W = Math.max(280, box.clientWidth), H = box.clientHeight || 230;
  const m = { l: 44, r: 6, t: 8, b: 22 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const upH = ph * 0.68, downH = ph - upH - 2, zero = m.t + upH;
  const n = se.times.length;
  const ids = Object.keys(se.devices).sort((a, b) => nameOf(a).localeCompare(nameOf(b)));
  const up = new Array(n).fill(0), denied = new Array(n).fill(0);
  for (const id of ids) se.devices[id].forEach((p, i) => { up[i] += allowedValue(p); denied[i] += p.denied; });
  const down = se.drops.map((d, i) => d + denied[i]);
  const maxUp = Math.max(1, ...up), maxDown = Math.max(1, ...down);
  const bw = pw / n, barW = Math.max(1, bw * 0.74);

  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Traffic over the last ${S.window}`);
  const el = (tag, attrs, parent = svg) => {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    parent.append(e);
    return e;
  };
  // grid + labels
  el('line', { x1: m.l, x2: W - m.r, y1: m.t, y2: m.t, class: 'grid' });
  el('line', { x1: m.l, x2: W - m.r, y1: m.t + upH / 2, y2: m.t + upH / 2, class: 'grid' });
  const tick = (y, t) => { const e = el('text', { x: m.l - 6, y, class: 'tick', 'text-anchor': 'end', 'dominant-baseline': 'middle' }); e.textContent = t; };
  tick(m.t + 2, fmtNum(maxUp));
  tick(m.t + upH / 2, fmtNum(Math.round(maxUp / 2)));
  tick(zero + downH - 2, fmtNum(maxDown));

  const total = up.reduce((a, b) => a + b, 0) + down.reduce((a, b) => a + b, 0);
  for (let i = 0; i < n; i++) {
    const x = m.l + i * bw + (bw - barW) / 2;
    let y = zero;
    for (const id of ids) {
      const v = allowedValue(se.devices[id][i]);
      if (!v) continue;
      const h = Math.max(1, v / maxUp * upH);
      y -= h;
      el('rect', { x, y, width: barW, height: h, fill: S.colors[id] || '#888' });
    }
    let yd = zero + 1;
    if (denied[i]) {
      const h = Math.max(1, denied[i] / maxDown * downH);
      el('rect', { x, y: yd, width: barW, height: h, class: 'den' });
      yd += h;
    }
    if (se.drops[i]) {
      const h = Math.max(1, se.drops[i] / maxDown * downH);
      el('rect', { x, y: yd, width: barW, height: h, class: 'drp' });
    }
  }
  el('line', { x1: m.l, x2: W - m.r, y1: zero, y2: zero, class: 'axis' });
  // x labels
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 70))));
  for (let i = 0; i < n; i += every) {
    const t = el('text', { x: m.l + i * bw + bw / 2, y: H - 6, class: 'tick', 'text-anchor': 'middle' });
    t.textContent = clock(se.times[i]);
  }
  if (!total) {
    const t = el('text', { x: m.l + pw / 2, y: m.t + upH / 2 - 14, class: 'empty', 'text-anchor': 'middle' });
    t.textContent = 'No traffic in this window yet.';
  }
  // hover columns
  const tip = $('#tip');
  for (let i = 0; i < n; i++) {
    const r = el('rect', { x: m.l + i * bw, y: m.t, width: bw, height: ph, fill: 'transparent' });
    r.addEventListener('mousemove', ev => {
      const rows = ids.map(id => [nameOf(id), allowedValue(se.devices[id][i]), S.colors[id]]).filter(x => x[1]);
      const unit = S.metric === 'tokens' ? 'tokens' : 'requests';
      let h = `<b>${esc(clock(se.times[i]))}</b>`;
      if (se.step_seconds > 60) h += ` <span>(${se.step_seconds / 60} min)</span>`;
      h += rows.length ? rows.map(([nm, v, c]) => `<br><span style="color:${c}">■</span> ${esc(nm)}: ${fmtNum(v)} ${unit}`).join('') : `<br>No allowed ${unit}`;
      if (denied[i]) h += `<br>Denied requests: ${denied[i]}`;
      if (se.drops[i]) h += `<br>Dropped packets: ${fmtNum(se.drops[i])}`;
      tip.innerHTML = h;
      tip.hidden = false;
      const x = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
      tip.style.left = x + 'px';
      tip.style.top = (ev.clientY + 14) + 'px';
    });
    r.addEventListener('mouseleave', () => { tip.hidden = true; });
  }
  box.replaceChildren(svg);

  const leg = ids.map(id => `<span style="--c:${S.colors[id]}">${esc(nameOf(id))}</span>`);
  leg.push('<span style="--c:var(--caution)">Denied by policy</span>', '<span style="--c:var(--stop)">Dropped by firewall</span>');
  $('#legend').innerHTML = leg.join('');
}

/* ---------- models ---------- */
function renderModels(models) {
  const box = $('#model-bars');
  if (!models.length) {
    box.innerHTML = '<p class="empty-note">Model usage appears here after the first chat or generate request.</p>';
    return;
  }
  const max = Math.max(1, ...models.map(m => m.prompt_tokens + m.completion_tokens));
  box.innerHTML = models.slice(0, 8).map(m => {
    const tot = m.prompt_tokens + m.completion_tokens;
    return `<div class="mbar" title="${fmtNum(m.prompt_tokens)} prompt, ${fmtNum(m.completion_tokens)} generated">
      <div class="row"><b>${esc(m.model)}</b><span>${fmtNum(tot)} tokens, ${fmtNum(m.requests)} req</span></div>
      <div class="track"><div class="p" style="width:${m.prompt_tokens / max * 100}%"></div><div class="c" style="width:${m.completion_tokens / max * 100}%"></div></div>
    </div>`;
  }).join('') + '<p class="hint">Muted segment: prompt tokens. Solid segment: generated.</p>';
}

/* ---------- devices ---------- */
function sparkPath(points, w, h) {
  const vals = points.map(p => p.requests);
  const max = Math.max(1, ...vals);
  const step = w / Math.max(1, vals.length - 1);
  const ys = vals.map(v => h - 2 - v / max * (h - 4));
  const line = ys.map((y, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)},${y.toFixed(1)}`).join('');
  return { line, area: `${line}L${w},${h}L0,${h}Z` };
}

function renderDevices() {
  const box = $('#devices');
  const ds = S.devices;
  $('#dev-sub').textContent = ds.length ? `${ds.filter(d => d.online).length} connected, ${ds.filter(d => d.blocked).length} blocked` : '';
  if (!ds.length) {
    box.innerHTML = '<p class="empty-note">No devices yet. Add one to get a config file for it, or run <code>ollamawg add-peer</code> on this server.</p>';
    return;
  }
  const spark = S.spark || S.series;
  box.innerHTML = ds.map(d => {
    const cls = d.blocked ? 'blocked' : d.online ? 'online' : 'offline';
    const state = d.blocked ? 'Blocked' : d.online ? 'Connected' : 'Offline';
    const pts = spark && spark.devices[d.id];
    let sp = '<svg class="spark" aria-hidden="true"></svg>';
    if (pts) {
      const { line, area } = sparkPath(pts, 130, 34);
      sp = `<svg class="spark" viewBox="0 0 130 34" preserveAspectRatio="none" aria-label="Requests in the last hour"><path class="area" d="${area}"/><path d="${line}"/></svg>`;
    }
    const where = d.endpoint
      ? `<span class="k">from</span> <span class="v mono">${esc(d.endpoint)}</span>`
      : '<span class="k">never connected</span>';
    const c = d.client || {};
    const host = c.hostname
      ? `<div><span class="v">${esc(c.hostname)}</span></div><div class="k">${esc(osName(c.os))} ${esc(c.arch || '')}, client ${esc(c.version || '?')}</div>`
      : '<div class="k">Host not reported yet</div>';
    const policy = [];
    if (d.models.length) policy.push(`models: ${d.models.join(', ')}`);
    if (d.rpm) policy.push(`${d.rpm}/min`);
    const tok = d.last24h.prompt_tokens + d.last24h.completion_tokens;
    return `<div class="strip ${cls}" data-id="${esc(d.id)}">
      <div class="band"></div>
      <div class="who"><b>${esc(d.name)}<span class="role ${d.role === 'admin' ? 'admin' : ''}">${esc(d.role)}</span></b>
        <span class="id mono" title="${esc(d.public_key)}">${esc(d.id)}</span> <span class="id mono">${esc(d.address)}</span></div>
      <div class="cell"><div><span class="state">${state}</span> ${where}</div>
        <div><span class="k">handshake</span> ${esc(ago(d.last_handshake))}, <span class="k">tunnel</span> ${fmtBytes(d.rx_bytes + d.tx_bytes)}</div></div>
      <div class="cell">${host}</div>
      ${sp}
      <div class="cell"><div><span class="v">${fmtNum(d.last24h.requests)}</span> <span class="k">requests, 24 h</span></div>
        <div><span class="v">${fmtNum(tok)}</span> <span class="k">tokens</span>${d.last24h.denied ? `, <span class="v" style="color:var(--caution)">${d.last24h.denied}</span> <span class="k">denied</span>` : ''}</div>
        ${policy.length ? `<div class="k" title="${esc(policy.join('; '))}">${esc(policy.join('; '))}</div>` : ''}</div>
      <div class="acts">
        <button class="btn sm" data-act="edit">Policy</button>
        ${d.blocked ? '<button class="btn sm go-o" data-act="unblock">Unblock</button>' : '<button class="btn sm stop-o" data-act="block">Block</button>'}
        <button class="btn sm ghost" data-act="delete" aria-label="Delete ${esc(d.name)}">Delete</button>
      </div>
    </div>`;
  }).join('');
}

$('#devices').addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-act]');
  if (!b) return;
  const id = b.closest('.strip').dataset.id;
  const d = S.devices.find(x => x.id === id);
  if (!d) return;
  const a = b.dataset.act;
  if (a === 'block') {
    if (await confirmDialog(`Block ${d.name}?`, 'Its WireGuard session is cut immediately and new handshakes are refused until you unblock it.', 'Block device')) {
      act(() => api('POST', `/api/devices/${id}/block`), `Blocked ${d.name}`);
    }
  } else if (a === 'unblock') {
    act(() => api('POST', `/api/devices/${id}/unblock`), `Unblocked ${d.name}. It reconnects within about 15 seconds.`);
  } else if (a === 'delete') {
    if (await confirmDialog(`Delete ${d.name}?`, "The device's key is removed from this server. To bring it back you'd add it again and send it a new config.", 'Delete device')) {
      act(() => api('DELETE', `/api/devices/${id}`), `Deleted ${d.name}`);
    }
  } else if (a === 'edit') {
    S.editing = d;
    const f = $('#edit-form');
    $('#edit-name').textContent = d.name;
    f.role.value = d.role;
    f.models.value = d.models.join(', ');
    f.rpm.value = d.rpm || '';
    $('#dlg-edit').showModal();
  }
});

$('#edit-form').addEventListener('submit', ev => {
  if (ev.submitter && ev.submitter.value !== 'ok') return;
  const f = ev.target, d = S.editing;
  const body = {
    role: f.role.value,
    models: f.models.value.split(',').map(s => s.trim()).filter(Boolean),
    rpm: parseInt(f.rpm.value, 10) || 0,
  };
  act(() => api('PATCH', `/api/devices/${d.id}`, body), `Saved policy for ${d.name}`);
});

/* ---------- add device ---------- */
$$('[data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
$('#btn-add').addEventListener('click', () => {
  const d = $('#dlg-add');
  $('#add-form').hidden = false;
  $('#add-result').hidden = true;
  $('#add-form').reset();
  d.showModal();
});
$('#add-form').addEventListener('submit', async ev => {
  if (!ev.submitter || ev.submitter.value !== 'ok') return;
  ev.preventDefault();
  const f = ev.target;
  try {
    const r = await api('POST', '/api/devices', { name: f.name.value.trim(), role: f.role.value });
    $('#add-name').textContent = r.name;
    $('#add-file').textContent = r.filename;
    $('#add-config').textContent = r.config;
    S.added = r;
    f.hidden = true;
    $('#add-result').hidden = false;
    refresh(true);
  } catch (e) {
    toast(e.message, true);
  }
});
$('#add-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(S.added.config); toast('Copied config'); }
  catch { toast('Copy failed. Select the text and copy it instead.', true); }
});
$('#add-download').addEventListener('click', () => {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([S.added.config], { type: 'application/yaml' }));
  a.download = S.added.filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
$('#add-done').addEventListener('click', () => { S.added = null; $('#add-config').textContent = ''; $('#dlg-add').close(); });
$('#dlg-add').addEventListener('close', () => { S.added = null; $('#add-config').textContent = ''; });

/* ---------- sources ---------- */
function renderSources(src) {
  const tb = $('#sources tbody');
  $('#src-sub').textContent = `UDP sources hitting port ${S.overview ? S.overview.listen_port : ''}`;
  if (!src.length) {
    tb.innerHTML = '<tr><td colspan="6" class="muted">Nothing has reached the WireGuard port yet.</td></tr>';
    return;
  }
  tb.innerHTML = src.slice(0, 200).map(s => `<tr class="${s.blocked ? 'drop' : ''}">
    <td class="mono">${esc(s.ip)}<span class="muted">:${s.port}</span></td>
    <td>${s.device ? esc(s.device) : '<span class="unknown" title="Packets from this IP never matched a device. Scanners and misconfigured clients show up here.">unknown</span>'}</td>
    <td class="r">${fmtNum(s.packets)}</td>
    <td class="r">${s.dropped ? `<span class="s5">${fmtNum(s.dropped)}</span>` : '0'}</td>
    <td class="muted">${esc(ago(s.last_seen))}</td>
    <td class="r">${s.blocked ? `<span class="muted" title="${esc(s.rule || '')}">blocked</span>` : `<button class="btn sm stop-o" data-ip="${esc(s.ip)}" data-dev="${esc(s.device || '')}">Block IP</button>`}</td>
  </tr>`).join('');
}
$('#sources').addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-ip]');
  if (!b) return;
  const ip = b.dataset.ip, dev = b.dataset.dev;
  const body = dev
    ? `${dev} is connecting from this IP. Its packets will be dropped before WireGuard sees them, and so will anything else from ${ip}.`
    : `Every UDP packet from ${ip} will be dropped before WireGuard sees it.`;
  if (await confirmDialog(`Block ${ip}?`, body, 'Block IP')) {
    act(() => api('POST', '/api/firewall', { action: 'block', cidr: ip, note: dev ? `was ${dev}` : 'from sources' }), `Blocked ${ip}`);
  }
});

/* ---------- firewall ---------- */
function renderFirewall(fw) {
  const ul = $('#rules');
  if (!fw.rules.length) {
    ul.innerHTML = `<li class="empty-note" style="display:block">No rules. ${fw.default === 'deny' ? 'Every IP is dropped: add an allow rule.' : 'Every IP may attempt a handshake; only valid keys get in.'}</li>`;
    return;
  }
  ul.innerHTML = fw.rules.map(r => `<li>
    <span class="act ${r.action}">${r.action === 'block' ? 'Block' : 'Allow'}</span>
    <span><span class="mono">${esc(r.cidr)}</span>${r.note ? `<span class="note">${esc(r.note)}</span>` : ''}</span>
    <span class="hits">${fmtNum(r.hits)} packets</span>
    <button class="btn sm ghost" data-cidr="${esc(r.cidr)}" data-action="${esc(r.action)}">Remove</button>
  </li>`).join('');
}
$('#rules').addEventListener('click', ev => {
  const b = ev.target.closest('button[data-cidr]');
  if (!b) return;
  act(() => api('DELETE', `/api/firewall?cidr=${encodeURIComponent(b.dataset.cidr)}&action=${b.dataset.action}`), `Removed rule for ${b.dataset.cidr}`);
});
$('#fw-form').addEventListener('submit', ev => {
  ev.preventDefault();
  const f = ev.target;
  const body = { action: f.action.value, cidr: f.cidr.value.trim(), note: f.note.value.trim() };
  act(async () => { await api('POST', '/api/firewall', body); f.reset(); }, `${body.action === 'block' ? 'Blocked' : 'Allowed'} ${body.cidr}`);
});
$('#fw-default').addEventListener('change', async ev => {
  const v = ev.target.value;
  if (v === 'deny' && !(await confirmDialog('Drop every unlisted IP?', 'Only sources matching an allow rule will reach WireGuard. Devices on other networks are cut off until you add allow rules for them.', 'Drop unlisted IPs'))) {
    ev.target.value = 'allow';
    return;
  }
  act(() => api('PUT', '/api/firewall/default', { default: v }), v === 'deny' ? 'Unlisted IPs are now dropped' : 'Unlisted IPs are now allowed');
});

/* ---------- logs ---------- */
function renderLog(rows) {
  const thead = $('#log thead'), tb = $('#log tbody');
  if (S.tab === 'access') {
    thead.innerHTML = '<tr><th>Time</th><th>Device</th><th>Request</th><th>Model</th><th>Result</th><th class="r">Tokens in / out</th><th class="r">Took</th><th>From</th></tr>';
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="8" class="muted">No requests yet.</td></tr>'; return; }
    tb.innerHTML = rows.map(e => {
      const sc = e.status >= 500 ? 's5' : e.status >= 400 ? 's4' : 's2';
      const res = e.denied ? `<span class="s4" title="${esc(e.denied)}">${e.status} ${esc(e.denied)}</span>` : `<span class="${sc}">${e.status}</span>`;
      const tk = e.prompt_tokens || e.completion_tokens ? `${fmtNum(e.prompt_tokens)} / ${fmtNum(e.completion_tokens)}` : '<span class="muted">–</span>';
      return `<tr class="${e.denied ? 'denied' : ''}">
        <td class="muted" title="${esc(e.time)}">${esc(clock(e.time, true))}</td>
        <td>${esc(e.device)}</td>
        <td class="path">${esc(e.method)} ${esc(e.path)}</td>
        <td>${esc(e.model || '')}</td>
        <td>${res}</td>
        <td class="r">${tk}</td>
        <td class="r muted">${e.duration_ms >= 1000 ? (e.duration_ms / 1000).toFixed(1) + ' s' : e.duration_ms + ' ms'}</td>
        <td class="mono muted">${esc(e.remote_ip || '')}</td>
      </tr>`;
    }).join('');
  } else {
    thead.innerHTML = '<tr><th>Time</th><th>Level</th><th>Source</th><th>What happened</th><th>IP</th></tr>';
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="5" class="muted">No events yet.</td></tr>'; return; }
    tb.innerHTML = rows.map(e => `<tr class="${e.level === 'block' ? 'drop' : e.level === 'warn' ? 'denied' : ''}">
      <td class="muted" title="${esc(e.time)}">${esc(clock(e.time, true))}</td>
      <td><span class="lvl ${esc(e.level)}">${esc(e.level)}</span></td>
      <td>${esc(e.kind)}</td>
      <td>${esc(e.message)}</td>
      <td class="mono muted">${esc(e.ip || '')}</td>
    </tr>`).join('');
  }
}
function syncDeviceFilter() {
  const sel = $('#log-device');
  const cur = sel.value;
  const opts = ['<option value="">All devices</option>'].concat(S.devices.map(d => `<option value="${esc(d.id)}">${esc(d.name)}</option>`));
  if (sel.options.length !== opts.length) { sel.innerHTML = opts.join(''); sel.value = cur; }
}
$$('.tabs button').forEach(b => b.addEventListener('click', () => {
  S.tab = b.dataset.tab;
  $$('.tabs button').forEach(x => x.setAttribute('aria-selected', String(x === b)));
  $('#log-device').parentElement.hidden = S.tab !== 'access';
  $('#log-denied').parentElement.hidden = S.tab !== 'access';
  loadLog();
}));
$('#log-device').addEventListener('change', loadLog);
$('#log-denied').addEventListener('change', loadLog);
$('#log-pause').addEventListener('click', ev => {
  S.paused = !S.paused;
  ev.target.setAttribute('aria-pressed', String(S.paused));
  ev.target.textContent = S.paused ? 'Resume' : 'Pause';
  if (!S.paused) loadLog();
});
async function loadLog() {
  try {
    if (S.tab === 'access') {
      const q = new URLSearchParams({ limit: 300 });
      if ($('#log-device').value) q.set('device', $('#log-device').value);
      if ($('#log-denied').checked) q.set('denied', '1');
      renderLog(await api('GET', '/api/logs?' + q));
    } else {
      renderLog(await api('GET', '/api/events?limit=300'));
    }
  } catch (e) { /* surfaced by the main refresh */ }
}

/* ---------- chart controls ---------- */
$$('[data-metric]').forEach(b => b.addEventListener('click', () => {
  S.metric = b.dataset.metric;
  $$('[data-metric]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  renderChart();
}));
$$('[data-window]').forEach(b => b.addEventListener('click', async () => {
  S.window = b.dataset.window;
  $$('[data-window]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  S.series = await api('GET', '/api/series?window=' + S.window);
  renderChart();
}));
let rsz;
window.addEventListener('resize', () => { clearTimeout(rsz); rsz = setTimeout(renderChart, 120); });

/* ---------- refresh loop ---------- */
let failing = false;
async function refresh(force) {
  if (S.busy || S.locked || (!force && document.hidden)) return;
  S.busy = true;
  try {
    const [ov, devs, series, models, src, fw] = await Promise.all([
      api('GET', '/api/overview'), api('GET', '/api/devices'),
      api('GET', '/api/series?window=' + S.window), api('GET', '/api/models'),
      api('GET', '/api/sources'), api('GET', '/api/firewall'),
    ]);
    S.overview = ov; S.devices = devs; S.series = series;
    S.spark = S.window === '1h' ? null : await api('GET', '/api/series?window=1h');
    assignColors();
    renderOverview();
    renderChart();
    renderModels(models);
    renderDevices();
    renderSources(src);
    renderFirewall(fw);
    syncDeviceFilter();
    if (!S.paused) await loadLog();
    if (failing) { failing = false; toast('Reconnected to the server'); }
  } catch (e) {
    if (!failing) { failing = true; toast('Lost contact with the ollamawg server: ' + e.message, true); }
  } finally {
    S.busy = false;
  }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(true); });

/* ---------- login and two-factor auth ---------- */
const digits = v => String(v || '').replace(/\s+/g, '');
function showLogin() {
  if (S.locked) return;
  S.locked = true;
  $$('dialog[open]').forEach(d => d.close());
  document.body.classList.add('locked');
  $('#login').hidden = false;
  $('#login-err').textContent = '';
  $('#login-form').password.focus();
}
function unlock() {
  S.locked = false;
  document.body.classList.remove('locked');
  $('#login').hidden = true;
  $('#login-form').reset();
  $('#btn-logout').hidden = !S.twoFactor;
  refresh(true);
}
$('#login-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  $('#login-submit').disabled = true;
  try {
    await api('POST', '/api/login', { password: f.password.value, code: digits(f.code.value) });
    unlock();
  } catch (e) {
    $('#login-err').textContent = e.message;
    f.code.value = '';
    f.code.focus();
  } finally {
    $('#login-submit').disabled = false;
  }
});
$('#btn-logout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch (e) { /* the session is gone either way */ }
  showLogin();
});

function tfaView(name) {
  for (const id of ['tfa-off', 'tfa-setup', 'tfa-on']) $('#' + id).hidden = id !== name;
  const f = $('#' + name);
  if (f.reset) f.reset();
}
$('#btn-2fa').addEventListener('click', async () => {
  try {
    const st = await api('GET', '/api/2fa');
    $('#tfa-token').textContent = st.api_token || '';
    tfaView(st.enabled ? 'tfa-on' : 'tfa-off');
    $('#dlg-2fa').showModal();
  } catch (e) { toast(e.message, true); }
});
$('#tfa-start').addEventListener('click', async () => {
  try {
    const s = await api('POST', '/api/2fa/setup');
    $('#tfa-qr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s.qr_svg);
    $('#tfa-secret').textContent = s.secret.replace(/(.{4})/g, '$1 ').trim();
    tfaView('tfa-setup');
    $('#tfa-setup').code.focus();
  } catch (e) { toast(e.message, true); }
});
$('#tfa-setup').addEventListener('submit', async ev => {
  ev.preventDefault();
  try {
    const r = await api('POST', '/api/2fa/enable', { code: digits(ev.target.code.value) });
    S.twoFactor = true;
    $('#btn-logout').hidden = false;
    $('#tfa-token').textContent = r.api_token;
    tfaView('tfa-on');
    toast('Two-factor login is on');
  } catch (e) { toast(e.message, true); }
});
$('#tfa-on').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  try {
    await api('POST', '/api/2fa/disable', { password: f.password.value, code: digits(f.code.value) });
    toast('Two-factor login is off');
    // The browser goes back to the password prompt (basic auth).
    location.reload();
  } catch (e) { toast(e.message, true); }
});

// checkSession shows the login form when 2FA is on and there is no session,
// including when 2FA was just turned on from the CLI. It returns true then.
async function checkSession() {
  try {
    const s = await api('GET', '/api/session');
    S.twoFactor = s.two_factor;
    $('#btn-logout').hidden = !s.two_factor;
    if (s.two_factor && !s.authenticated) { showLogin(); return true; }
  } catch (e) { /* refresh reports connection errors */ }
  return false;
}
checkSession().then(locked => { if (!locked) refresh(true); });
setInterval(refresh, 3000);
