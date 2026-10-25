'use strict';
// ollamawg chat. Talks to Ollama's /api/chat through the tunnel proxy, which
// applies this device's role, model allowlist and rate limit. No
// dependencies; chats are kept in this browser only.

const $ = (sel, root = document) => root.querySelector(sel);
const STORE = 'ollamawg.chats';
const MODEL = 'ollamawg.model';
const S = { chats: [], current: null, me: null, models: [], abort: null };
const touch = matchMedia('(pointer: coarse)').matches;

/* ---------- storage (best effort: private mode can refuse it) ---------- */
function load() {
  try { S.chats = JSON.parse(localStorage.getItem(STORE) || '[]'); } catch { S.chats = []; }
}
function save() {
  S.chats.sort((a, b) => b.updated - a.updated);
  S.chats = S.chats.slice(0, 100);
  try { localStorage.setItem(STORE, JSON.stringify(S.chats)); } catch { /* storage full or blocked */ }
}
function pref(key, val) {
  try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch { return null; }
}

/* ---------- markdown: escape first, then format, so model output can't inject HTML ---------- */
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function inline(s) {
  const codes = [];
  s = s.replace(/`([^`\n]+)`/g, (_, c) => { codes.push(c); return `\u0000${codes.length - 1}\u0000`; });
  s = esc(s)
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*\w])\*([^*\n]+)\*(?!\w)/g, '$1<em>$2</em>')
    .replace(/(^|[^_\w])_([^_\n]+)_(?!\w)/g, '$1<em>$2</em>')
    .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
    .replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(codes[i])}</code>`);
}
function blocks(text) {
  const out = [];
  const lines = text.split('\n');
  let para = [], list = null;
  const flushPara = () => { if (para.length) { out.push(`<p>${para.map(inline).join('<br>')}</p>`); para = []; } };
  const flushList = () => { if (list) { out.push(`<${list.tag}>${list.items.map(i => `<li>${inline(i)}</li>`).join('')}</${list.tag}>`); list = null; } };
  for (const line of lines) {
    let m;
    if (!line.trim()) { flushPara(); flushList(); continue; }
    if ((m = line.match(/^(#{1,4})\s+(.*)$/))) { flushPara(); flushList(); out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`); continue; }
    if (/^\s*([-*_])\s*\1\s*\1[\s\1]*$/.test(line)) { flushPara(); flushList(); out.push('<hr>'); continue; }
    if ((m = line.match(/^>\s?(.*)$/))) { flushPara(); flushList(); out.push(`<blockquote>${inline(m[1])}</blockquote>`); continue; }
    if ((m = line.match(/^\s*([-*+]|\d+[.)])\s+(.*)$/))) {
      flushPara();
      const tag = /\d/.test(m[1]) ? 'ol' : 'ul';
      if (!list || list.tag !== tag) { flushList(); list = { tag, items: [] }; }
      list.items.push(m[2]);
      continue;
    }
    if (list && /^\s{2,}\S/.test(line)) { list.items[list.items.length - 1] += ' ' + line.trim(); continue; }
    flushList();
    para.push(line);
  }
  flushPara(); flushList();
  return out.join('');
}
function markdown(text) {
  // Split on code fences; an unclosed fence (mid-stream) still renders as code.
  const parts = text.split(/^```/m);
  let html = '';
  parts.forEach((part, i) => {
    if (i % 2 === 0) { html += blocks(part); return; }
    const nl = part.indexOf('\n');
    const lang = nl < 0 ? part.trim() : part.slice(0, nl).trim();
    const code = nl < 0 ? '' : part.slice(nl + 1).replace(/\n$/, '');
    html += `<div class="code"><div class="code-head"><span>${esc(lang || 'code')}</span><button type="button" data-copy>Copy</button></div><pre><code>${esc(code)}</code></pre></div>`;
  });
  return html;
}

/* ---------- models and identity ---------- */
// Mirrors the server's allowlist matching (policy.go: modelAllowed).
function allowed(allow, model) {
  if (!allow || !allow.length) return true;
  const norm = s => { s = s.toLowerCase().trim(); return s.includes(':') ? s : s + ':latest'; };
  const m = norm(model);
  return allow.some(a => {
    a = a.toLowerCase().trim();
    return a === '*' || (a.endsWith(':*') && m.startsWith(a.slice(0, -1))) || norm(a) === m;
  });
}
async function loadModels() {
  const sel = $('#model');
  try {
    const [me, tags] = await Promise.all([
      fetch('/_ollamawg/whoami').then(r => r.json()).catch(() => null),
      fetch('/api/tags').then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.error || r.statusText); return d; }),
    ]);
    S.me = me;
    S.models = (tags.models || []).map(m => m.name).filter(n => allowed(me && me.models, n)).sort();
    if (me) $('#who').innerHTML = `Signed in by WireGuard key as <strong>${esc(me.device)}</strong> (${esc(me.role)})`;
  } catch (e) {
    S.models = [];
    $('#empty-sub').textContent = 'Could not list models: ' + e.message;
  }
  if (!S.models.length) {
    sel.innerHTML = '<option value="">No models</option>';
    if (!$('#empty-sub').textContent.startsWith('Could not')) $('#empty-sub').textContent = 'No models are available to this device. Pull one on the server with `ollama pull llama3.2`.';
    return;
  }
  sel.innerHTML = S.models.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
  const want = (S.current && S.current.model) || pref(MODEL);
  sel.value = S.models.includes(want) ? want : S.models[0];
  updateSend();
}
$('#model').addEventListener('change', e => {
  pref(MODEL, e.target.value);
  if (S.current) { S.current.model = e.target.value; save(); }
});

/* ---------- rendering ---------- */
function renderList() {
  const nav = $('#chat-list');
  const day = 864e5, now = Date.now();
  const groups = [['Today', c => now - c.updated < day], ['Previous 7 days', c => now - c.updated < 7 * day], ['Older', () => true]];
  const seen = new Set();
  let html = '';
  for (const [label, test] of groups) {
    const items = S.chats.filter(c => !seen.has(c.id) && test(c));
    if (!items.length) continue;
    items.forEach(c => seen.add(c.id));
    html += `<div class="group-label">${label}</div>` + items.map(c => `
      <div class="chat-item${S.current && S.current.id === c.id ? ' active' : ''}">
        <a href="#${esc(c.id)}" data-open="${esc(c.id)}">${esc(c.title || 'New chat')}</a>
        <button type="button" data-del="${esc(c.id)}" aria-label="Delete chat"><svg viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg></button>
      </div>`).join('');
  }
  nav.innerHTML = html;
}
function msgEl(m) {
  const el = document.createElement('div');
  el.className = 'msg ' + m.role;
  if (m.role === 'user') el.textContent = m.content;
  else if (m.role === 'error') el.textContent = m.content;
  else fillAssistant(el, m, false);
  return el;
}
function fillAssistant(el, m, streaming) {
  let html = '';
  if (m.thinking) {
    const open = streaming && !m.content ? ' open' : '';
    html += `<details class="think"${open}><summary>${streaming && !m.content ? 'Thinking…' : 'Thought process'}</summary><div>${esc(m.thinking)}</div></details>`;
  }
  html += `<div class="md${streaming ? ' cursor' : ''}">${markdown(m.content || '')}</div>`;
  if (!streaming && m.content) {
    const stats = m.stats ? `<span>${esc(m.stats)}</span>` : '';
    html += `<div class="meta"><button type="button" data-copymsg>Copy</button>${stats}</div>`;
  }
  el.innerHTML = html;
  el._msg = m;
}
function renderThread() {
  const box = $('#messages');
  box.innerHTML = '';
  const msgs = S.current ? S.current.messages : [];
  msgs.forEach(m => box.append(msgEl(m)));
  $('#empty').hidden = msgs.length > 0;
  scrollDown(true);
}
let stick = true;
$('#thread').addEventListener('scroll', e => {
  const t = e.target;
  stick = t.scrollHeight - t.scrollTop - t.clientHeight < 80;
});
function scrollDown(force) {
  const t = $('#thread');
  if (force || stick) t.scrollTop = t.scrollHeight;
}

/* ---------- chats ---------- */
function newChat() {
  stop();
  S.current = null;
  location.hash = '';
  renderThread();
  renderList();
  closeDrawer();
  if (!touch) $('#input').focus();
}
function openChat(id) {
  const c = S.chats.find(x => x.id === id);
  if (!c) return newChat();
  stop();
  S.current = c;
  if (S.models.includes(c.model)) $('#model').value = c.model;
  renderThread();
  renderList();
  closeDrawer();
}
$('#new-chat').addEventListener('click', newChat);
$('#new-chat-side').addEventListener('click', newChat);
$('#chat-list').addEventListener('click', e => {
  const del = e.target.closest('[data-del]');
  if (del) {
    e.preventDefault();
    S.chats = S.chats.filter(c => c.id !== del.dataset.del);
    save();
    if (S.current && S.current.id === del.dataset.del) newChat(); else renderList();
    return;
  }
  const open = e.target.closest('[data-open]');
  if (open) { e.preventDefault(); location.hash = open.dataset.open; openChat(open.dataset.open); }
});
$('#clear-all').addEventListener('click', () => {
  if (!confirm('Delete all chats on this device?')) return;
  S.chats = [];
  save();
  newChat();
});

/* ---------- drawer ---------- */
function openDrawer() { $('#drawer').classList.add('open'); $('#scrim').hidden = false; }
function closeDrawer() { $('#drawer').classList.remove('open'); $('#scrim').hidden = true; }
$('#open-drawer').addEventListener('click', openDrawer);
$('#scrim').addEventListener('click', closeDrawer);

/* ---------- copy buttons ---------- */
// navigator.clipboard needs a secure context, and http://10.77.0.1 on a
// phone isn't one, so fall back to a hidden textarea and execCommand.
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* fall back */ }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
  document.body.append(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { /* unsupported */ }
  ta.remove();
  return ok;
}
$('#messages').addEventListener('click', async e => {
  const b = e.target.closest('[data-copy], [data-copymsg]');
  if (!b) return;
  const text = b.hasAttribute('data-copy') ? b.closest('.code').querySelector('code').textContent : b.closest('.msg')._msg.content;
  b.textContent = (await copyText(text)) ? 'Copied' : 'Copy failed';
  setTimeout(() => { b.textContent = 'Copy'; }, 1500);
});

/* ---------- composer ---------- */
const input = $('#input');
function grow() { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, innerHeight * 0.4) + 'px'; }
function updateSend() {
  const b = $('#send');
  b.classList.toggle('busy', !!S.abort);
  b.disabled = !S.abort && (!input.value.trim() || !$('#model').value);
  b.setAttribute('aria-label', S.abort ? 'Stop' : 'Send');
}
input.addEventListener('input', () => { grow(); updateSend(); });
input.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && !touch && !e.isComposing) {
    e.preventDefault();
    $('#composer').requestSubmit();
  }
});
$('#composer').addEventListener('submit', e => {
  e.preventDefault();
  if (S.abort) { stop(); return; }
  send();
});
function stop() {
  if (S.abort) S.abort.abort();
}

async function send() {
  const text = input.value.trim();
  const model = $('#model').value;
  if (!text || !model) return;
  if (!S.current) {
    S.current = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), title: text.slice(0, 60), model, messages: [], updated: Date.now() };
    S.chats.unshift(S.current);
    location.hash = S.current.id;
  }
  const chat = S.current;
  chat.model = model;
  chat.messages = chat.messages.filter(m => m.role !== 'error');
  chat.messages.push({ role: 'user', content: text });
  input.value = '';
  grow();
  renderThread();
  stick = true;

  const reply = { role: 'assistant', content: '', thinking: '' };
  const el = msgEl({ role: 'assistant', content: '' });
  $('#messages').append(el);
  fillAssistant(el, reply, true);
  scrollDown(true);

  S.abort = new AbortController();
  updateSend();
  let frame = 0;
  const paint = () => { frame = 0; fillAssistant(el, reply, true); scrollDown(); };
  try {
    const history = chat.messages.filter(m => m.role === 'user' || m.role === 'assistant').map(m => ({ role: m.role, content: m.content }));
    const r = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, messages: history, stream: true }),
      signal: S.abort.signal,
    });
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.error) throw new Error(ev.error);
        if (ev.message) {
          reply.content += ev.message.content || '';
          reply.thinking += ev.message.thinking || '';
        }
        if (ev.done && ev.eval_count && ev.eval_duration) {
          reply.stats = `${ev.eval_count} tokens · ${(ev.eval_count / (ev.eval_duration / 1e9)).toFixed(1)} tok/s`;
        }
        if (!frame) frame = requestAnimationFrame(paint);
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError') {
      if (!reply.content) el.remove();
      chat.messages.push({ role: 'error', content: err.message || 'Request failed' });
    }
  } finally {
    if (frame) cancelAnimationFrame(frame);
    S.abort = null;
    if (reply.content || reply.thinking) {
      if (!reply.thinking) delete reply.thinking;
      const errIdx = chat.messages.findIndex(m => m.role === 'error');
      if (errIdx >= 0) chat.messages.splice(errIdx, 0, reply); else chat.messages.push(reply);
    }
    chat.updated = Date.now();
    save();
    if (S.current === chat) renderThread();
    renderList();
    updateSend();
  }
}

/* ---------- start ---------- */
load();
renderList();
if (location.hash.length > 1) openChat(location.hash.slice(1)); else renderThread();
loadModels();
addEventListener('hashchange', () => {
  const id = location.hash.slice(1);
  if (id && (!S.current || S.current.id !== id)) openChat(id);
});
