'use strict';

const $ = (s, r = document) => r.querySelector(s);
const api = async (url, opt = {}) => {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opt,
    body: opt.body ? JSON.stringify(opt.body) : undefined,
  });
  try { return await r.json(); } catch (e) { return { ok: false, message: '服务没响应' }; }
};

const n = v => (v || 0).toLocaleString('en-US');
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const S = { accounts: [], picked: null, who: localStorage.getItem('sd_who') || '' };

function toast(msg, ms = 2200) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove('show'), ms);
}

const STATUS = {
  pending: ['待审核', 'wait'],
  approved: ['已通过', 'ok'],
  rejected: ['被驳回', 'err'],
  failed: ['执行失败', 'err'],
};

function reqItem(r) {
  const [txt, cls] = STATUS[r.status] || ['未知', ''];
  const when = (r.handled_at || r.created_at || '').slice(5, 16).replace('T', ' ');
  return `<div class="reqitem ${cls}">
    <div class="rtop">
      <b>${esc(r.acc_note || r.account || '账号')}</b>
      <span class="badge ${cls}">${txt}</span>
    </div>
    <div class="rmeta">
      <span>${n(r.steps)} 步</span>
      <span>${esc(r.requester || '匿名')}</span>
      <span>${when}</span>
    </div>
    ${r.note ? `<div class="rnote">${esc(r.note)}</div>` : ''}
    ${r.reason ? `<div class="rnote err">驳回：${esc(r.reason)}</div>` : ''}
    ${r.result && r.status === 'approved' ? `<div class="rnote ok">${esc(String(JSON.parse(r.result || '{}').message || ''))}</div>` : ''}
  </div>`;
}

function renderAccounts() {
  $('#accCount').textContent = S.accounts.length;
  $('#list').innerHTML = S.accounts.length ? S.accounts.map(a => `
    <div class="pcard ${S.picked === a.id ? 'sel' : ''}" data-id="${a.id}">
      <div class="prow">
        <div class="pname">${esc(a.note || a.account)}</div>
        <div class="badge ${a.status === 'ok' ? 'ok' : 'wait'}">${n(a.current)} 步</div>
      </div>
      <div class="pmeta">${esc(a.account)}${a.note ? ' · ' + esc(a.note) : ''}</div>
    </div>`).join('') : '<div class="empty">还没有可申请的账号</div>';
}

async function loadAccounts() {
  const r = await api('/api/public/accounts');
  if (r.ok) S.accounts = r.accounts;
  renderAccounts();
}

async function loadMine() {
  if (!S.who) {
    $('#mine').innerHTML = '<div class="empty">填一个称呼就能看到自己的申请记录</div>';
    return;
  }
  const r = await api('/api/public/requests?who=' + encodeURIComponent(S.who));
  const rows = (r.requests || []).filter(x => (x.requester || '') === S.who);
  $('#mine').innerHTML = rows.length ? rows.map(reqItem).join('')
    : '<div class="empty">还没有申请记录</div>';
}

document.addEventListener('click', e => {
  const c = e.target.closest('.pcard');
  if (!c) return;
  S.picked = c.dataset.id;
  renderAccounts();
  const a = S.accounts.find(x => x.id === S.picked);
  $('#pTip').textContent = a
    ? `已选：${a.note || a.account}（当前 ${n(a.current)} 步）`
    : '先点上面选一个账号';
});

$('#pSend').onclick = async () => {
  if (!S.picked) return toast('先选一个账号');
  const steps = parseInt($('#pSteps').value, 10);
  if (!steps || steps <= 0) return toast('步数要大于 0');
  if (steps > 98800) return toast('单日上限 98,800');
  const who = $('#pWho').value.trim() || S.who || '匿名';
  if (who !== '匿名') { localStorage.setItem('sd_who', who); S.who = who; }
  const b = $('#pSend');
  b.disabled = true;
  const r = await api('/api/public/requests', {
    method: 'POST',
    body: { account_id: S.picked, steps, requester: who, note: $('#pNote').value.trim() },
  });
  b.disabled = false;
  toast(r.ok ? (r.message || '已提交') : (r.message || '提交失败'), r.ok ? 2400 : 3200);
  if (r.ok) { $('#pNote').value = ''; $('#pSteps').value = ''; loadMine(); }
};

$('#pRefresh').onclick = () => { loadAccounts(); loadMine(); };

(function boot() {
  $('#pWho').value = S.who || '';
  loadAccounts();
  loadMine();
  setInterval(loadAccounts, 10000);
  setInterval(loadMine, 8000);
})();
