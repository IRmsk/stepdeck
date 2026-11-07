'use strict';

const $ = (s, r = document) => r.querySelector(s);
const api = async (url, opt = {}) => {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opt,
    body: opt.body ? JSON.stringify(opt.body) : undefined,
  });
  let j = {};
  try { j = await r.json(); } catch (e) { j = { ok: false, message: '服务没响应' }; }
  if (r.status === 401 && j.needAdmin) showGate();
  return j;
};

function showGate(hint) {
  const g = document.getElementById('gate');
  if (!g) return;
  g.classList.add('show');
  if (hint) document.getElementById('gateHint').textContent = hint;
  setTimeout(() => document.getElementById('gatePass').focus(), 120);
}

function hideGate() {
  const g = document.getElementById('gate');
  if (g) g.classList.remove('show');
}

const S = {
  stepsInput: {}, accounts: [], requests: [], editId: null, cfgId: null };
const n = v => (v || 0).toLocaleString('en-US');

function toast(msg, ms = 1900) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove('show'), ms);
}

const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const provLabel = p => p === 'mock' ? '离线模拟'
  : p === 'zepp' ? 'Zepp' : p === 'zepp_dry' ? 'Zepp 演练' : p === 'keep' ? 'Keep' : p;

function card(a) {
  const ok = a.status === 'ok';
  const pct = a.target > 0 ? Math.min(100, Math.round((a.current || 0) / a.target * 100)) : 0;
  const modeTxt = a.mode === 'smart' ? '渐进爬坡' : '一次到位';
  return `
  <div class="acct ${a.custody ? '' : 'off'}" data-id="${a.id}">
    <div class="top">
      <span class="dot ${ok ? '' : 'err'}"></span>
      <div class="who">
        <div class="n">${esc(a.note || a.nickname || a.username)}</div>
        <div class="m">
          ${a.note ? `<span class="chip note">${esc(a.note)}</span>` : '<span class="chip ghost">没备注</span>'}
          <span>${esc(a.username)}</span>
          <span class="chip ${a.provider.startsWith('zepp') ? 'acc' : ''}">${provLabel(a.provider)}</span>
          ${a.custody ? '<span class="chip ok">托管中</span>' : ''}
        </div>
      </div>
      <div class="toggle ${a.custody ? 'on' : ''}" data-act="custody"></div>
    </div>

    <div class="progress">
      <div class="pbar"><div class="pfill" style="width:${pct}%"></div></div>
      <div class="pmeta">
        <span><b>${n(a.current)}</b> / ${a.target ? n(a.target) : '未设目标'}</span>
        <span>${pct}%</span>
      </div>
    </div>

    <div class="meta">
      <span>执行 <b>${a.exec_at || '未设置'}</b></span>
      <span>方式 <b>${modeTxt}</b></span>
      <span>已提交 <b>${a.submit_cnt}</b> 次</span>
      ${a.last_run ? `<span>上次 <b>${a.last_run.slice(5, 16)}</b></span>` : ''}
    </div>

    <div class="setline">
      <input class="setinput" type="number" inputmode="numeric" min="1" max="98800"
             value="${S.stepsInput[a.id] ?? (a.target || '')}"
             placeholder="${a.current ? n(a.current) : '输入步数'}">
      <button class="btn sm" data-act="set">改到</button>
      <span class="setnow">当前 <b>${n(a.current || 0)}</b><br><i>上限 98,800</i></span>
    </div>

    <div class="acts">
      <button class="btn sm ghost" data-act="submit">按目标提交</button>
      <button class="btn sm ghost" data-act="config">设置</button>
      <button class="btn sm ghost" data-act="note">备注</button>
      <button class="btn sm ghost" data-act="edit">修改</button>
      <button class="btn sm danger" data-act="delete">删除</button>
    </div>
  </div>`;
}

function render() {
  $('#accCount').textContent = S.accounts.length;
  $('#list').innerHTML = S.accounts.length
    ? S.accounts.map(card).join('')
    : `<div class="empty">还没有账号<br>点右上角「+ 添加账号」开始</div>`;
}

async function loadStats() {
  const r = await api('/api/stats');
  if (!r.ok) return;
  $('#sSteps').textContent = n(r.today_steps);
  $('#sCustody').textContent = `${r.custody_on} / ${r.accounts}`;
  $('#sSubmits').textContent = r.today_submits;
  $('#sNext').textContent = r.next_run || '未排程';
}

async function refresh() {
  const r = await api('/api/accounts');
  if (r.ok) S.accounts = r.accounts;
  render();
  loadStats();
}

const REQ_STATUS = {
  pending: ['待审核', 'wait'], approved: ['已通过', 'ok'],
  rejected: ['已驳回', 'err'], failed: ['执行失败', 'err'],
};

function reqRow(r) {
  const [txt, cls] = REQ_STATUS[r.status] || ['未知', ''];
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
    ${r.reason ? `<div class="rnote">驳回理由：${esc(r.reason)}</div>` : ''}
    ${r.status === 'pending' ? `<div class="racts">
        <button class="btn sm" data-req="${r.id}" data-do="approve">同意</button>
        <button class="btn sm danger" data-req="${r.id}" data-do="reject">不同意</button>
      </div>` : ''}
  </div>`;
}

async function loadRequests() {
  const r = await api('/api/requests');
  if (!r.ok) return;
  S.requests = r.requests || [];
  const pending = S.requests.filter(x => x.status === 'pending');
  const box = document.getElementById('reqs');
  if (!box) return;
  document.getElementById('reqCount').textContent = pending.length;
  box.innerHTML = (pending.length ? pending : S.requests.slice(0, 8)).map(reqRow).join('')
    || '<div class="empty">暂时没有申请</div>';
}

async function refreshLogs() {
  const r = await api('/api/logs?limit=80');
  if (!r.ok) return;
  $('#logs').innerHTML = r.logs.map(l =>
    `<div class="l ${l.level === 'error' ? 'err' : ''}"><span class="t">${l.ts.slice(5, 16)}</span>${esc(l.message)}</div>`
  ).join('') || '<div class="l">暂无日志</div>';
}

function acc(el) {
  return S.accounts.find(a => a.id === el.closest('.acct').dataset.id);
}

document.addEventListener('input', e => {
  const box = e.target.closest('.setinput');
  if (!box) return;
  const accEl = box.closest('.acct');
  if (accEl) S.stepsInput[accEl.dataset.id] = box.value;
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const box = e.target.closest('.setinput');
  if (!box) return;
  e.preventDefault();
  box.closest('.acct').querySelector('[data-act="set"]').click();
});

document.addEventListener('click', async e => {
  const rb = e.target.closest('[data-req]');
  if (rb) {
    const id = rb.dataset.req;
    if (rb.dataset.do === 'approve') {
      rb.disabled = true;
      const r = await api(`/api/requests/${id}/approve`, { method: 'POST', body: {} });
      rb.disabled = false;
      const msg = r.result ? (r.result.message || '') : (r.message || '');
      toast(r.ok ? `已同意：${msg}` : msg || '处理失败', r.ok ? 3000 : 4000);
    } else {
      const reason = prompt('驳回理由（可留空）', '');
      if (reason === null) return;
      const r = await api(`/api/requests/${id}/reject`, { method: 'POST', body: { reason } });
      toast(r.ok ? '已驳回' : (r.message || '处理失败'), 2400);
    }
    loadRequests(); refresh(); refreshLogs();
    return;
  }
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const a = acc(el);
  if (!a) return;

  switch (el.dataset.act) {
    case 'custody':
      await api(`/api/accounts/${a.id}/update`, { method: 'POST', body: { custody: !a.custody } });
      toast(!a.custody ? '已开启托管' : '已停止托管');
      refresh(); break;

    case 'set': {
      const box = el.closest('.acct').querySelector('.setinput');
      const v = parseInt(box.value, 10);
      if (!v || v <= 0) { toast('先输入要改到的步数', 2200); return; }
      S.stepsInput[a.id] = v;
      // 先把这个值存成目标，刷新后还能看到
      await api(`/api/accounts/${a.id}/update`, { method: 'POST', body: { target: v } });
      if (!a.tokenReady) {
        refresh();
        toast('步数已保存为目标（' + n(v) + '）；但账号还没登录成功，先去『修改』填对密码', 4200);
        return;
      }
      if (a.current && v <= a.current) {
        if (!confirm(`云端已有 ${a.current} 步，接口只往上加。\n继续提交会保持 ${a.current}，确定？`)) { refresh(); return; }
      }
      el.disabled = true;
      const r = await api(`/api/accounts/${a.id}/submit`, { method: 'POST', body: { steps: v } });
      el.disabled = false;
      toast(r.changed ? `已改到 ${n(r.submitted)} 步` : (r.message || '没变'), r.changed ? 1800 : 3600);
      refresh(); refreshLogs(); break;
    }

    case 'submit': {
      el.disabled = true;
      const r = await api(`/api/accounts/${a.id}/submit`, { method: 'POST', body: {} });
      el.disabled = false;
      toast(r.ok ? `已提交 ${n(r.submitted)} 步` : (r.message || '提交失败'), r.ok ? 1600 : 3200);
      refresh(); refreshLogs(); break;
    }

    case 'note': {
      const v = prompt('这个账号的备注（公开页会显示，留空则显示打码邮箱）', a.note || '');
      if (v === null) return;
      const r = await api(`/api/accounts/${a.id}/update`, { method: 'POST', body: { note: v.trim() } });
      toast(r.ok ? (v.trim() ? '备注已保存：' + v.trim() : '备注已清空') : '保存失败', 2400);
      refresh(); break;
    }

    case 'config':
      S.cfgId = a.id;
      $('#cTarget').value = a.target || '';
      $('#cExec').value = a.exec_at || '07:00';
      $('#cMode').value = a.mode || 'normal';
      $('#mCfg').classList.add('show'); break;

    case 'edit':
      S.editId = a.id;
      $('#eUser').value = a.username || '';
      $('#ePass').value = '';
      $('#eNote').value = a.note || '';
      $('#eProv').value = a.provider || 'zepp_dry';
      $('#mEdit').classList.add('show'); break;

    case 'delete':
      if (!confirm(`删除账号 ${a.username}？`)) return;
      await api(`/api/accounts/${a.id}`, { method: 'DELETE' });
      refresh(); break;
  }
});

document.querySelectorAll('[data-close]').forEach(b => {
  b.onclick = () => $('#' + b.dataset.close).classList.remove('show');
});

$('#btnAdd').onclick = () => $('#mAdd').classList.add('show');
$('#btnLogs').onclick = () => { $('#drawer').classList.add('show'); $('#scrim').classList.add('show'); refreshLogs(); };
$('#drawerClose').onclick = $('#scrim').onclick = () => {
  $('#drawer').classList.remove('show'); $('#scrim').classList.remove('show');
};

$('#doProbe').onclick = async () => {
  const u = $('#fUser').value.trim();
  if (!u) return toast('先填账号');
  const m = $('#probeMsg');
  m.textContent = '检测中…';
  const r = await api('/api/probe', { method: 'POST', body: { username: u } });
  if (!r.ok) { m.textContent = r.message || '检测失败'; return; }
  m.textContent = r.exists ? '✓ 该账号已注册（可以登录）' : '✗ Zepp 说没有这个账号';
  m.style.color = r.exists ? '#33d6a6' : '#ff6b6b';
};

$('#doAdd').onclick = async () => {
  const b = $('#doAdd'); b.disabled = true;
  const r = await api('/api/accounts', {
    method: 'POST',
    body: { username: $('#fUser').value.trim(), password: $('#fPass').value,
            provider: $('#fProv').value, note: ($('#fNote')?.value || '').trim() },
  });
  b.disabled = false;
  if (!r.ok) return toast(r.message || '添加失败', 3200);
  $('#mAdd').classList.remove('show');
  $('#fUser').value = ''; $('#fPass').value = ''; if ($('#fNote')) $('#fNote').value = '';
  toast('已添加');
  refresh(); refreshLogs();
};

$('#doCfg').onclick = async () => {
  const r = await api(`/api/accounts/${S.cfgId}/update`, {
    method: 'POST',
    body: {
      target: parseInt($('#cTarget').value || '0', 10) || 0,
      exec_at: $('#cExec').value || '07:00',
      mode: $('#cMode').value,
    },
  });
  if (!r.ok) return toast('保存失败');
  $('#mCfg').classList.remove('show');
  toast('已保存');
  refresh();
};

$('#doEdit').onclick = async () => {
  const b = $('#doEdit'); b.disabled = true;
  const body = { username: $('#eUser').value.trim(), provider: $('#eProv').value,
                 note: $('#eNote').value.trim() };
  if ($('#ePass').value) body.password = $('#ePass').value;
  const r = await api(`/api/accounts/${S.editId}/edit`, { method: 'POST', body });
  b.disabled = false;
  if (!r.ok) return toast(r.message || '保存失败', 3200);
  $('#mEdit').classList.remove('show');
  toast(r.relogin ? '已保存并重新登录' : '已保存');
  refresh(); refreshLogs();
};

/* ---------------- 登录门 ---------------- */
const gateBtn = document.getElementById('gateBtn');
const gatePass = document.getElementById('gatePass');

async function tryLogin() {
  const pw = gatePass.value;
  if (!pw) return toast('先输入密码');
  gateBtn.disabled = true;
  const r = await api('/api/admin/login', { method: 'POST', body: { password: pw } });
  gateBtn.disabled = false;
  if (!r.ok) return toast(r.message || '登录失败', 3000);
  gatePass.value = '';
  hideGate();
  boot();
}

if (gateBtn) gateBtn.onclick = tryLogin;
if (gatePass) gatePass.addEventListener('keydown', e => { if (e.key === 'Enter') tryLogin(); });

const lo = document.getElementById('btnLogout');
if (lo) lo.onclick = async () => {
  await api('/api/admin/logout', { method: 'POST', body: {} });
  location.reload();
};

const bp = document.getElementById('btnPw');
if (bp) bp.onclick = async () => {
  const old = prompt('原密码');
  if (!old) return;
  const nw = prompt('新密码（至少 4 位）');
  if (!nw) return;
  const r = await api('/api/admin/password', { method: 'POST', body: { old, new: nw } });
  toast(r.ok ? '密码已更新，请重新登录' : (r.message || '改密码失败'), 3000);
  if (r.ok) setTimeout(() => location.reload(), 1200);
};

const ra = document.getElementById('btnReqAll');
if (ra) ra.onclick = () => loadRequests();

async function boot() {
  const me = await fetch('/api/admin/me').then(r => r.json()).catch(() => ({}));
  if (!me.admin) {
    if (me.ready === false) showGate('第一次使用：设置一个管理员密码');
    else showGate('输入管理员密码进入');
    return;
  }
  hideGate();
  refresh(); refreshLogs(); loadRequests();
  setInterval(refresh, 5000);
  setInterval(loadRequests, 6000);
  setInterval(() => { if ($('#drawer').classList.contains('show')) refreshLogs(); }, 8000);
}

boot();
