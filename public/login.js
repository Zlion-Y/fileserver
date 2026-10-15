'use strict';
// 登录页。原为 login.html 内联脚本，外置以让 CSP 的 script-src 不必放开 'unsafe-inline'
// 站点根路径：与 app.js 同一套约定 —— 子路径部署时 <html data-base="/子路径">
const BASE = (() => {
  const b = document.documentElement.dataset.base || '';
  return b === '/' ? '' : b.replace(/\/+$/, '');
})();

const form = document.getElementById('form');
const btn = document.getElementById('btn');
const err = document.getElementById('err');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const user = document.getElementById('user').value.trim();
  const pass = document.getElementById('pass').value;
  if (!user || !pass) { err.textContent = '请输入用户名和密码'; return; }
  btn.disabled = true; err.textContent = '';
  try {
    const r = await fetch(BASE + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: user, pass: pass })
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      location.href = BASE + '/';
      return;
    }
    err.textContent = d.error || ('登录失败 ' + r.status);
  } catch (ex) {
    err.textContent = '网络错误，请重试';
  }
  btn.disabled = false;
});
