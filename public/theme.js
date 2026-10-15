/* 首帧前确定主题：本地记忆优先，否则跟随系统。
   以不带 defer 的 <script> 放在 <head> 中原样执行，与内联版本行为一致（阻塞渲染前生效），
   避免暗色主题闪白。外置是为了让 CSP 的 script-src 不必放开 'unsafe-inline' */
(function () {
  try {
    var t = localStorage.getItem('fh-theme');
    if (t !== 'dark' && t !== 'light') {
      t = (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    }
    document.documentElement.dataset.theme = t;
  } catch (e) { document.documentElement.dataset.theme = 'light'; }
})();
