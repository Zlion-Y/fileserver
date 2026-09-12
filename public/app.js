'use strict';
/* FileHub 前端：侧边栏导航 + 文件表格 + 分享/搜索/日志 */
const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
// 防御式绑定：元素缺失时只跳过，不抛异常中断后续初始化
function on(selOrEl, ev, fn) {
  const el = typeof selOrEl === 'string' ? $(selOrEl) : selOrEl;
  if (el) el.addEventListener(ev, fn);
  return el;
}

let state = { rootDir: '', curPath: '', quick: {}, platform: '', entries: [], searching: false };
let sharesMap = {}; // relPath -> share（用于表格「分享状态」列）

/* ---------------- 工具 ---------------- */
function fmtSize(b) {
  if (b === null || b === undefined) return '—';
  if (b < 1024) return b + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1, n = b;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + u[i];
}
function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function fmtLeft(ts) {
  if (!ts) return '永久有效';
  const s = Math.floor((ts - Date.now()) / 1000);
  if (s <= 0) return '已过期';
  if (s < 60) return s + ' 秒后过期';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟后过期';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时后过期';
  return Math.floor(s / 86400) + ' 天后过期';
}
async function api(url, opt) {
  const r = await fetch(url, opt);
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok && r.status === 401 && data && data.code === 'AUTH') {
    location.href = '/login';
    return null;
  }
  if (!r.ok && r.status === 409 && data && data.code === 'NO_ROOT') { showSetup(); return null; }
  if (!r.ok) {
    const err = new Error((data && data.error) || ('请求失败 ' + r.status));
    err.status = r.status;
    err.data = data;   // 带上响应体（如分片进度 received），调用方可据此恢复
    throw err;
  }
  return data;
}
let toastTimer;
function toast(msg) {
  const t = $('#toast');
  if (!t) return;
  t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2200);
}
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text); return true;
    }
  } catch (e) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch (e) { return false; }
}
/* ---------------- 主题切换 ---------------- */
function applyThemeUI() {
  const dark = document.documentElement.dataset.theme === 'dark';
  const moon = $('#ic-moon'), sun = $('#ic-sun'), label = $('#theme-label');
  if (moon) moon.classList.toggle('hidden', dark);
  if (sun) sun.classList.toggle('hidden', !dark);
  if (label) label.textContent = dark ? '浅色模式' : '深色模式';
}
on('#btn-theme', 'click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('fh-theme', next); } catch (e) {}
  applyThemeUI();
  if (statsDays) drawStatsChart(); // 图表配色跟随主题
});
applyThemeUI();

const svgFile = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>`;
const svgDir = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`;
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const joinPath = (a, b) => (a ? a.replace(/\/$/, '') + '/' : '') + b;
const fileExt = (name) => {
  const i = name.lastIndexOf('.');
  return i > 0 && i < name.length - 1 ? name.slice(i + 1).toUpperCase() : 'FILE';
};

/* ---------------- 启动 ---------------- */
(async function init() {
  const s = await api('/api/state');
  if (!s) return;
  state.quick = s.quick || {};
  state.platform = s.platform;
  if (s.disk) renderDisk(s.disk);
  if (!s.initialized) showSetup();
  else { state.rootDir = s.rootDir; showMain(); }
})();

function renderDisk(disk) {
  const used = disk.total - disk.free;
  const pct = disk.total > 0 ? Math.round(used / disk.total * 100) : 0;
  const p = $('#disk-pill-pct'), b = $('#disk-pill-bar'), pill = $('#disk-pill');
  const f = $('#disk-pill-free');
  if (p) p.textContent = pct + '%';
  if (b) { b.style.width = pct + '%'; b.classList.toggle('warn', pct >= 85); }
  if (f) f.textContent = disk.total > 0 ? `剩余 ${fmtSize(disk.free)}` : '';
  if (pill) pill.title = `磁盘空间：已使用 ${fmtSize(used)} / ${fmtSize(disk.total)}，剩余 ${fmtSize(disk.free)}（${pct}%）`;
}

function showSetup() {
  const s = $('#setup'); if (s) s.classList.remove('hidden');
  const m = $('#main'); if (m) m.classList.add('hidden');
  // 与 showMain 对称：设置页确定显示后移除 preload（body.preload 会隐藏 #setup）
  requestAnimationFrame(() => document.body.classList.remove('preload'));
}
async function showMain() {
  const s = $('#setup'); if (s) s.classList.add('hidden');
  const m = $('#main'); if (m) m.classList.remove('hidden');
  // 恢复期间先全部隐藏（含顶栏/面包屑），避免闪过默认「所有文件」视图
  $$('.view').forEach(v => v.classList.add('hidden'));
  const tb = $('#topbar'); if (tb) tb.classList.add('hidden');
  const cb = $('#crumbbar'); if (cb) cb.classList.add('hidden');
  await refreshShares();
  // 恢复上次离开时的目录与视图（刷新浏览器不回到默认页）
  let savedView = 'files', savedPath = '';
  try {
    savedView = localStorage.getItem('fh-view') || 'files';
    savedPath = localStorage.getItem('fh-path') || '';
  } catch (e) {}
  if (!$('#view-' + savedView)) savedView = 'files';
  state.curPath = savedPath;
  switchView(savedView);
  // 恢复完成后再恢复进度条动画（本帧渲染完成即移除）
  requestAnimationFrame(() => document.body.classList.remove('preload'));
}

/* ---------------- 设置目录 ---------------- */
on('#setup-confirm', 'click', async () => {
  const v = $('#setup-path').value.trim();
  if (!v) return toast('请输入目录路径');
  try {
    const r = await api('/api/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rootDir: v })
    });
    if (!r) return;
    state.rootDir = r.rootDir;
    toast('目录已设置');
    showMain();
  } catch (e) { toast(e.message); }
});
$$('.chip[data-quick]').forEach(c => {
  c.addEventListener('click', () => {
    const v = state.quick[c.dataset.quick];
    if (v) $('#setup-path').value = v; else toast('该目录不可用');
  });
});
on('#setup-browse', 'click', () => {
  const box = $('#setup-browser');
  if (!box) return;
  const show = box.classList.contains('hidden');
  box.classList.toggle('hidden', !show);
  if (show) loadDir('', '#dir-crumb-setup', '#dir-list-setup');
});
on('#setup-dir-ok', 'click', () => {
  if (!dirState.cur) return toast('请先浏览并进入目标目录');
  $('#setup-path').value = dirState.cur;
  const box = $('#setup-browser'); if (box) box.classList.add('hidden');
});

/* ---------------- 视图切换（文件 / 分享管理 / 检查更新） ---------------- */
let curView = 'files';
function switchView(name) {
  curView = name;
  try { localStorage.setItem('fh-view', name); } catch (e) {}
  $$('.view').forEach(v => v.classList.add('hidden'));
  const target = $('#view-' + name);
  if (target) target.classList.remove('hidden');
  $$('.nav-item[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  // 顶栏搜索与面包屑只属于文件视图
  const inFiles = name === 'files';
  const tb = $('#topbar');
  if (tb) tb.classList.toggle('hidden', !inFiles);
  const cb = $('#crumbbar');
  if (cb) cb.classList.toggle('hidden', !inFiles);
  if (name === 'shares') { loadShares(); loadStats(); }
  if (name === 'update') loadVersionInfo();
  if (name === 'security') loadSessionsList();
  if (name === 'chdir') enterChdirView();
  if (name === 'tidy') enterTidyView();
  if (name === 'trash') loadTrash();
  if (name === 'files') { clearSearch(); loadList(state.curPath); }
}
// 所有带 data-view 的导航项统一走视图切换
$$('.nav-item[data-view]').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
on('#btn-logout', 'click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
  location.href = '/login';
});

/* ---------------- 目录浏览器（内嵌，无弹窗） ---------------- */
const dirState = { cur: '' }; // 修改目录视图 / 设置页浏览的当前目录
// 在指定 crumb/list 容器里渲染 st.cur 目录的子目录浏览（st 缺省用 dirState）
async function loadDir(p, crumbSel, listSel, st) {
  st = st || dirState;
  st.cur = p;
  const d = await api('/api/browse?path=' + encodeURIComponent(p));
  if (!d) return;
  const c = $(crumbSel), list = $(listSel);
  if (!c || !list) return;
  c.innerHTML = '';
  if (d.path) {
    const parts = d.path.split(/[\\/]/).filter(Boolean);
    let acc = '';
    const mkRoot = document.createElement('button');
    mkRoot.textContent = d.path.startsWith('/') ? '根目录' : '我的电脑';
    mkRoot.addEventListener('click', () => loadDir('', crumbSel, listSel, st));
    c.appendChild(mkRoot);
    parts.forEach((pt, i) => {
      acc = d.path.startsWith('/') ? acc + '/' + pt : (acc ? acc + '\\' + pt : pt + '\\');
      const sep = document.createElement('span'); sep.className = 'sep'; sep.textContent = '›'; c.appendChild(sep);
      const b = document.createElement('button'); b.textContent = pt;
      const target = acc; b.addEventListener('click', () => loadDir(target, crumbSel, listSel, st));
      if (i === parts.length - 1) { b.className = 'cur'; }
      c.appendChild(b);
    });
  } else {
    const s = document.createElement('span'); s.className = 'cur'; s.textContent = '选择磁盘';
    c.appendChild(s);
  }
  list.innerHTML = '';
  if (!d.entries.length) {
    list.innerHTML = `<div class="dir-empty">${esc(d.error || '没有子文件夹')}</div>`;
    return;
  }
  d.entries.forEach(e => {
    const el = document.createElement('div');
    el.className = 'dir-item';
    el.innerHTML = svgDir + `<span>${esc(e.name)}</span>`;
    el.addEventListener('click', () => loadDir(e.path, crumbSel, listSel, st));
    list.appendChild(el);
  });
}

/* ---------------- 修改目录视图 ---------------- */
function enterChdirView() {
  const cur = $('#chdir-current');
  if (cur) cur.textContent = state.rootDir || '（未设置）';
  const inp = $('#chdir-path');
  if (inp) inp.value = state.rootDir || '';
  loadDir(state.rootDir || '', '#dir-crumb', '#dir-list');
}
on('#chdir-go', 'click', () => {
  const v = ($('#chdir-path').value || '').trim();
  if (!v) return toast('请输入路径');
  loadDir(v, '#dir-crumb', '#dir-list');
});
on('#chdir-path', 'keydown', (e) => { if (e.key === 'Enter') $('#chdir-go').click(); });
on('#btn-dir-ok', 'click', () => applyRootDir(dirState.cur));
async function applyRootDir(p) {
  if (!p) return toast('请先在下方浏览并进入目标目录');
  try {
    const r = await api('/api/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rootDir: p })
    });
    if (!r) return;
    state.rootDir = r.rootDir;
    clearSearch(); loadList(''); toast('目录已修改');
    switchView('files');
  } catch (e) { toast(e.message); }
}

/* ---------------- 文件表格 ---------------- */
// 排序：文件夹始终在前，同类内按所选维度
function sortEntries(entries) {
  const mode = ($('#sort-select') || {}).value || 'time-desc';
  const dirFirst = (a, b) => (b.isDir - a.isDir);
  const byName = (a, b) => a.name.localeCompare(b.name, 'zh-CN', { numeric: true });
  const bySize = (a, b) => (a.size || 0) - (b.size || 0);
  const byTime = (a, b) => (a.mtime || 0) - (b.mtime || 0);
  const key = mode.startsWith('name') ? byName : mode.startsWith('size') ? bySize : byTime;
  const asc = mode.endsWith('asc') ? 1 : -1;
  return entries.slice().sort((a, b) => dirFirst(a, b) || asc * key(a, b));
}
function applyFilter(entries) {
  const f = ($('#filter-select') || {}).value || 'all';
  let out = entries;
  if (f === 'file') out = out.filter(e => !e.isDir);
  if (f === 'dir') out = out.filter(e => e.isDir);
  const sz = ($('#size-select') || {}).value || 'all';
  const MB = 1024 * 1024, GB = 1024 * MB;
  if (sz === 'gt-100mb') out = out.filter(e => !e.isDir && (e.size || 0) > 100 * MB);
  if (sz === 'gt-1gb') out = out.filter(e => !e.isDir && (e.size || 0) > GB);
  if (sz === 'lt-1mb') out = out.filter(e => !e.isDir && (e.size || 0) < MB);
  return out;
}
/* ---------------- 类型图标 ---------------- */
const ARC_EXT = ['ZIP','RAR','7Z','TAR','GZ','XZ','BZ2','TGZ','ISO'];
const IMG_EXT = ['PNG','JPG','JPEG','GIF','WEBP','BMP','SVG','ICO','HEIC'];
const VID_EXT = ['MP4','MKV','AVI','MOV','WMV','FLV','WEBM','M4V','TS'];
const AUD_EXT = ['MP3','FLAC','WAV','AAC','OGG','M4A','WMA'];
const DOC_EXT = ['PDF','DOC','DOCX','XLS','XLSX','PPT','PPTX','TXT','MD','CSV','EPUB'];
const KIND_SVG = {
  dir: svgDir,
  arc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8"/><rect x="1" y="3" width="22" height="5" rx="1"/><path d="M10 12h4"/></svg>',
  img: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg>',
  vid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="m22 8-6 4 6 4V8z"/><rect x="2" y="6" width="14" height="12" rx="2"/></svg>',
  aud: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>',
  doc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h6"/></svg>',
  file: svgFile,
};
function typeKind(e) {
  if (e.isDir) return 'dir';
  const ext = fileExt(e.name);
  if (ARC_EXT.includes(ext)) return 'arc';
  if (IMG_EXT.includes(ext)) return 'img';
  if (VID_EXT.includes(ext)) return 'vid';
  if (AUD_EXT.includes(ext)) return 'aud';
  if (DOC_EXT.includes(ext)) return 'doc';
  return 'file';
}
function shareTagFor(rel, isDir) {
  const s = sharesMap[rel];
  if (!s) return '<span class="tag">未分享</span>';
  const inner = s.alive
    ? (s.expiresAt ? `<span class="tag blue">已分享 · ${fmtLeft(s.expiresAt)}</span>` : '<span class="tag green">已分享 · 永久</span>')
    : '<span class="tag red">已失效</span>';
  return `<a class="tag-link" data-jump="${esc(s.token)}" title="点击查看分享详情">${inner}</a>`;
}
function mkAction(text, cls, fn) {
  const b = document.createElement('button');
  b.className = 'btn ' + cls; b.textContent = text;
  b.addEventListener('click', (ev) => { ev.stopPropagation(); fn(); });
  return b;
}
function renderTable(entries, opts) {
  const searchMode = !!(opts && opts.search);
  const list = $('#list');
  if (!list) return;
  const empty = $('#empty');
  // 相册开关只在目录浏览时有意义：搜索结果固定渲染进表格
  const gb = $('#btn-gallery');
  if (gb) gb.classList.toggle('hidden', searchMode);
  if (!entries.length) {
    if (empty) {
      empty.classList.remove('hidden');
      const p = empty.querySelector('p');
      if (p) p.textContent = searchMode ? '没有匹配的文件' : '这个文件夹是空的，把文件拖进来即可上传';
    }
  } else if (empty) {
    empty.classList.add('hidden');
  }
  if (searchMode) {
    // 搜索结果量小（SEARCH_LIMIT 限制）：客户端排序筛选 + 全量渲染。
    // 搜索结果固定渲染进表格：强制显示表格并隐藏相册（否则结果进了一个
    // 仍被隐藏的容器，页面上什么都看不到）
    const shown = applyFilter(sortEntries(entries));
    pageState = { items: shown, total: shown.length, hasMore: false, loading: false, search: true };
    const wrap = document.querySelector('.table-wrap');
    if (wrap) wrap.classList.remove('hidden');
    const g = $('#gallery');
    if (g) g.classList.add('hidden');
    list.innerHTML = '';
    shown.forEach(e => list.appendChild(buildRow(e, true)));
  } else {
    pageState.search = false;
    if (galleryOn) renderGallery();
    else renderVirtual();
  }
  const ci = $('#count-info');
  if (ci) ci.textContent = searchMode ? `共 ${pageState.items.length} 个结果` : `共 ${pageState.total || pageState.items.length} 项`;
  updateBatchUI();
}

/* ---------------- 相册视图 ----------------
   图片文件夹的缩略图网格：服务端仍只吐原始文件字节，<img loading=lazy>
   让浏览器只拉取滚入视口的图片（客户端渲染，零服务端加工） */
let galleryOn = false;
try { galleryOn = localStorage.getItem('fh-gallery') === '1'; } catch (e) {}

// syncListContainer 统一同步「表格 / 相册」两个容器的互斥可见性。
// 必须在 renderVirtual 和 renderGallery 两边都调用：renderGallery 切入相册时
// 会隐藏 .table-wrap，切回列表的 renderVirtual 若不把它恢复，列表就"消失"了
// （数据其实渲染了，容器还是 display:none），只能靠刷新页面恢复——实测踩过的坑
function syncListContainer() {
  const wrap = document.querySelector('.table-wrap');
  const g = $('#gallery');
  if (wrap) wrap.classList.toggle('hidden', galleryOn);
  if (g) g.classList.toggle('hidden', !galleryOn);
}

function applyGalleryBtn() {
  const b = $('#btn-gallery');
  if (!b) return;
  b.textContent = galleryOn ? '列表' : '相册';
  b.classList.toggle('btn-primary', galleryOn);
  b.classList.toggle('btn-soft', !galleryOn);
}

function renderGallery() {
  const g = $('#gallery');
  if (!g) return;
  syncListContainer();
  if (!galleryOn) return;
  g.innerHTML = '';
  const frag = document.createDocumentFragment();
  (pageState.items || []).forEach(e => {
    const rel = joinPath(e.dirPath || '', e.name);
    const tile = document.createElement('div');
    tile.className = 'g-tile';
    const kind = typeKind(e);
    const thumb = document.createElement('div');
    thumb.className = 'g-thumb';
    if (!e.isDir && kind === 'img') {
      const img = document.createElement('img');
      img.loading = 'lazy';
      img.decoding = 'async';
      img.alt = e.name;
      img.src = '/api/download?path=' + encodeURIComponent(rel);
      thumb.appendChild(img);
    } else {
      thumb.innerHTML = `<div class="fi ${kind === 'dir' ? 'dir' : 'k-' + kind}">${KIND_SVG[kind]}</div>`;
    }
    const cap = document.createElement('div');
    cap.className = 'g-name';
    cap.textContent = e.name;
    cap.title = e.isDir ? e.name : `${e.name} · ${fmtSize(e.size)}`;
    tile.appendChild(thumb);
    tile.appendChild(cap);
    tile.addEventListener('click', () => {
      if (e.isDir) { clearSearch(); loadList(rel); return; }
      if (extKindOf(e.name)) { openPreview(rel, e.name, e.size); return; }
      location.href = '/api/download?path=' + encodeURIComponent(rel);
    });
    frag.appendChild(tile);
  });
  g.appendChild(frag);
  // 分页加载与表格共用同一 loadListMore；此处补一个「加载更多」入口
  if (pageState.hasMore) {
    const more = document.createElement('div');
    more.className = 'g-more';
    more.textContent = `已加载 ${(pageState.items || []).length}/${pageState.total} 项，点击加载更多…`;
    more.addEventListener('click', () => loadListMore(true));
    g.appendChild(more);
  }
}
// 列表/相册统一刷新入口（数据变化后调用）
function refreshListView() {
  if (pageState.search) renderTable(pageState.items, { search: true });
  else renderTable(pageState.items);
}
on('#btn-gallery', 'click', () => {
  galleryOn = !galleryOn;
  try { localStorage.setItem('fh-gallery', galleryOn ? '1' : '0'); } catch (e) {}
  applyGalleryBtn();
  refreshListView();
});
applyGalleryBtn();

/* ---------------- 虚拟滚动 + 分页加载 ----------------
   大目录（几千项）不再全量渲染 DOM：只保留可见窗口内的行（上下用占位行撑高），
   勾选状态存在 selMap（DOM 复用后勾选必须走数据层），滚动接近底部自动取下一页 */
const PAGE_SIZE = 500;
// 与 CSS .table tbody tr { height:54px } 对应的初始估值（实测行高 54.5，
// td 下边框 1px 未完全计入 box-sizing）。但行高会随视口变化：窄屏下操作按钮换行、
// 文件名换行都会让真实行高变大，固定常数会让虚拟滚动的占位高度与实际不符，
// 表现为滚动时跳行/出现空白。因此渲染后用真实 DOM 校准一次（见 measureRowHeight）。
let VROW = 54.5;
let pageState = { items: [], total: 0, hasMore: false, loading: false, search: false };
const selMap = new Map(); // rel -> { path, name, isDir }

function buildRow(e, searchMode) {
  const rel = searchMode ? e.path : joinPath(e.dirPath || '', e.name);
  const tr = document.createElement('tr');
  const kind = typeKind(e);
  const typeText = e.isDir ? '文件夹' : fileExt(e.name);
  const nameBlock = searchMode && e.path
    ? `<div class="name-text">${esc(e.name)}</div><div class="path-sub">${esc(e.path)}</div>`
    : `<div class="name-text">${esc(e.name)}</div>`;
  tr.innerHTML = `
    <td class="th-check"><input type="checkbox" class="row-check" data-path="${esc(rel)}" data-name="${esc(e.name)}" data-isdir="${e.isDir ? 1 : 0}"></td>
    <td><div class="td-name">
      <div class="fi ${kind === 'dir' ? 'dir' : 'k-' + kind}">${KIND_SVG[kind]}</div>
      <div class="main-col">${nameBlock}</div>
    </div></td>
    <td class="cell-dim cell-type">${esc(typeText)}</td>
    <td class="cell-dim cell-size">${e.isDir ? '—' : fmtSize(e.size)}</td>
    <td class="cell-dim cell-time">${fmtTime(e.mtime)}</td>
    <td>${shareTagFor(rel, e.isDir)}</td>
    <td><div class="cell-actions"></div></td>`;
  // 勾选状态来自 selMap：虚拟滚动下 DOM 只保留可见行，勾选必须存数据层
  const cb = tr.querySelector('.row-check');
  if (cb) {
    cb.checked = selMap.has(rel);
    cb.addEventListener('change', () => {
      if (cb.checked) selMap.set(rel, { path: rel, name: e.name, isDir: !!e.isDir });
      else selMap.delete(rel);
      updateBatchUI();
    });
  }
  const actions = tr.querySelector('.cell-actions');
  const open = () => { clearSearch(); loadList(rel); };
  if (e.isDir) {
    tr.querySelector('.td-name').classList.add('clickable');
    tr.querySelector('.name-text').addEventListener('click', open);
    actions.appendChild(mkAction('打开', 'btn-soft mini', open));
    actions.appendChild(mkAction('分享', 'btn-soft mini', () => openShare(rel, e.name, null)));
    actions.appendChild(mkAction('重命名', 'btn-soft mini', () => renameItem(rel, e.name)));
    actions.appendChild(mkAction('移动', 'btn-soft mini', () => moveItem(rel, e.name, e.isDir)));
    actions.appendChild(mkAction('删除', 'btn-soft mini btn-danger', () => delItem(rel, e.name, true)));
  } else {
    // 双击文件名直接重命名
    const nt = tr.querySelector('.name-text');
    nt.classList.add('dbl-rename');
    nt.addEventListener('dblclick', () => renameItem(rel, e.name));
    actions.appendChild(mkAction('分享', 'btn-soft mini', () => openShare(rel, e.name, e.size)));
    // 图片/视频/音频可直接预览（浏览器端渲染，服务端只透传文件流）
    if (extKindOf(e.name)) actions.appendChild(mkAction('预览', 'btn-soft mini', () => openPreview(rel, e.name, e.size)));
    actions.appendChild(mkAction('下载', 'btn-soft mini', () => {
      location.href = '/api/download?path=' + encodeURIComponent(rel);
    }));
    actions.appendChild(mkAction('重命名', 'btn-soft mini', () => renameItem(rel, e.name)));
    actions.appendChild(mkAction('移动', 'btn-soft mini', () => moveItem(rel, e.name, e.isDir)));
    actions.appendChild(mkAction('删除', 'btn-soft mini btn-danger', () => delItem(rel, e.name, false)));
  }
  return tr;
}

// 只渲染可见窗口内的行，上下用占位行撑出完整滚动高度
function renderVirtual(depth) {
  const list = $('#list');
  if (!list || pageState.search) return;
  syncListContainer();
  const items = pageState.items || [];
  if (!items.length) { list.innerHTML = ''; return; }
  const rect = list.getBoundingClientRect();
  const top = Math.max(0, -rect.top);
  const first = Math.max(0, Math.floor(top / VROW) - 5);
  const count = Math.ceil(window.innerHeight / VROW) + 10;
  const last = Math.min(items.length, first + count);
  const frag = document.createDocumentFragment();
  if (first > 0) frag.appendChild(vSpacer(first * VROW));
  for (let i = first; i < last; i++) frag.appendChild(buildRow(items[i], false));
  if (last < items.length) frag.appendChild(vSpacer((items.length - last) * VROW));
  else if (pageState.hasMore) frag.appendChild(vMoreRow());
  list.innerHTML = '';
  list.appendChild(frag);
  // 用真实行高校准一次（只允许递归一层，避免来回抖动）
  const before = VROW;
  measureRowHeight(list);
  if (VROW !== before && !depth) renderVirtual(1);
}

// measureRowHeight 量出真实行高，偏差超过 1px 才采纳（避免亚像素抖动导致反复重排）
function measureRowHeight(list) {
  const tr = list.querySelector('tr:not(.vspace):not(.vmore)');
  if (!tr) return;
  const h = tr.getBoundingClientRect().height;
  if (h > 20 && Math.abs(h - VROW) > 1) VROW = h;
}
function vSpacer(h) {
  const tr = document.createElement('tr');
  tr.className = 'vspace';
  const td = document.createElement('td');
  td.colSpan = 7;
  td.style.height = h + 'px';
  tr.appendChild(td);
  return tr;
}
function vMoreRow() {
  const tr = document.createElement('tr');
  tr.className = 'vmore';
  tr.innerHTML = `<td colspan="7">已加载 ${pageState.items.length}/${pageState.total} 项，点击加载更多…</td>`;
  tr.addEventListener('click', () => loadListMore(true));
  return tr;
}
let vRaf = 0;
function scheduleVirtual() {
  // 相册模式：可见视图不依赖表格虚拟滚动，避免每帧空转重建隐藏的表格
  if (pageState.search || galleryOn || vRaf) return;
  vRaf = requestAnimationFrame(() => { vRaf = 0; renderVirtual(); });
}
window.addEventListener('scroll', () => { scheduleVirtual(); loadListMore(false); }, { passive: true });
window.addEventListener('resize', () => scheduleVirtual());
async function refreshShares() {
  try {
    const d = await api('/api/shares');
    if (!d) return;
    const m = {};
    d.shares.forEach(s => {
      const old = m[s.relPath];
      if (!old) { m[s.relPath] = s; return; }
      // 同一文件存在多条分享记录时：优先保留有效的；同样有效（或都失效）时保留最新创建的，
      // 否则重新生成分享后表格状态列仍显示旧记录
      if (old.alive !== s.alive) {
        if (s.alive) m[s.relPath] = s;
      } else if ((s.createdAt || 0) > (old.createdAt || 0)) {
        m[s.relPath] = s;
      }
    });
    sharesMap = m;
  } catch (e) {}
}
async function loadList(p) {
  state.curPath = p || '';
  try { localStorage.setItem('fh-path', state.curPath); } catch (e) {}
  selMap.clear();
  pageState = { items: [], total: 0, hasMore: false, loading: true, search: false };
  try {
    const d = await fetchList(0);
    if (!d) { pageState.loading = false; return; }
    renderCrumb(d.path);
    d.entries.forEach(e => { e.dirPath = d.path; });
    state.entries = d.entries;
    pageState.items = d.entries;
    pageState.total = d.total != null ? d.total : d.entries.length;
    pageState.hasMore = !!d.hasMore;
    pageState.loading = false;
    renderTable(pageState.items);
  } catch (e) {
    pageState.loading = false;
    toast(e.message);
  }
}
// 带排序/筛选/分页参数拉取目录（服务端排序保证跨页次序稳定）
function fetchList(offset) {
  const q = new URLSearchParams();
  q.set('path', state.curPath);
  q.set('offset', String(offset));
  q.set('limit', String(PAGE_SIZE));
  q.set('sort', (($('#sort-select') || {}).value) || 'time-desc');
  q.set('filter', (($('#filter-select') || {}).value) || 'all');
  q.set('size', (($('#size-select') || {}).value) || 'all');
  return api('/api/list?' + q.toString());
}
// 追加下一页（滚动接近底部自动触发；force 供「点击加载更多」）
async function loadListMore(force) {
  if (pageState.search || pageState.loading || !pageState.hasMore) return;
  if (!force && window.innerHeight + window.scrollY < document.body.scrollHeight - 600) return;
  pageState.loading = true;
  try {
    const d = await fetchList(pageState.items.length);
    if (d && d.entries) {
      const seen = new Set(pageState.items.map(x => x.name));
      d.entries.forEach(e => {
        e.dirPath = d.path;
        if (!seen.has(e.name)) pageState.items.push(e);
      });
      pageState.total = d.total != null ? d.total : pageState.items.length;
      pageState.hasMore = !!d.hasMore;
      pageState.loading = false;
      if (galleryOn) renderGallery(); else renderVirtual();
      const ci = $('#count-info');
      if (ci) ci.textContent = `共 ${pageState.total} 项`;
      updateBatchUI();
      return;
    }
  } catch (e) { /* 静默，下次滚动重试 */ }
  pageState.loading = false;
}

/* ---------------- 面包屑 ---------------- */
function renderCrumb(p) {
  const c = $('#crumb'); if (!c) return;
  c.innerHTML = '';
  const root = document.createElement('button');
  root.textContent = '所有文件';
  root.addEventListener('click', () => { clearSearch(); loadList(''); });
  c.appendChild(root);
  const title = $('#page-title');
  if (p) {
    p.split('/').filter(Boolean).forEach((seg, i, arr) => {
      const sep = document.createElement('span'); sep.className = 'sep'; sep.textContent = '›';
      c.appendChild(sep);
      const b = document.createElement('button');
      b.textContent = seg;
      if (i === arr.length - 1) b.className = 'cur';
      else b.addEventListener('click', () => { clearSearch(); loadList(arr.slice(0, i + 1).join('/')); });
      c.appendChild(b);
    });
    if (title) title.textContent = p.split('/').filter(Boolean).pop();
  } else if (title) {
    title.textContent = '文件列表';
  }
}

/* ---------------- 搜索 ---------------- */
let searchTimer = null;
on('#search-input', 'input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runSearch, 350);
});
// 记住排序/筛选选择：刷新后保持上次的列表视图偏好（纯前端，无服务端开销）
['#sort-select', '#filter-select', '#size-select'].forEach(sel => {
  const el = $(sel);
  if (!el) return;
  const key = 'fh-' + sel.slice(1);
  try {
    const saved = localStorage.getItem(key);
    if (saved && [...el.options].some(o => o.value === saved)) el.value = saved;
  } catch (e) {}
  el.addEventListener('change', () => { try { localStorage.setItem(key, el.value); } catch (e) {} });
});
// 「/」聚焦搜索框（桌面效率键）；输入框内 Esc 清空搜索
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== $('#search-input')) {
    const tag = (document.activeElement || {}).tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    e.preventDefault();
    const si = $('#search-input');
    if (si) si.focus();
  }
});
on('#search-input', 'keydown', (e) => {
  if (e.key === 'Escape' && e.target.value) {
    e.stopPropagation();
    clearSearch(); loadList(state.curPath);
  }
});
async function runSearch() {
  const si = $('#search-input');
  const q = si ? si.value.trim() : '';
  if (!q) { if (state.searching) { clearSearch(); loadList(state.curPath); } return; }
  state.searching = true;
  const sc = $('#search-clear'); if (sc) sc.classList.remove('hidden');
  const title = $('#page-title'); if (title) title.textContent = `搜索“${q}”`;
  try {
    const d = await api('/api/search?q=' + encodeURIComponent(q));
    if (!d) return;
    const crumb = $('#crumb');
    if (crumb) crumb.innerHTML = `<span class="cur">全盘搜索 · ${d.results.length} 个结果${d.truncated ? '（已达上限，请细化关键词）' : ''}</span>`;
    renderTable(d.results, { search: true });
  } catch (e) { toast(e.message); }
}
function clearSearch() {
  state.searching = false;
  const si = $('#search-input'); if (si) si.value = '';
  const sc = $('#search-clear'); if (sc) sc.classList.add('hidden');
}
on('#search-clear', 'click', () => { clearSearch(); loadList(state.curPath); });
on('#sort-select', 'change', () => {
  if (state.searching) { const si = $('#search-input'); if (si && si.value.trim()) runSearch(); }
  else loadList(state.curPath);
});
on('#filter-select', 'change', () => {
  if (state.searching) { const si = $('#search-input'); if (si && si.value.trim()) runSearch(); }
  else loadList(state.curPath);
});
on('#size-select', 'change', () => {
  if (state.searching) { const si = $('#search-input'); if (si && si.value.trim()) runSearch(); }
  else loadList(state.curPath);
});

/* ---------------- 重命名 / 删除 / 新建文件夹 ---------------- */
const dirNameOf = (rel) => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');
async function doMove(from, to, label) {
  if (!to || to === from) return;
  if (to.includes('..')) return toast('路径不合法');
  try {
    await api('/api/move', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to })
    });
    toast(label + '完成'); refreshShares(); loadList(state.curPath);
  } catch (e) { toast(e.message); }
}
// 重命名：只改名字，保持在原目录
async function renameItem(rel, name) {
  const newName = await askText('重命名', name, '新的名称');
  if (newName === null || !newName || newName === name) return;
  const dir = dirNameOf(rel);
  await doMove(rel, dir ? dir + '/' + newName : newName, '重命名');
}
// 移动：弹出文件夹选择器（复用目录浏览器），不手填路径
const moveState = { cur: '' };
let moveCb = null;
function openMovePicker(startAbs, title, cb) {
  moveCb = cb;
  const m = $('#move-modal');
  if (!m) return;
  const t = $('#move-title');
  if (t) t.textContent = title;
  const tg = $('#move-target');
  if (tg) tg.textContent = '…';
  m.classList.remove('hidden');
  loadDir(startAbs || '', '#move-crumb', '#move-list', moveState);
}
// 绝对路径 -> 相对根目录；不在根目录内返回 null
function absToRel(abs) {
  const root = (state.rootDir || '').replace(/[\\/]+$/, '');
  let r = (abs || '').replace(/[\\/]+$/, '');
  if (!root || !r.startsWith(root)) return null;
  return r.slice(root.length).replace(/^[\\/]+/, '');
}
on('#move-ok', 'click', () => {
  const m = $('#move-modal');
  if (m) m.classList.add('hidden');
  if (moveCb) moveCb(moveState.cur);
});
async function moveItem(rel, name, isDir) {
  const startAbs = joinPath(state.rootDir || '', dirNameOf(rel));
  openMovePicker(startAbs, `移动「${name}」到…`, (abs) => {
    const dir = absToRel(abs);
    if (dir === null) return toast('请选择根目录内的文件夹');
    if (dir === dirNameOf(rel)) return toast('目标目录与当前目录相同');
    if (isDir && (dir === rel || dir.startsWith(rel + '/'))) return toast('不能移动到其自身内部');
    doMove(rel, dir ? dir + '/' + name : name, '移动');
  });
}
async function delItem(rel, name, isDir) {
  const ok = await askConfirm('删除确认', `确定删除「${name}」？${isDir ? '将包含其中所有文件，' : ''}删除后进入回收站，可随时恢复。`);
  if (!ok) return;
  try {
    await api('/api/item?path=' + encodeURIComponent(rel), { method: 'DELETE' });
    toast('已移入回收站'); refreshShares(); loadList(state.curPath);
  } catch (e) { toast(e.message); }
}
function getChecked() {
  return Array.from(selMap.values());
}

/* ---------------- 选中状态 / 批量操作 ---------------- */
function updateBatchUI() {
  const sel = Array.from(selMap.values());
  const bar = $('#batch-bar');
  if (bar) bar.classList.toggle('hidden', sel.length === 0);
  const bc = $('#batch-count');
  if (bc) bc.textContent = sel.length;
  const bs = $('#btn-share-new');
  if (bs) bs.disabled = sel.length === 0;
  const bz = $('#batch-zip');
  if (bz) bz.disabled = sel.length === 0;
  const ca = $('#check-all');
  if (ca) {
    const total = pageState.items ? pageState.items.length : 0;
    ca.checked = total > 0 && sel.length >= total;
    ca.indeterminate = sel.length > 0 && sel.length < total;
  }
}
on('#check-all', 'change', () => {
  const on_ = $('#check-all').checked;
  if (on_) {
    (pageState.items || []).forEach(e => {
      const rel = pageState.search ? e.path : joinPath(e.dirPath || '', e.name);
      selMap.set(rel, { path: rel, name: e.name, isDir: !!e.isDir });
    });
  } else {
    selMap.clear();
  }
  if (pageState.search) renderTable(pageState.items, { search: true });
  else renderVirtual();
  updateBatchUI();
});
on('#batch-clear', 'click', () => {
  selMap.clear();
  if (pageState.search) renderTable(pageState.items, { search: true });
  else renderVirtual();
  updateBatchUI();
});
on('#btn-share-new', 'click', () => {
  const sel = getChecked();
  if (!sel.length) return toast('请先勾选要分享的文件或文件夹');
  if (sel.length > 1) return toast('已选中多项，请使用「批量创建分享」');
  openShare(sel[0].path, sel[0].name, null);
});
// 批量创建分享：逐个用默认配置（1 天 / 不限次 / 直链）创建，结果面板列出全部链接；
// 文件夹也可批量分享（访问时自动打包 ZIP）
on('#batch-share', 'click', async () => {
  const files = getChecked();
  if (!files.length) return toast('请先勾选要分享的文件或文件夹');
  const box = $('#batch-links');
  if (box) box.innerHTML = `<div class="mgr-empty">正在创建 0/${files.length} …</div>`;
  const bm = $('#batch-modal');
  if (bm) bm.classList.remove('hidden');
  const results = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (box) box.innerHTML = `<div class="mgr-empty">正在创建 ${i + 1}/${files.length} …</div>`;
    try {
      const r = await api('/api/share', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: f.path, expireSeconds: 86400, maxDownloads: 0, scheme: 'auto', mode: 'direct' })
      });
      if (r) results.push({ name: f.name, url: buildUrl(r.share.token, 'auto', ''), ok: true });
      else results.push({ name: f.name, url: '', ok: false });
    } catch (e) {
      results.push({ name: f.name, url: '', ok: false, err: e.message });
    }
  }
  if (box) {
    box.innerHTML = results.map((r, i) => `
      <div class="batch-link-item">
        <div class="mgr-name">${esc(r.name)}</div>
        ${r.ok
          ? `<div class="batch-url"><code>${esc(r.url)}</code></div>`
          : `<div class="batch-url"><span class="tag red">失败${r.err ? '：' + esc(r.err) : ''}</span></div>`}
      </div>`).join('');
  }
  const copyAll = $('#batch-copy-all');
  if (copyAll) {
    const text = results.filter(r => r.ok).map(r => `${r.name}\n${r.url}`).join('\n\n');
    copyAll.style.display = results.some(r => r.ok) ? '' : 'none';
    copyAll.onclick = async () => { toast(await copyText(text) ? '已复制全部链接' : '复制失败'); };
  }
  refreshShares(); loadList(state.curPath);
});
on('#batch-close', 'click', () => { const m = $('#batch-modal'); if (m) m.classList.add('hidden'); });
// 批量移动：文件夹选择器
on('#batch-move', 'click', () => {
  const sel = getChecked();
  if (!sel.length) return;
  const startAbs = joinPath(state.rootDir || '', state.curPath || '');
  openMovePicker(startAbs, `移动 ${sel.length} 项到…`, async (abs) => {
    const dir = absToRel(abs);
    if (dir === null) return toast('请选择根目录内的文件夹');
    let ok = 0, fail = 0;
    for (const s of sel) {
      if (s.isDir && (dir === s.path || dir.startsWith(s.path + '/'))) { fail++; continue; } // 不能移入自身
      try {
        await api('/api/move', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ from: s.path, to: dir ? dir + '/' + s.name : s.name })
        });
        ok++;
      } catch (e) { fail++; }
    }
    toast(`移动完成：成功 ${ok}${fail ? '，失败 ' + fail : ''}`);
    refreshShares(); loadList(state.curPath);
  });
});
// 批量删除
on('#batch-del', 'click', async () => {
  const sel = getChecked();
  if (!sel.length) return;
  if (!(await askConfirm('批量删除', `确定删除选中的 ${sel.length} 项？删除后进入回收站，可随时恢复。`))) return;
  let ok = 0, fail = 0;
  for (const s of sel) {
    try {
      await api('/api/item?path=' + encodeURIComponent(s.path), { method: 'DELETE' });
      ok++;
    } catch (e) { fail++; }
  }
  toast(`删除完成：成功 ${ok}${fail ? `，失败 ${fail}` : ''}`);
  refreshShares(); loadList(state.curPath);
});
// 批量打包下载：服务端流式 zip，不占服务器磁盘
on('#batch-zip', 'click', async () => {
  const sel = getChecked();
  if (!sel.length) return toast('请先勾选要打包的内容');
  try {
    const r = await fetch('/api/zip', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths: sel.map(s => s.path) })
    });
    if (!r.ok) {
      let msg = '打包失败';
      try { const j = await r.json(); if (j && j.error) msg = j.error; } catch (e) {}
      return toast(msg);
    }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = sel.length === 1 ? sel[0].name + '.zip' : 'files.zip';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 30000);
    toast('已开始下载 ZIP');
  } catch (e) { toast(e.message); }
});
// 点击分享状态标签 → 跳转分享管理并定位该条目
document.addEventListener('click', (e) => {
  const jump = e.target.closest ? e.target.closest('[data-jump]') : null;
  if (!jump) return;
  gotoShareDetail(jump.dataset.jump);
});
async function gotoShareDetail(token) {
  switchView('shares');
  await new Promise(r => setTimeout(r, 400)); // 等 loadShares 渲染
  const el = document.querySelector(`[data-token="${token}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('flash');
    setTimeout(() => el.classList.remove('flash'), 2000);
  }
}
async function mkdirAction() {
  const name = await askText('新建文件夹', '', '文件夹名称');
  if (!name) return;
  try {
    await api('/api/mkdir?path=' + encodeURIComponent(state.curPath), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    toast('已创建'); loadList(state.curPath);
  } catch (e) { toast(e.message); }
}

/* ---------------- 上传 ----------------
   统一管线 sendFile：小文件走原 multipart 单请求；≥8MB 走分片断点续传
   （init → 逐片 PUT 追加 → complete 原子改名），网络抖动只补缺失分片 */
on('#btn-upload', 'click', () => { const f = $('#file-input'); if (f) f.click(); });
on('#file-input', 'change', (e) => { uploadFiles(e.target.files); e.target.value = ''; });
on('#btn-mkdir', 'click', () => mkdirAction());

const CHUNK_THRESHOLD = 8 * 1024 * 1024; // 超过 8MB 启用分片上传
const CHUNK_SIZE = 4 * 1024 * 1024;      // 每片 4MB
const CHUNK_RETRY = 3;                   // 单片重试次数

// xhrSend Promise 化 XHR；返回解析后的 JSON，非 2xx 抛错（err.status/err.data 带详情）
function xhrSend(xhr, body, onProgress) {
  return new Promise((resolve, reject) => {
    if (xhr.upload) xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total);
    };
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch (e) {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(data || {});
      else {
        const err = new Error((data && data.error) || ('请求失败 ' + xhr.status));
        err.status = xhr.status; err.data = data;
        reject(err);
      }
    };
    xhr.onerror = () => reject(new Error('网络错误'));
    xhr.send(body);
  });
}

// uploadSimple 小文件：一次 multipart 直传
async function uploadSimple(file, dirPath, onProgress) {
  const fd = new FormData();
  fd.append('files', file, file.name);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload?path=' + encodeURIComponent(dirPath));
  return xhrSend(xhr, fd, onProgress);
}

// uploadChunked 大文件：init → 逐片顺序追加 → complete。
// 每片从「服务端已收字节数」处续传：409 冲突按服务端进度校正，网络错误重试，
// complete 报分片不完整（400+received）时接回分片循环继续补传，
// 会话丢失（服务重启/目录被删）自动重新 init
async function uploadChunked(file, dirPath, onProgress) {
  const init = await api('/api/upload/init', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dir: dirPath, name: file.name, size: file.size })
  });
  let id = init.id, done = 0, restarts = 0, lastProg = 0;
  // 进度只进不退：409/complete 校正回退偏移时避免进度条倒跳
  const prog = (n) => {
    n = Math.min(Math.max(n, lastProg), file.size);
    lastProg = n;
    if (onProgress) onProgress(n, file.size);
  };
  for (;;) {
    if (done < file.size) {
      const end = Math.min(done + CHUNK_SIZE, file.size);
      let attempt = 0, restart = false;
      for (;;) {
        try {
          const xhr = new XMLHttpRequest();
          xhr.open('PUT', '/api/upload/chunk?id=' + encodeURIComponent(id) + '&offset=' + done);
          await xhrSend(xhr, file.slice(done, end), (loaded) => prog(done + loaded));
          done = end;
          break;
        } catch (e) {
          if (e.status === 409 && e.data && typeof e.data.received === 'number') {
            done = Math.min(e.data.received, file.size); // 按服务端真实进度续传
            break;
          }
          // 终止性失败：单片超限/总超限，服务端已作废会话，重试无意义
          if (e.status === 413 || (e.data && e.data.code === 'ABORTED')) throw e;
          if (e.status === 404 && (e.data && (e.data.code === 'NO_SESSION' || e.data.code === 'NO_DIR'))) {
            if (e.data.code === 'NO_DIR') throw e; // 目录没了，重传也不会成功
            if (++restarts > 3) throw e;
            restart = true;
            break;
          }
          if (++attempt >= CHUNK_RETRY) throw e;
          await new Promise(r => setTimeout(r, 600 * attempt));
        }
      }
      if (restart) {
        const again = await api('/api/upload/init', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ dir: dirPath, name: file.name, size: file.size })
        });
        id = again.id; done = 0; prog(0);
      }
      continue;
    }
    // 全部字节已送达，请求落盘生效；分片不完整（校验失败）时按服务端进度补传
    try {
      await api('/api/upload/complete?id=' + encodeURIComponent(id), {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
      });
      return;
    } catch (e) {
      if (e.data && typeof e.data.received === 'number' && e.data.received < file.size) {
        done = e.data.received;
        continue;
      }
      throw e;
    }
  }
}

// sendFile 统一入口：按大小自动选择上传方式
function sendFile(file, dirPath, onProgress) {
  if (file.size >= CHUNK_THRESHOLD) return uploadChunked(file, dirPath, onProgress);
  return uploadSimple(file, dirPath, onProgress);
}

// 多文件顺序上传：进度条按「累计字节 / 总字节」推进，单个失败不阻断后续
async function uploadFiles(files) {
  const arr = Array.from(files || []);
  if (!arr.length) return;
  const totalBytes = arr.reduce((s, f) => s + f.size, 0) || 1;
  let sent = 0, ok = 0, fail = 0;
  const failMsgs = [];
  const card = $('#upload-progress');
  if (card) card.classList.remove('hidden');
  const bar = $('#progress-bar'), pp = $('#progress-pct'), pn = $('#progress-name');
  const paint = (n) => {
    const pct = Math.min(100, Math.round(n / totalBytes * 100));
    if (bar) bar.style.width = pct + '%';
    if (pp) pp.textContent = pct + '%';
  };
  for (const f of arr) {
    if (pn) pn.textContent = arr.length > 1 ? `上传 ${ok + fail + 1}/${arr.length}：${f.name}` : f.name;
    try {
      await sendFile(f, state.curPath, (loaded) => paint(sent + loaded));
      ok++;
    } catch (e) {
      fail++;
      failMsgs.push(f.name + (e && e.message ? '：' + e.message : ''));
    }
    sent += f.size;
    paint(sent);
  }
  setTimeout(() => { if (card) card.classList.add('hidden'); }, 800);
  if (bar) bar.style.width = '0%';
  if (fail) {
    toast(`上传完成：成功 ${ok}，失败 ${fail}（${failMsgs[0] || ''}${failMsgs.length > 1 ? ' 等' : ''}）`);
  } else {
    toast(`上传成功 ${ok} 个文件`);
  }
  loadList(state.curPath);
}

// 拖拽
let dragDepth = 0;
window.addEventListener('dragenter', (e) => {
  const m = $('#main');
  if (!m || m.classList.contains('hidden')) return;
  e.preventDefault(); dragDepth++; const dm = $('#drop-mask'); if (dm) dm.classList.remove('hidden');
});
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('dragleave', (e) => {
  e.preventDefault(); dragDepth--;
  if (dragDepth <= 0) { dragDepth = 0; const dm = $('#drop-mask'); if (dm) dm.classList.add('hidden'); }
});
window.addEventListener('drop', (e) => {
  const m = $('#main');
  if (!m || m.classList.contains('hidden')) return;
  e.preventDefault(); dragDepth = 0;
  const dm = $('#drop-mask'); if (dm) dm.classList.add('hidden');
  const items = e.dataTransfer.items;
  if (items && items.length && items[0].webkitGetAsEntry) {
    // 拖入目录：遍历 webkitGetAsEntry 树，把目录结构展平成带相对路径的文件列表
    // （与「上传文件夹」同一管线，服务端仍只收普通 multipart）
    const entries = Array.from(items).map(it => {
      try { return it.webkitGetAsEntry && it.webkitGetAsEntry(); } catch (err) { return null; }
    }).filter(Boolean);
    if (entries.some(en => en.isDirectory)) {
      const out = [];
      (async () => {
        for (const en of entries) await walkEntry(en, '', out);
        if (!out.length) return toast('拖入的内容里没有可上传的文件');
        uploadDropped(out);
      })();
      return;
    }
  }
  if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});
// 递归展开拖拽条目为 { file, relPath }；relPath 含顶层名（与 webkitRelativePath 一致）
function walkEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    const rel = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isFile) {
      entry.file(f => { out.push({ file: f, relPath: rel }); resolve(); }, resolve);
      return;
    }
    if (!entry.isDirectory) return resolve();
    const reader = entry.createReader();
    const all = [];
    const readBatch = () => reader.readEntries(async batch => {
      if (!batch.length) {
        for (const en of all) await walkEntry(en, rel, out);
        resolve();
        return;
      }
      all.push(...batch);
      readBatch(); // readEntries 单次最多返回 100 条，必须读到空为止
    }, resolve);
    readBatch();
  });
}

/* ---------------- 文件夹上传 ----------------
   浏览器 webkitdirectory 递归选中整个文件夹，逐文件上传到对应子目录（后端自动建目录），
   大文件自动走分片断点续传（与普通上传同一 sendFile 管线） */
on('#btn-upload-dir', 'click', () => { const f = $('#dir-input'); if (f) f.click(); });
on('#dir-input', 'change', (e) => { uploadFolder(e.target.files); e.target.value = ''; });
async function uploadFolder(files) {
  const arr = Array.from(files || []).map(f => ({
    file: f, relPath: f.webkitRelativePath || f.name
  }));
  await uploadSequence(arr);
}
// 顺序上传带相对路径的文件列表（[{file, relPath}]，relPath 含目录部分），
// 「上传文件夹」与「拖拽目录上传」共用；进度按累计字节推进
async function uploadSequence(arr) {
  if (!arr.length) return;
  const totalBytes = arr.reduce((s, it) => s + (it.file.size || 0), 0) || 1;
  let sent = 0, done = 0, fail = 0;
  const card = $('#upload-progress');
  if (card) card.classList.remove('hidden');
  const bar = $('#progress-bar'), pp = $('#progress-pct'), pn = $('#progress-name');
  const paint = (n) => {
    const pct = Math.min(100, Math.round(n / totalBytes * 100));
    if (bar) bar.style.width = pct + '%';
    if (pp) pp.textContent = pct + '%';
  };
  for (const it of arr) {
    const f = it.file, rp = it.relPath || f.name;
    // relPath 形如 "顶层文件夹/子目录/文件名"（含顶层文件夹名，保留以重建目录结构）
    const idx = rp.lastIndexOf('/');
    const sub = idx > 0 ? rp.slice(0, idx) : '';
    const target = (state.curPath ? state.curPath + '/' : '') + sub;
    if (pn) pn.textContent = `上传文件夹 ${done + fail + 1}/${arr.length}：${f.name}`;
    try {
      await sendFile(f, target, (loaded) => paint(sent + loaded));
      done++;
    } catch (e) { fail++; }
    sent += f.size || 0;
    paint(sent);
  }
  setTimeout(() => { if (card) card.classList.add('hidden'); }, 800);
  if (bar) bar.style.width = '0%';
  toast(`文件夹上传完成：成功 ${done}${fail ? `，失败 ${fail}` : ''}`);
  loadList(state.curPath);
}
// 拖拽目录的入口：walkEntry 展开结果直接进同一管线
function uploadDropped(items) {
  uploadSequence(items);
}

/* ---------------- 媒体预览（浏览器端渲染） ----------------
   图片/视频/音频直接用 <img>/<video>/<audio> 指向下载接口，服务端仅透传文件流，
   不做任何服务端渲染/转码；视频音频支持拖动（后端 Range） */
function extKindOf(name) {
  const ext = fileExt(name);
  if (IMG_EXT.includes(ext)) return 'img';
  if (VID_EXT.includes(ext)) return 'vid';
  if (AUD_EXT.includes(ext)) return 'aud';
  if (TXT_EXT.includes(ext)) return 'txt';
  return '';
}
// 文本预览扩展名：源码/配置/日志等纯文本，浏览器端按文本渲染（截断上限见 TXT_PREVIEW_MAX）
const TXT_EXT = ['TXT','MD','LOG','JSON','CSV','XML','YML','YAML','INI','CONF','CFG','TOML',
  'SH','BASH','PY','JS','TS','CSS','HTML','HTM','GO','C','CPP','H','JAVA','SQL','BAT','PS1','ENV','SERVICE'];
const TXT_PREVIEW_MAX = 2 * 1024 * 1024; // 超过 2MB 只取前 2MB，避免大日志撑爆浏览器

async function openPreview(rel, name, size) {
  const kind = extKindOf(name);
  const img = $('#preview-img'), vid = $('#preview-video'), aud = $('#preview-audio'), txt = $('#preview-text');
  const m = $('#preview-modal');
  if (!kind || !img || !vid || !aud || !txt || !m) return;
  const url = '/api/download?path=' + encodeURIComponent(rel);
  [img, vid, aud, txt].forEach(el => el.classList.add('hidden'));
  if (kind === 'img') { img.src = url; img.classList.remove('hidden'); }
  else if (kind === 'vid') { vid.src = url; vid.classList.remove('hidden'); }
  else if (kind === 'aud') { aud.src = url; aud.classList.remove('hidden'); }
  else {
    // 文本文件：Range 请求只取前 2MB 并流式拼接，浏览器端解码渲染。
    // 不能用 arrayBuffer() 一口读完——大"文本"（日志/CSV）会把整个文件灌进内存
    txt.classList.remove('hidden');
    txt.textContent = '加载中…';
    try {
      const resp = await fetch(url, { headers: { Range: 'bytes=0-' + (TXT_PREVIEW_MAX - 1) } });
      if (!resp.ok && resp.status !== 206) throw new Error('读取失败 ' + resp.status);
      // 206 = 服务端确认只回前 2MB；200 = 拿到了整个文件，总长看 Content-Length
      let total = 0;
      if (resp.status === 206) {
        const m = /\/(\d+)$/.exec(resp.headers.get('content-range') || '');
        total = m ? parseInt(m[1], 10) : 0;
      } else {
        total = parseInt(resp.headers.get('content-length') || '0', 10);
      }
      const reader = resp.body.getReader();
      const chunks = [];
      let got = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        got += value.length;
        if (got >= TXT_PREVIEW_MAX) { try { reader.cancel(); } catch (e) {} break; }
      }
      const buf = new Uint8Array(got);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      let text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
      const truncated = total > got || (total === 0 && got >= TXT_PREVIEW_MAX);
      if (truncated) {
        text += `\n\n…（文件过大，仅显示前 ${fmtSize(got)}${total ? `，共 ${fmtSize(total)}` : ''}）`;
      }
      txt.textContent = text;
    } catch (e) {
      txt.textContent = '文本预览失败：' + e.message;
    }
  }
  const t = $('#preview-name'); if (t) t.textContent = name;
  const info = $('#preview-info'); if (info) info.textContent = size != null ? fmtSize(size) : '';
  const dl = $('#preview-dl'); if (dl) dl.href = url;
  m.classList.remove('hidden');
}
function closePreview() {
  const m = $('#preview-modal');
  if (!m || m.classList.contains('hidden')) return;
  m.classList.add('hidden');
  const img = $('#preview-img'), vid = $('#preview-video'), aud = $('#preview-audio'), txt = $('#preview-text');
  // 停止播放并释放媒体资源
  [vid, aud].forEach(el => {
    if (!el) return;
    try { el.pause(); } catch (e) {}
    el.removeAttribute('src');
    try { el.load(); } catch (e) {}
  });
  if (img) img.removeAttribute('src');
  if (txt) txt.textContent = '';
}
document.addEventListener('click', (e) => {
  const closer = e.target.closest ? e.target.closest('[data-close]') : null;
  if (closer && closer.closest('.modal') && closer.closest('.modal').id === 'preview-modal') closePreview();
  else if (e.target.classList && e.target.classList.contains('modal') && e.target.id === 'preview-modal') closePreview();
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePreview(); });

/* ---------------- 磁盘卡片收起（已改为顶栏常驻组件，保留空绑定防旧缓存报错） ---------------- */

/* ---------------- 分享 ---------------- */
let shareTarget = null;
const segState = { expire: 86400, count: 0, scheme: 'auto' };

$$('#seg-expire .seg-item').forEach(b => b.addEventListener('click', () => {
  $$('#seg-expire .seg-item').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); segState.expire = Number(b.dataset.sec);
  // 点了预设档位就退出「自定义」模式：否则勾选状态下自定义输入会静默覆盖
  // 刚点选的档位（提交逻辑优先读自定义值），用户以为选了 7 天实际还是旧日期
  const tg = $('#expire-custom-toggle');
  if (tg) { tg.checked = false; }
  const ec = $('#expire-custom');
  if (ec) { ec.disabled = true; ec.value = ''; }
}));
$$('#seg-count .seg-item').forEach(b => b.addEventListener('click', () => {
  $$('#seg-count .seg-item').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); segState.count = Number(b.dataset.count);
  const cc = $('#count-custom'); if (cc) cc.value = '';
}));
$$('#seg-scheme .seg-item').forEach(b => b.addEventListener('click', () => {
  $$('#seg-scheme .seg-item').forEach(x => x.classList.remove('active'));
  b.classList.add('active'); segState.scheme = b.dataset.scheme;
}));
$$('#seg-mode .seg-item').forEach(b => b.addEventListener('click', () => {
  $$('#seg-mode .seg-item').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
}));
on('#expire-custom-toggle', 'change', (e) => {
  const c = $('#expire-custom');
  if (c) { c.disabled = !e.target.checked; if (c.disabled) c.value = ''; }
  if (e.target.checked) {
    // 进入自定义模式时取消预设档位的高亮，视觉上二选一
    $$('#seg-expire .seg-item').forEach(x => x.classList.remove('active'));
  } else {
    const chip = $('#seg-expire .seg-item.active') || $$('#seg-expire .seg-item')[2];
    if (chip) chip.classList.add('active');
  }
});
// 访问密码开关：默认收起，开关打开才可输入，减少无密码分享时的视觉噪音
on('#pw-toggle', 'change', (e) => {
  const inp = $('#share-password');
  if (inp) { inp.disabled = !e.target.checked; if (inp.disabled) inp.value = ''; }
});

function openShare(rel, name, size) {
  shareTarget = { path: rel, name, size, created: null };
  $('#share-filename').textContent = name;
  $('#share-filesize').textContent = size == null ? '—' : fmtSize(size);
  $('#share-result').classList.add('hidden');
  $('#host-override').value = '';
  const aliasInp = $('#share-alias');
  if (aliasInp) aliasInp.value = '';
  const hlTg = $('#share-hotlink');
  if (hlTg) hlTg.checked = false;
  const pwInp = $('#share-password');
  if (pwInp) { pwInp.value = ''; pwInp.disabled = true; }
  const pwTg = $('#pw-toggle');
  if (pwTg) pwTg.checked = false;
  const genBtn = $('#btn-gen');
  if (genBtn) genBtn.textContent = '生成链接';
  $('#share-modal').classList.remove('hidden');
}
// buildUrl 别名优先：设置了 alias 的分享用 /s/<alias>（token 链接同样有效）
function buildUrl(token, schemeMode, hostOverride, alias) {
  const curScheme = location.protocol.replace(':', '');
  const scheme = schemeMode === 'auto' ? curScheme : schemeMode;
  const host = (hostOverride || '').trim() || location.host;
  return `${scheme}://${host}/s/${alias || token}`;
}
on('#btn-gen', 'click', async () => {
  if (!shareTarget) return;
  // 同一文件重复点「生成链接」：先撤销上一次生成的链接再建新的，
  // 否则每次点击都会留下一条有效分享记录，失效入口越积越多
  if (shareTarget.created) {
    const again = await askConfirm('重新生成', '该文件本次已生成过链接，将撤销旧链接并按当前设置生成新链接，继续？');
    if (!again) return;
    try { await api('/api/share?token=' + encodeURIComponent(shareTarget.created), { method: 'DELETE' }); } catch (e) {}
    shareTarget.created = null;
  }
  let expireSeconds = segState.expire;
  const customToggle = $('#expire-custom-toggle');
  if (customToggle && customToggle.checked) {
    const v = $('#expire-custom').value;
    if (!v) return toast('请选择到期时间');
    const t = new Date(v).getTime();
    if (!(t > Date.now())) return toast('到期时间必须晚于当前');
    expireSeconds = Math.round((t - Date.now()) / 1000);
  }
  const customCount = $('#count-custom').value.trim();
  const maxDownloads = customCount !== '' ? Math.max(0, parseInt(customCount, 10) || 0) : segState.count;
  const modeBtn = $('#seg-mode .seg-item.active');
  const pwInp = $('#share-password');
  const aliasInp = $('#share-alias'), hlTg = $('#share-hotlink');
  try {
    const r = await api('/api/share', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        path: shareTarget.path, expireSeconds, maxDownloads,
        scheme: segState.scheme, host: $('#host-override').value.trim(),
        password: pwInp && !pwInp.disabled ? pwInp.value.trim() : '',
        mode: (modeBtn && modeBtn.dataset.mode) || 'direct',
        alias: aliasInp ? aliasInp.value.trim() : '',
        hotlink: hlTg ? hlTg.checked : false
      })
    });
    if (!r) return;
    shareTarget.created = r.share.token;
    const url = buildUrl(r.share.token, segState.scheme, $('#host-override').value.trim(), r.share.alias);
    $('#share-url').value = url;
    // 二维码：纯前端生成，扫码即可访问分享链接
    const qr = $('#share-qr');
    if (qr) {
      try { if (window.FHQR) FHQR.draw(qr, url, 3); } catch (e) {}
    }
    const leftTag = r.share.expiresAt
      ? `<span class="tag orange">${fmtLeft(r.share.expiresAt)}</span>`
      : `<span class="tag green">永久有效</span>`;
    const cntTag = r.share.maxDownloads > 0
      ? `<span class="tag">最多 ${r.share.maxDownloads} 次下载</span>`
      : `<span class="tag green">不限次数</span>`;
    const pwTag = r.share.hasPw ? `<span class="tag orange">🔒 密码保护</span>` : '';
    const modeTag = (r.share.mode === 'page') ? `<span class="tag">确认页模式</span>` : `<span class="tag green">直链模式</span>`;
    const aliasTag = r.share.alias ? `<span class="tag purple">别名 /s/${esc(r.share.alias)}</span>` : '';
    const hlTag = r.share.hotlink ? `<span class="tag">防盗链已开启</span>` : '';
    $('#share-meta').innerHTML = leftTag + cntTag + pwTag + modeTag + aliasTag + hlTag +
      `<span class="tag">${esc(url.split('://')[0].toUpperCase())} 协议</span>` +
      `<br>到期时间：${fmtTime(r.share.expiresAt)}` +
      (r.share.hasPw ? `<br>提示：链接本身不含密码，请把密码单独告知对方` : '');
    const result = $('#share-result');
    result.classList.remove('hidden');
    // 结果区已置顶，正常无需滚动；小屏/缩放场景兜底滚动定位一次
    try { result.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (e) {}
    result.classList.remove('result-flash');
    void result.offsetWidth; // 重启动画
    result.classList.add('result-flash');
    $('#btn-gen').textContent = '重新生成';
    refreshShares();
  } catch (e) { toast(e.message); }
});
on('#btn-copy', 'click', async () => {
  const ok = await copyText($('#share-url').value);
  toast(ok ? '链接已复制' : '复制失败，请手动复制');
});

/* ---------------- 最近 30 天下载统计图（canvas 客户端绘制） ---------------- */
let statsDays = null;
async function loadStats() {
  const cv = $('#stats-chart');
  if (!cv) return;
  try {
    const d = await api('/api/stats');
    if (!d) return;
    statsDays = d.days || [];
    drawStatsChart();
    const totals = statsDays.reduce((a, x) => ({ dl: a.dl + (x.downloads || 0), fail: a.fail + (x.fails || 0), pv: a.pv + (x.previews || 0) }), { dl: 0, fail: 0, pv: 0 });
    const sm = $('#stats-summary');
    if (sm) sm.textContent = `下载 ${totals.dl} 次 · 预览 ${totals.pv} 次 · 失败 ${totals.fail} 次`;
  } catch (e) { /* 统计加载失败不打扰主流程 */ }
}
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888';
}
function drawStatsChart() {
  const cv = $('#stats-chart');
  if (!cv || !statsDays) return;
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth || cv.parentElement.clientWidth || 600;
  const H = 150;
  cv.width = W * dpr; cv.height = H * dpr;
  cv.style.height = H + 'px';
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const padL = 8, padR = 8, padT = 10, padB = 22;
  const n = statsDays.length || 1;
  const slot = (W - padL - padR) / n;
  const barW = Math.max(2, Math.min(14, slot * 0.55));
  const innerH = H - padT - padB;
  const maxV = Math.max(1, ...statsDays.map(d => Math.max(d.downloads || 0, d.fails || 0)));
  const cBlue = cssVar('--primary'), cRed = cssVar('--red'), cDim = cssVar('--t3'), cLine = cssVar('--line');
  // 网格线（1/2、满值两条）
  ctx.strokeStyle = cLine; ctx.lineWidth = 1;
  [0.5, 1].forEach(f => {
    const y = Math.round(padT + innerH * (1 - f)) + .5;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
  });
  statsDays.forEach((d, i) => {
    const cx = padL + slot * i + slot / 2;
    const dh = (d.downloads || 0) / maxV * innerH;
    if (dh > 0) {
      ctx.fillStyle = cBlue;
      // 下载与失败并排：失败画在右侧细条
      ctx.fillRect(cx - barW - 1, padT + innerH - dh, barW, dh);
    }
    const fh = (d.fails || 0) / maxV * innerH;
    if (fh > 0) {
      ctx.fillStyle = cRed;
      ctx.fillRect(cx + 1, padT + innerH - fh, Math.max(2, barW * 0.5), fh);
    }
    // 每 5 天一个日期刻度（Go JSON 字段为小写 date）
    if (i % 5 === 0 || i === n - 1) {
      ctx.fillStyle = cDim;
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(d.date, cx, H - 8);
    }
  });
  if (!statsDays.some(d => (d.downloads || 0) + (d.fails || 0) > 0)) {
    ctx.fillStyle = cDim;
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('最近 30 天还没有分享访问记录', W / 2, H / 2);
  }
}
window.addEventListener('resize', () => { if (statsDays) drawStatsChart(); });

/* ---------------- 分享管理（右侧视图） ---------------- */
let allShares = [];
async function loadShares() {
  const box = $('#mgr-list');
  if (!box) return;
  box.innerHTML = '<div class="mgr-empty">加载中…</div>';
  let d;
  try { d = await api('/api/shares'); } catch (e) { box.innerHTML = `<div class="mgr-empty">${esc(e.message)}</div>`; return; }
  if (!d) return;
  allShares = d.shares || [];
  renderShares();
}
// 统一状态标签组件：与文件列表「分享状态」列同一套颜色（失效红 / 倒计时蓝 / 永久绿）
function shareStatusTag(s) {
  if (!s.alive) return '<span class="tag red">已失效</span>';
  return s.expiresAt ? `<span class="tag blue">有效 · ${fmtLeft(s.expiresAt)}</span>` : '<span class="tag green">有效 · 永久</span>';
}
function shareModeTag(s) {
  return s.mode === 'page' ? '<span class="tag purple">确认页</span>' : '<span class="tag green">直链</span>';
}
// 密码标签：新版记录显示明文，点击复制；旧记录（升级前创建）未存明文则只显示标记
function sharePwTag(s) {
  if (!s.hasPw) return '';
  return s.password
    ? `<span class="tag orange tag-link" data-copy-pw="${esc(s.password)}" title="点击复制密码">🔒 ${esc(s.password)}</span>`
    : '<span class="tag orange" title="旧记录未存明文密码，可在「编辑」中重设">🔒 密码</span>';
}
function filteredShares() {
  const f = ($('#share-filter') || {}).value || 'all';
  return allShares.filter(s => {
    if (f === 'alive') return s.alive;
    if (f === 'expired') return !s.alive;
    if (f === 'pw') return s.hasPw;
    if (f === 'direct') return s.mode !== 'page';
    return true;
  });
}
function updateShareBatchUI() {
  const boxes = $$('#mgr-list .share-check');
  const sel = boxes.filter(c => c.checked);
  const btn = $('#share-batch-revoke');
  if (btn) btn.disabled = sel.length === 0;
  const cnt = $('#share-count');
  if (cnt) cnt.textContent = `共 ${allShares.length} 条 · 显示 ${filteredShares().length} 条`;
  const all = $('#share-check-all');
  if (all) {
    all.checked = boxes.length > 0 && sel.length === boxes.length;
    all.indeterminate = sel.length > 0 && sel.length < boxes.length;
  }
}
function renderShares() {
  const box = $('#mgr-list');
  if (!box) return;
  box.innerHTML = '';
  if (!allShares.length) {
    box.innerHTML = '<div class="mgr-empty">还没有创建任何分享链接<br>在「所有文件」中勾选文件后点击「新建分享链接」</div>';
    updateShareBatchUI();
    return;
  }
  const list = filteredShares();
  if (!list.length) {
    box.innerHTML = '<div class="mgr-empty">当前筛选条件下没有分享记录</div>';
    updateShareBatchUI();
    return;
  }
  list.forEach(s => {
    const url = buildUrl(s.token, s.scheme === 'auto' ? 'auto' : s.scheme, s.host, s.alias);
    const el = document.createElement('div');
    el.className = 'mgr-item';
    el.dataset.token = s.token;
    const cnt = s.maxDownloads > 0
      ? `<span class="tag">${s.downloads}/${s.maxDownloads} 次</span>`
      : `<span class="tag green">不限次 (已下载 ${s.downloads})</span>`;
    const aliasTag = s.alias ? `<span class="tag purple">别名 /s/${esc(s.alias)}</span>` : '';
    const hlTag = s.hotlink ? `<span class="tag">防盗链</span>` : '';
    el.innerHTML = `
      <input type="checkbox" class="row-check share-check" data-token="${esc(s.token)}" title="选择此分享">
      <div class="fi">${svgFile}</div>
      <div class="mgr-main">
        <div class="mgr-name">${esc(s.name)}</div>
        <div class="mgr-meta">${shareStatusTag(s)}${cnt}${sharePwTag(s)}${shareModeTag(s)}${aliasTag}${hlTag}<span class="tag">${fmtSize(s.size)}</span><span class="tag">${fmtTime(s.createdAt)}</span></div>
        <div class="mgr-meta"><code>${esc(url)}</code></div>
        <div class="share-edit hidden"></div>
        <div class="share-log hidden"></div>
      </div>`;
    // 点击条目主体直接展开编辑（按钮/链接/复制/编辑面板/日志面板除外）。
    // 注意 .share-edit 里的 <select> 与 .share-log 的文本都不在 a/button/input
    // 选择器内，若不整体排除，点击下拉框会把刚展开的编辑面板又收起来
    el.querySelector('.mgr-main').addEventListener('click', (e) => {
      if (e.target.closest('a, button, input, select, [data-copy-pw], .share-edit, .share-log')) return;
      toggleShareEdit(s, el);
    });
    // 密码标签点击复制：data-copy-pw 属性此前只被 closest 排除逻辑引用，
    // 从未绑定实际复制事件，点击无任何反应
    el.querySelectorAll('[data-copy-pw]').forEach(tag => {
      tag.addEventListener('click', async (e) => {
        e.stopPropagation();
        toast(await copyText(tag.dataset.copyPw) ? '密码已复制' : '复制失败，请手动复制');
      });
    });
    const right = document.createElement('div');
    right.className = 'right-col';
    right.appendChild(mkAction('复制链接', 'btn-primary mini', async () => {
      toast(await copyText(url) ? '链接已复制' : '复制失败');
    }));
    right.appendChild(mkAction('打开', 'btn-soft mini', () => {
      window.open(url, '_blank', 'noopener');
    }));
    right.appendChild(mkAction('编辑', 'btn-soft mini', () => toggleShareEdit(s, el)));
    right.appendChild(mkAction('日志', 'btn-soft mini', () => toggleShareLog(s.token, s.name, el)));
    right.appendChild(mkAction('撤销', 'btn-soft mini btn-danger', async () => {
      if (!(await askConfirm('撤销分享', '撤销该分享链接？撤销后链接立即失效。'))) return;
      await api('/api/share?token=' + encodeURIComponent(s.token), { method: 'DELETE' });
      toast('已撤销'); refreshShares(); loadShares(); loadList(state.curPath);
    }));
    el.appendChild(right);
    box.appendChild(el);
  });
  updateShareBatchUI();
}

/* ---------------- 快速编辑分享（条目内展开，免删除重建） ---------------- */
function toggleShareEdit(s, itemEl) {
  const pane = itemEl.querySelector('.share-edit');
  if (!pane) return;
  if (!pane.classList.contains('hidden')) { pane.classList.add('hidden'); pane.innerHTML = ''; return; }
  const log = itemEl.querySelector('.share-log');
  if (log) { log.classList.add('hidden'); log.innerHTML = ''; }
  const p2 = (n) => String(n).padStart(2, '0');
  const d = s.expiresAt ? new Date(s.expiresAt) : null;
  const dtLocal = d ? `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}` : '';
  pane.innerHTML = `
    <div class="edit-row"><span class="edit-label">有效期</span>
      <select class="input-sm" id="se-expire-${s.token}">
        <option value="3600">1 小时</option>
        <option value="21600">6 小时</option>
        <option value="86400">1 天</option>
        <option value="604800">7 天</option>
        <option value="2592000">30 天</option>
        <option value="forever">永久</option>
        <option value="custom"${s.expiresAt ? ' selected' : ''}>自定义…</option>
      </select>
      <input type="datetime-local" class="input-sm${s.expiresAt ? '' : ' hidden'}" id="se-expire-custom-${s.token}" value="${dtLocal}">
    </div>
    <div class="edit-row"><span class="edit-label">访问密码</span>
      <input type="text" class="input-sm" id="se-pw-${s.token}" value="${esc(s.password || '')}" placeholder="留空 = 清除密码保护">
    </div>
    <div class="edit-row"><span class="edit-label">链接别名</span>
      <input type="text" class="input-sm" id="se-alias-${s.token}" value="${esc(s.alias || '')}" placeholder="留空 = 不用别名（中英文/数字/-/_）">
    </div>
    <div class="edit-row"><span class="edit-label">防盗链</span>
      <label class="switch"><input type="checkbox" id="se-hl-${s.token}"${s.hotlink ? ' checked' : ''}><span>拒绝其他网站的页面引用</span></label>
    </div>
    <div class="edit-row"><span class="edit-label">访问方式</span>
      <span class="seg" id="se-mode-${s.token}">
        <button type="button" class="seg-item${s.mode !== 'page' ? ' active' : ''}" data-mode="direct">直链下载</button>
        <button type="button" class="seg-item${s.mode === 'page' ? ' active' : ''}" data-mode="page">确认页</button>
      </span>
    </div>
    <div class="edit-actions">
      <button type="button" class="btn btn-primary mini" id="se-save-${s.token}">保存修改</button>
      <button type="button" class="btn btn-soft mini" id="se-cancel-${s.token}">取消</button>
    </div>`;
  pane.classList.remove('hidden');
  const sel = pane.querySelector(`#se-expire-${s.token}`);
  const custom = pane.querySelector(`#se-expire-custom-${s.token}`);
  sel.addEventListener('change', () => custom.classList.toggle('hidden', sel.value !== 'custom'));
  pane.querySelectorAll(`#se-mode-${s.token} .seg-item`).forEach(b => b.addEventListener('click', () => {
    pane.querySelectorAll(`#se-mode-${s.token} .seg-item`).forEach(x => x.classList.remove('active'));
    b.classList.add('active');
  }));
  pane.querySelector(`#se-cancel-${s.token}`).addEventListener('click', () => { pane.classList.add('hidden'); pane.innerHTML = ''; });
  pane.querySelector(`#se-save-${s.token}`).addEventListener('click', async () => {
    let expiresAt = 0;
    if (sel.value === 'custom') {
      const t = new Date(custom.value).getTime();
      if (!(t > Date.now())) return toast('到期时间必须晚于当前');
      expiresAt = t;
    } else if (sel.value !== 'forever') {
      expiresAt = Date.now() + Number(sel.value) * 1000;
    }
    const modeBtn = pane.querySelector(`#se-mode-${s.token} .seg-item.active`);
    const aliasVal = (pane.querySelector(`#se-alias-${s.token}`).value || '').trim();
    if (aliasVal) {
      // 前端先做与后端一致的校验（中英文/数字/中划线/下划线，1~40 字符），省一次必然失败的往返
      if (!/^[\w\u4e00-\u9fa5-]{1,40}$/.test(aliasVal)) {
        return toast('别名不合法：仅限中英文、数字、中划线、下划线，1~40 字符');
      }
    }
    try {
      await api('/api/share/update', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: s.token, expiresAt,
          password: pane.querySelector(`#se-pw-${s.token}`).value.trim(),
          mode: (modeBtn && modeBtn.dataset.mode) || 'direct',
          alias: aliasVal,
          hotlink: pane.querySelector(`#se-hl-${s.token}`).checked
        })
      });
      toast('分享已更新');
      pane.classList.add('hidden'); pane.innerHTML = '';
      refreshShares(); loadShares(); loadList(state.curPath);
    } catch (e) { toast(e.message); }
  });
}

// 筛选 / 全选 / 批量撤销
on('#share-filter', 'change', renderShares);
on('#mgr-list', 'change', (e) => {
  if (e.target.classList && e.target.classList.contains('share-check')) updateShareBatchUI();
});
on('#share-check-all', 'change', () => {
  const on_ = $('#share-check-all').checked;
  $$('#mgr-list .share-check').forEach(c => { c.checked = on_; });
  updateShareBatchUI();
});
on('#share-batch-revoke', 'click', async () => {
  const toks = $$('#mgr-list .share-check:checked').map(c => c.dataset.token);
  if (!toks.length) return;
  if (!(await askConfirm('批量撤销', `确定撤销选中的 ${toks.length} 条分享链接？撤销后链接立即失效。`))) return;
  let ok = 0, fail = 0;
  for (const t of toks) {
    try {
      await api('/api/share?token=' + encodeURIComponent(t), { method: 'DELETE' });
      ok++;
    } catch (e) { fail++; }
  }
  toast(`已撤销 ${ok} 条分享${fail ? `，失败 ${fail} 条` : ''}`);
  refreshShares(); loadShares(); loadList(state.curPath);
});

/* ---------------- 分享访问日志（行内展开） ---------------- */
async function toggleShareLog(token, name, itemEl) {
  const pane = itemEl.querySelector('.share-log');
  if (!pane) return;
  if (!pane.classList.contains('hidden')) { // 再点一次收起
    pane.classList.add('hidden');
    pane.innerHTML = '';
    return;
  }
  pane.classList.remove('hidden');
  pane.innerHTML = '<div class="log-ua">加载中…</div>';
  try {
    const d = await api('/api/sharelog?token=' + encodeURIComponent(token));
    if (!d) { pane.classList.add('hidden'); return; }
    if (!d.log.length) {
      pane.innerHTML = '<div class="log-ua">还没有访问记录</div>';
      return;
    }
    const rows = d.log.slice().reverse().map(l => `
      <div class="log-row">
        <span class="tag ${l.ok ? 'green' : 'red'}">${l.ok ? '✓ 下载成功' : '✗ 失败'}</span>
        ${l.note ? `<span class="tag red">${esc(l.note)}</span>` : ''}
        <span class="tag">${esc(l.ip || '未知 IP')}</span>
        <span class="tag">${fmtTime(l.at)}</span>
        ${l.ua ? `<div class="log-ua">${esc(l.ua)}</div>` : ''}
      </div>`).join('');
    pane.innerHTML = `<div class="log-title">访问日志 · ${esc(name)}（${d.log.length} 条）</div>${rows}`;
  } catch (e) {
    pane.innerHTML = `<div class="log-ua">${esc(e.message)}</div>`;
  }
}

/* ---------------- 输入 / 确认对话框（自定义样式，替代浏览器原生 prompt/confirm） ---------------- */
let askResolve = null;
function askText(title, def, placeholder) {
  return new Promise(resolve => {
    askResolve = resolve;
    $('#ask-title').textContent = title;
    $('#ask-msg').classList.add('hidden');
    const input = $('#ask-input');
    input.classList.remove('hidden');
    input.value = def || '';
    input.placeholder = placeholder || '';
    $('#ask-modal').classList.remove('hidden');
    setTimeout(() => input.focus(), 50);
  });
}
function askConfirm(title, msg) {
  return new Promise(resolve => {
    askResolve = resolve;
    $('#ask-title').textContent = title;
    const m = $('#ask-msg');
    m.textContent = msg;
    m.classList.remove('hidden');
    $('#ask-input').classList.add('hidden');
    $('#ask-modal').classList.remove('hidden');
  });
}
function settleAsk(v) {
  const r = askResolve;
  askResolve = null;
  const m = $('#ask-modal');
  if (m) m.classList.add('hidden');
  if (r) r(v);
}
on('#ask-ok', 'click', () => {
  const input = $('#ask-input');
  settleAsk(input.classList.contains('hidden') ? true : input.value.trim());
});
on('#ask-cancel', 'click', () => settleAsk(null));
on('#ask-input', 'keydown', (e) => { if (e.key === 'Enter') $('#ask-ok').click(); });

/* ---------------- 弹窗关闭（事件委托，动态内容也生效） ---------------- */
document.addEventListener('click', (e) => {
  const closer = e.target.closest ? e.target.closest('[data-close]') : null;
  if (closer) {
    const m = closer.closest('.modal');
    if (m) m.classList.add('hidden');
    return;
  }
  if (e.target.classList && e.target.classList.contains('modal')) {
    e.target.classList.add('hidden');
    if (e.target.id === 'ask-modal') settleAsk(null);
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const ask = $('#ask-modal');
    if (ask && !ask.classList.contains('hidden')) settleAsk(null);
    $$('.modal').forEach(m => m.classList.add('hidden'));
  }
});

/* ---------------- 检查更新（设置视图） ---------------- */
function setStatus(html) {
  const el = $('#update-status');
  if (el) el.innerHTML = html;
}
function archStr(r) { return r.goos + '/' + r.goarch + (r.goarm ? 'v' + r.goarm : ''); }

async function loadVersionInfo() {
  setStatus('正在查询 GitHub 最新版本…');
  const curBox = $('#upd-cur-notes'), newBox = $('#upd-new-notes');
  // 通用：把一个「更新内容」区块渲染到指定容器
  const showNotes = (box, title, notes, empty) => {
    if (!box) return;
    const t = (notes || '').trim();
    if (t) {
      box.innerHTML = `<div class="cl-title">${esc(title)}</div><div class="cl-body">${esc(t)}</div>`;
      box.classList.remove('hidden');
    } else if (empty) {
      box.innerHTML = `<div class="cl-title">${esc(title)}</div><div class="cl-body">${esc(empty)}</div>`;
      box.classList.remove('hidden');
    } else {
      box.classList.add('hidden');
      box.innerHTML = '';
    }
  };
  let r;
  try { r = await api('/api/version?force=1'); } catch (e) {
    setStatus('加载失败：' + esc(e.message));
    if (curBox) curBox.classList.add('hidden');
    if (newBox) newBox.classList.add('hidden');
    return;
  }
  if (!r) return;
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('#upd-version', r.version);
  set('#upd-arch', archStr(r));
  set('#upd-build', r.buildTime || '—');
  set('#upd-asset', r.asset || '—');
  const online = $('#upd-online'), dl = $('#upd-download');
  if (online) online.classList.add('hidden');
  if (dl) dl.classList.add('hidden');
  // 当前版本的更新内容（与 GitHub 是否可达无关，只要查得到就展示）
  showNotes(curBox, `当前版本更新内容 · ${r.version}`, r.currentNotes,
    r.releaseVersion ? 'GitHub 上未找到该版本的发布说明。' : '当前为自构建/容器版本（无发布版本号），无法匹配更新内容。');
  if (!r.checkOk) {
    if (newBox) newBox.classList.add('hidden');
    setStatus(`检查失败：${esc(r.checkError || '未知错误')}（GitHub 不可达时可用「本地上传更新包」）`);
    return;
  }
  if (!r.releaseVersion) {
    // 容器/自构建：版本号不是 vX.Y.Z，任何 Release 都会被误判为更新，且容器里替换二进制没有意义
    if (newBox) newBox.classList.add('hidden');
    setStatus(`<span class="tag">非发布版本</span> 当前 ${esc(r.version)}（最新 Release 为 ${esc(r.latest)}）。容器/自构建版本请通过重新构建镜像更新，已禁用在线更新。`);
    return;
  }
  if (r.hasUpdate) {
    setStatus(`<span class="tag orange">发现新版本 ${esc(r.latest)}</span> 当前 ${esc(r.version)} → 可更新到 ${esc(r.latest)}`);
    showNotes(newBox, `新版本更新内容 · ${r.latest}`, r.notes, '该版本未提供更新说明。');
    if (online) {
      online.textContent = `一键更新到 ${r.latest}`;
      online.classList.remove('hidden');
      online.onclick = () => doUpdate(r.latest);
    }
    if (dl) {
      dl.href = r.assetUrl || r.releaseUrl;
      dl.classList.remove('hidden');
    }
  } else {
    if (newBox) newBox.classList.add('hidden');
    setStatus(`<span class="tag green">已是最新版本</span> ${esc(r.version)} · commit ${esc(r.commit || '—')} · 构建于 ${esc(r.buildTime || '—')}`);
  }
}

// 手动上传更新包：服务器连不上 GitHub 时的本地替代路径
async function uploadBin(file) {
  setStatus(`上传 ${esc(file.name)}（${(file.size / 1048576).toFixed(1)}MB）中…`);
  try {
    const fd = new FormData();
    fd.append('file', file);
    await api('/api/selfupdate', { method: 'POST', body: fd });
    pollUpdate(file.name);
  } catch (err) {
    setStatus(`上传失败：${esc(err.message)}`);
  }
}
async function doUpdate(latest) {
  setStatus('提交更新任务…');
  try {
    await api('/api/selfupdate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    pollUpdate(latest);
  } catch (err) {
    setStatus(`更新启动失败：${esc(err.message)}`);
  }
}
function pollUpdate(label) {
  const t = setInterval(async () => {
    let s;
    try { s = await api('/api/selfupdate'); } catch (e) { return; } // 网络抖动继续等
    if (s.status === 'error') {
      clearInterval(t);
      setStatus(`更新失败：${esc(s.message)}`);
    } else if (s.status === 'restarting' || s.status === 'done') {
      clearInterval(t);
      waitHealthy(s.status === 'restarting' ? null : label);
    } else if (s.status === 'idle') {
      clearInterval(t);
      setStatus(esc(s.message || '已是最新'));
    } else if (s.status === 'downloading' && s.total > 0) {
      // 下载中：进度条 + 取消按钮
      const pct = Math.min(100, Math.round(s.done / s.total * 100));
      setStatus(
        `<div>${esc(s.message)}：${fmtSize(s.done)} / ${fmtSize(s.total)}（${pct}%）</div>` +
        `<div class="bar upd-bar"><div class="bar-inner" style="width:${pct}%"></div></div>` +
        `<button id="upd-cancel" class="btn btn-soft mini">取消更新</button>`
      );
      const c = $('#upd-cancel');
      if (c) c.onclick = async () => {
        c.disabled = true; c.textContent = '取消中…';
        try { await api('/api/selfupdate/cancel', { method: 'POST' }); }
        catch (e) { c.disabled = false; c.textContent = '取消更新'; toast(e.message); }
      };
    } else {
      // 查询中 / 总大小未知：文本 + 可取消
      setStatus(
        `<div>更新（${esc(label)}）：${esc(s.message || s.status)}</div>` +
        (s.cancelable ? `<button id="upd-cancel" class="btn btn-soft mini">取消更新</button>` : '')
      );
      const c = $('#upd-cancel');
      if (c) c.onclick = async () => {
        c.disabled = true; c.textContent = '取消中…';
        try { await api('/api/selfupdate/cancel', { method: 'POST' }); }
        catch (e) { c.disabled = false; c.textContent = '取消更新'; toast(e.message); }
      };
    }
  }, 1000);
}
function waitHealthy(expected) {
  let n = 0;
  const t = setInterval(async () => {
    n++;
    try {
      const v = await api('/api/version');
      clearInterval(t);
      const ok = !expected || v.version === expected;
      setStatus(ok
        ? `<span class="tag green">更新成功</span> 已更新到 ${esc(v.version)}，页面即将刷新`
        : `<span class="tag green">服务已恢复</span> 当前版本 ${esc(v.version)}`);
      toast(ok ? `已成功更新到 ${v.version}` : '服务已恢复');
      setTimeout(() => location.reload(), 1500);
    } catch (e) {
      if (n > 60) { // 2 分钟仍不通
        clearInterval(t);
        setStatus('等待服务恢复超时，请检查服务状态');
      }
      if (n % 5 === 0) setStatus(`服务重启中…（${Math.round(n * 2)}s）`);
    }
  }, 2000);
}
on('#upd-check', 'click', loadVersionInfo);
on('#ver-upload-link', 'click', () => { const up = $('#ver-upload'); if (up) up.click(); });
on('#ver-upload', 'change', function () {
  if (this.files && this.files[0]) { uploadBin(this.files[0]); this.value = ''; }
});

/* ---------------- 定时清理（设置视图，开关可视化 + 可保存配置） ---------------- */
async function enterTidyView() {
  const st = $('#tidy-status');
  if (st) st.textContent = '加载中…';
  try {
    const d = await api('/api/tidy');
    if (!d) return;
    const sw = $('#tidy-enabled'), sel = $('#tidy-hours');
    if (sw) sw.checked = d.enabled !== false;
    if (sel) {
      // 当前值不在预设里时补一个选项，保证回显准确
      if (![...sel.options].some(o => o.value == d.graceHours)) {
        const o = document.createElement('option');
        o.value = String(d.graceHours);
        o.textContent = `${d.graceHours} 小时（当前配置）`;
        sel.appendChild(o);
      }
      sel.value = String(d.graceHours);
    }
    const g1 = $('#tidy-grace'), g2 = $('#tidy-grace2'), p = $('#tidy-pending');
    if (g1) g1.textContent = d.graceHours;
    if (g2) g2.textContent = d.graceHours;
    if (p) p.textContent = d.pending + ' 条';
    if (st) st.textContent = d.pending > 0
      ? `有 ${d.pending} 条分享记录已过期超过保留时长，等待下次自动清理，可点「立即清理」马上处理。`
      : '当前没有待清理的过期记录。';
  } catch (e) {
    if (st) st.textContent = '加载失败：' + esc(e.message);
  }
}
on('#tidy-refresh', 'click', enterTidyView);
on('#tidy-save', 'click', async () => {
  const sw = $('#tidy-enabled'), sel = $('#tidy-hours');
  const hours = sel ? Number(sel.value) : 0;
  if (!hours || hours < 1) return toast('请选择有效的保留时长');
  try {
    const d = await api('/api/tidy/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: sw ? sw.checked : true, hours })
    });
    if (!d) return;
    toast(`已保存：自动清理${d.enabled ? '开启' : '关闭'}，保留 ${d.graceHours} 小时`);
    enterTidyView();
  } catch (e) { toast(e.message); }
});
on('#tidy-run', 'click', async () => {
  if (!(await askConfirm('立即清理', '清理所有过期超过保留时长的分享记录？'))) return;
  const st = $('#tidy-status');
  if (st) st.textContent = '清理中…';
  try {
    const d = await api('/api/tidy', { method: 'POST' });
    if (!d) return;
    if (st) st.textContent = `已清理 ${d.removed} 条记录，当前剩余待清理 ${d.pending} 条。`;
    toast(d.removed > 0 ? `已清理 ${d.removed} 条过期记录` : '没有需要清理的记录');
  } catch (e) {
    if (st) st.textContent = '清理失败：' + esc(e.message);
  }
});

/* ---------------- 安全与会话（会话列表 / 踢出 / 修改密码） ---------------- */
async function loadSessionsList() {
  const box = $('#sess-list');
  if (!box) return;
  box.innerHTML = '<div class="mgr-empty">加载中…</div>';
  let d;
  try { d = await api('/api/sessions'); } catch (e) { box.innerHTML = `<div class="mgr-empty">${esc(e.message)}</div>`; return; }
  if (!d) return;
  if (d.enabled === false) {
    box.innerHTML = '<div class="mgr-empty">服务未启用登录认证，无需会话管理。</div>';
    return;
  }
  const list = d.sessions || [];
  if (!list.length) {
    box.innerHTML = '<div class="mgr-empty">当前没有活跃会话</div>';
    return;
  }
  box.innerHTML = '';
  list.forEach(s => {
    const el = document.createElement('div');
    el.className = 'sess-item';
    el.innerHTML = `
      <div class="sess-main">
        <div class="sess-line"><span class="sess-ip">${s.ip ? esc(s.ip) : 'IP 未记录（升级到 v1.0.13 之前的旧会话）'}</span>${s.current ? ' <span class="tag blue">当前会话</span>' : ''}</div>
        <div class="sess-meta">登录于 ${fmtTime(s.createdAt)} · 过期于 ${fmtTime(s.expiresAt)}${s.ip ? '' : ' · 退出登录后重新登录即可记录 IP'}</div>
      </div>`;
    const right = document.createElement('div');
    right.className = 'right-col';
    if (!s.current) {
      right.appendChild(mkAction('踢出', 'btn-soft mini btn-danger', async () => {
        if (!(await askConfirm('踢出会话', `确定踢出该会话？该浏览器需要重新登录。`))) return;
        try {
          await api('/api/sessions/kick', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: s.id })
          });
          toast('已踢出'); loadSessionsList();
        } catch (e) { toast(e.message); }
      }));
    }
    el.appendChild(right);
    box.appendChild(el);
  });
}

on('#pw-save', 'click', async () => {
  const st = $('#pw-status');
  const oldPw = ($('#pw-old') || {}).value || '';
  const newPw = ($('#pw-new') || {}).value || '';
  const newPw2 = ($('#pw-new2') || {}).value || '';
  if (!oldPw) return toast('请输入当前密码');
  if (newPw.length < 6) return toast('新密码至少需要 6 位');
  if (newPw !== newPw2) return toast('两次输入的新密码不一致');
  try {
    await api('/api/password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ oldPass: oldPw, newPass: newPw })
    });
    ['#pw-old', '#pw-new', '#pw-new2'].forEach(id => { const el = $(id); if (el) el.value = ''; });
    if (st) st.textContent = '密码已修改，下次登录请使用新密码；当前登录会话保持有效。';
    toast('密码已修改');
  } catch (e) {
    if (st) st.textContent = '修改失败：' + esc(e.message);
  }
});

/* ---------------- 回收站 ---------------- */
const trashSel = new Set(); // 勾选的回收站条目名
async function loadTrash() {
  const box = $('#trash-list');
  if (!box) return;
  box.innerHTML = '<div class="mgr-empty">加载中…</div>';
  let d;
  try { d = await api('/api/trash'); } catch (e) { box.innerHTML = `<div class="mgr-empty">${esc(e.message)}</div>`; return; }
  if (!d) return;
  const days = $('#trash-days'); if (days) days.textContent = d.retentionDays || '—';
  trashSel.clear();
  updateTrashBatchUI();
  if (!d.items || !d.items.length) {
    box.innerHTML = '<div class="mgr-empty">回收站是空的<br>删除的文件会先移到这里，保留期内可随时恢复</div>';
    return;
  }
  box.innerHTML = '';
  d.items.forEach(it => {
    const el = document.createElement('div');
    el.className = 'trash-item';
    el.innerHTML = `
      <input type="checkbox" class="row-check trash-check" data-name="${esc(it.name)}" title="选择此条目">
      <div class="fi ${it.isDir ? 'dir' : ''}">${it.isDir ? svgDir : svgFile}</div>
      <div class="trash-main">
        <div class="mgr-name">${esc((it.orig || it.name).split('/').pop())}</div>
        <div class="trash-orig">原路径：${esc(it.orig)} · 删除于 ${fmtTime(it.deleted)} · ${it.isDir ? '文件夹' : fmtSize(it.size)}</div>
      </div>`;
    el.querySelector('.trash-check').addEventListener('change', (e) => {
      if (e.target.checked) trashSel.add(it.name);
      else trashSel.delete(it.name);
      updateTrashBatchUI();
    });
    const right = document.createElement('div');
    right.className = 'right-col';
    right.appendChild(mkAction('恢复', 'btn-primary mini', async () => {
      try {
        const r = await api('/api/trash/restore', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: it.name })
        });
        toast('已恢复到 ' + ((r && r.path) || '原位置'));
        loadTrash(); loadList(state.curPath);
      } catch (e) { toast(e.message); }
    }));
    right.appendChild(mkAction('彻底删除', 'btn-soft mini btn-danger', async () => {
      if (!(await askConfirm('彻底删除', `彻底删除「${it.orig}」？此操作不可恢复。`))) return;
      try {
        await api('/api/trash/purge', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: it.name })
        });
        toast('已彻底删除'); loadTrash();
      } catch (e) { toast(e.message); }
    }));
    el.appendChild(right);
    box.appendChild(el);
  });
}
function updateTrashBatchUI() {
  const btnR = $('#trash-batch-restore'), btnP = $('#trash-batch-purge'), all = $('#trash-check-all');
  if (btnR) btnR.disabled = trashSel.size === 0;
  if (btnP) btnP.disabled = trashSel.size === 0;
  if (all) {
    const boxes = $$('#trash-list .trash-check');
    all.checked = boxes.length > 0 && trashSel.size === boxes.length;
    all.indeterminate = trashSel.size > 0 && trashSel.size < boxes.length;
  }
}
on('#trash-check-all', 'change', () => {
  const on_ = $('#trash-check-all').checked;
  $$('#trash-list .trash-check').forEach(c => {
    c.checked = on_;
    if (on_) trashSel.add(c.dataset.name); else trashSel.delete(c.dataset.name);
  });
  updateTrashBatchUI();
});
on('#trash-batch-restore', 'click', async () => {
  const names = Array.from(trashSel);
  if (!names.length) return;
  let ok = 0, fail = 0;
  for (const n of names) {
    try {
      await api('/api/trash/restore', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: n })
      });
      ok++;
    } catch (e) { fail++; }
  }
  toast(`恢复完成：成功 ${ok}${fail ? `，失败 ${fail}` : ''}`);
  loadTrash(); loadList(state.curPath);
});
on('#trash-batch-purge', 'click', async () => {
  const names = Array.from(trashSel);
  if (!names.length) return;
  if (!(await askConfirm('批量彻底删除', `彻底删除选中的 ${names.length} 项？此操作不可恢复。`))) return;
  let ok = 0, fail = 0;
  for (const n of names) {
    try {
      await api('/api/trash/purge', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: n })
      });
      ok++;
    } catch (e) { fail++; }
  }
  toast(`已彻底删除 ${ok} 项${fail ? `，失败 ${fail} 项` : ''}`);
  loadTrash();
});
on('#trash-clear', 'click', async () => {
  if (!(await askConfirm('清空回收站', '彻底删除回收站内的全部内容？此操作不可恢复。'))) return;
  try {
    const r = await api('/api/trash/clear', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    toast(`已清空 ${r.removed} 项`); loadTrash();
  } catch (e) { toast(e.message); }
});
