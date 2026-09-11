/* FileHub 内置二维码生成器（零第三方依赖）
 *
 * 能力：字节模式 + 纠错等级 M + 版本 1-10（约 106 字节，足够容纳分享链接）
 * 实现：GF(256) 里德-所罗门纠错、BCH 格式信息全部运行时计算（避免手抄表出错），
 *       8 种掩码按惩罚分自动择优。参考 ISO/IEC 18004。
 * 接口：
 *   FHQR.make(text)            -> { size, modules }  modules[y][x] 为 true/false，不含静区
 *   FHQR.draw(canvas, text, px) -> 在 canvas 上绘制（px 为每模块像素数，默认 4）
 */
(function (global) {
  'use strict';

  /* ---------- GF(256)，本原多项式 0x11D ---------- */
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function () {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const gmul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];

  /* ---------- 里德-所罗门 ---------- */
  // 多项式乘（系数最高次在前）
  function polyMult(a, b) {
    const r = new Array(a.length + b.length - 1).fill(0);
    for (let i = 0; i < a.length; i++)
      for (let j = 0; j < b.length; j++)
        r[i + j] ^= gmul(a[i], b[j]);
    return r;
  }
  // 生成多项式 (x - α^0)(x - α^1)…(x - α^(n-1))
  function rsGenPoly(n) {
    let p = [1];
    for (let i = 0; i < n; i++) p = polyMult(p, [1, EXP[i]]);
    return p;
  }
  // 综合除法取余数：data 长度 = 数据长 + ecLen（尾部 ecLen 个 0）
  function rsRemainder(data, gen) {
    for (let i = 0; i <= data.length - gen.length; i++) {
      const coef = data[i];
      if (coef === 0) continue;
      for (let j = 0; j < gen.length; j++) data[i + j] ^= gmul(gen[j], coef);
    }
    return data.slice(data.length - (gen.length - 1));
  }

  /* ---------- 版本表（纠错等级 M） ---------- */
  // 块结构：数组元素 = [块数, 每块数据码字数]（不同块长的取两种组合）
  const M_BLOCKS = {
    1: [[1, 16]], 2: [[1, 28]], 3: [[1, 44]], 4: [[2, 32]],
    5: [[2, 43]], 6: [[4, 27]], 7: [[4, 31]],
    8: [[2, 38], [2, 39]], 9: [[3, 36], [2, 37]], 10: [[4, 43], [1, 44]],
  };
  const TOTAL_CODEWORDS = { 1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242, 9: 292, 10: 346 };
  // 校正图形中心坐标（v2 起有，v1 无）
  const ALIGN_POS = {
    2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
  };
  const dataCodewords = (v) => M_BLOCKS[v].reduce((s, b) => s + b[0] * b[1], 0);
  const countBits = (v) => (v <= 9 ? 8 : 16);

  /* ---------- 比特流 ---------- */
  class BitBuf {
    constructor() { this.buf = []; this.len = 0; }
    push(val, n) {
      for (let i = n - 1; i >= 0; i--) {
        this.buf.push((val >>> i) & 1);
        this.len++;
      }
    }
    toBytes() {
      const out = [];
      for (let i = 0; i < this.buf.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | (this.buf[i + j] || 0);
        out.push(b);
      }
      return out;
    }
  }

  /* ---------- 编码主流程 ---------- */
  function make(text) {
    const bytes = new TextEncoder().encode(text);
    // 选版本：最小能容纳 4(模式) + countBits + 8*len 的版本
    let version = 0;
    for (let v = 1; v <= 10; v++) {
      if (4 + countBits(v) + 8 * bytes.length <= dataCodewords(v) * 8) { version = v; break; }
    }
    if (!version) throw new Error('内容过长，超出二维码容量（版本 10 / 等级 M）');

    // 1) 数据比特流
    const bb = new BitBuf();
    bb.push(0b0100, 4); // 字节模式
    bb.push(bytes.length, countBits(version));
    for (const b of bytes) bb.push(b, 8);
    const dataBits = dataCodewords(version) * 8;
    bb.push(0, Math.min(4, dataBits - bb.len)); // 终止符
    while (bb.len % 8 !== 0) bb.push(0, 1);     // 字节对齐
    const dataBytes = bb.toBytes();
    const pad = [0xEC, 0x11];                   // 填充字节
    for (let i = 0; dataBytes.length < dataCodewords(version); i++) dataBytes.push(pad[i % 2]);

    // 2) 分块 + RS 纠错
    const blocks = [];
    let off = 0;
    for (const [cnt, len] of M_BLOCKS[version]) {
      for (let b = 0; b < cnt; b++) {
        const data = dataBytes.slice(off, off + len);
        off += len;
        const ecLen = (TOTAL_CODEWORDS[version] - dataCodewords(version)) /
          M_BLOCKS[version].reduce((s, x) => s + x[0], 0);
        const gen = rsGenPoly(ecLen);
        const ec = rsRemainder(data.concat(new Array(ecLen).fill(0)), gen);
        blocks.push({ data, ec });
      }
    }

    // 3) 交错
    const final = [];
    const maxData = Math.max(...blocks.map(b => b.data.length));
    for (let i = 0; i < maxData; i++)
      for (const b of blocks) if (i < b.data.length) final.push(b.data[i]);
    const ecLen0 = blocks[0].ec.length;
    for (let i = 0; i < ecLen0; i++)
      for (const b of blocks) final.push(b.ec[i]);
    if (final.length !== TOTAL_CODEWORDS[version]) throw new Error('码字总数校验失败');

    // 4) 构建矩阵（含 8 种掩码择优）
    return buildMatrix(version, final);
  }

  /* ---------- 矩阵构建 ---------- */
  function buildMatrix(version, codewords) {
    const size = 17 + 4 * version;
    const mk = () => Array.from({ length: size }, () => new Array(size).fill(null));
    let best = null, bestScore = Infinity;

    for (let mask = 0; mask < 8; mask++) {
      const modules = mk();
      placeFunctionPatterns(modules, size, version);
      mapData(modules, size, codewords, mask);
      applyFormatInfo(modules, size, mask, false);
      if (version >= 7) applyVersionInfo(modules, size, version);
      const score = penalty(modules, size);
      if (score < bestScore) { bestScore = score; best = modules; }
    }
    return { size, modules: best.map(r => r.map(v => v === true)) };
  }

  // 掩码公式（i=行, j=列）
  function maskOn(mask, i, j) {
    switch (mask) {
      case 0: return (i + j) % 2 === 0;
      case 1: return i % 2 === 0;
      case 2: return j % 3 === 0;
      case 3: return (i + j) % 3 === 0;
      case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
      case 5: return (i * j) % 2 + (i * j) % 3 === 0;
      case 6: return ((i * j) % 2 + (i * j) % 3) % 2 === 0;
      case 7: return ((i * j) % 3 + (i + j) % 2) % 2 === 0;
    }
    return false;
  }

  // 功能图形：探测图形 + 分隔 + 时序线 + 校正图形 + 暗模块 + 预留格式区
  function placeFunctionPatterns(modules, size, version) {
    const finder = (row, col) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = row + r, cc = col + c;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          const dark = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
            (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          modules[rr][cc] = dark;
        }
      }
    };
    finder(0, 0);
    finder(size - 7, 0);
    finder(0, size - 7);
    // 校正图形必须先于时序线：中心落在行/列 6 上的校正图形要占据并穿透时序线，
    // 若时序线先画，中心格已被占用会导致该校正图形被跳过（v7+ 解码失败）
    const pos = ALIGN_POS[version];
    if (pos) {
      for (const r of pos) {
        for (const c of pos) {
          if (modules[r][c] !== null) continue; // 与探测图形重叠处跳过
          for (let dr = -2; dr <= 2; dr++) {
            for (let dc = -2; dc <= 2; dc++) {
              modules[r + dr][c + dc] =
                dr === -2 || dr === 2 || dc === -2 || dc === 2 || (dr === 0 && dc === 0);
            }
          }
        }
      }
    }
    // 时序线（跳过已被功能图形占据的格子）
    for (let i = 8; i < size - 8; i++) {
      if (modules[i][6] === null) modules[i][6] = i % 2 === 0;
      if (modules[6][i] === null) modules[6][i] = i % 2 === 0;
    }
    // 暗模块（规格固定位置）
    modules[size - 8][8] = true;
    // 预留格式信息位（稍后写入；先占位避免数据区侵入）
    for (let i = 0; i < 9; i++) {
      if (modules[8][i] === null) modules[8][i] = false;
      if (modules[i][8] === null) modules[i][8] = false;
    }
    for (let i = 0; i < 8; i++) {
      if (modules[8][size - 1 - i] === null) modules[8][size - 1 - i] = false;
      if (modules[size - 1 - i][8] === null) modules[size - 1 - i][8] = false;
    }
    // 版本信息区（v>=7，右上 + 左下 3x6）
    if (version >= 7) {
      for (let i = 0; i < 18; i++) {
        const r1 = Math.floor(i / 3), c1 = size - 11 + (i % 3);
        if (modules[r1][c1] === null) modules[r1][c1] = false;
        const r2 = size - 11 + (i % 3), c2 = Math.floor(i / 3);
        if (modules[r2][c2] === null) modules[r2][c2] = false;
      }
    }
  }

  // 数据区按两列锯齿形从右下向上填充
  function mapData(modules, size, data, mask) {
    let inc = -1, row = size - 1, bitIdx = 7, byteIdx = 0;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--; // 跳过时序列
      for (;;) {
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (modules[row][cc] !== null) continue;
          let dark = false;
          if (byteIdx < data.length) dark = ((data[byteIdx] >>> bitIdx) & 1) === 1;
          if (maskOn(mask, row, cc)) dark = !dark;
          modules[row][cc] = dark;
          bitIdx--;
          if (bitIdx === -1) { byteIdx++; bitIdx = 7; }
        }
        row += inc;
        if (row < 0 || row >= size) { row -= inc; inc = -inc; break; }
      }
    }
  }

  /* ---------- BCH 与格式/版本信息 ---------- */
  function bchDigit(v) { let d = 0; while (v !== 0) { d++; v >>>= 1; } return d; }
  const G15 = 0x537, G15_MASK = 0x5412, G18 = 0x1F25;

  function formatBits(mask) {
    const data = mask; // 纠错等级 M = 00 → data = mask(0-7)
    let d = data << 10;
    while (bchDigit(d) - bchDigit(G15) >= 0) d ^= (G15 << (bchDigit(d) - bchDigit(G15)));
    return ((data << 10) | d) ^ G15_MASK;
  }
  function versionBits(v) {
    let d = v << 12;
    while (bchDigit(d) - bchDigit(G18) >= 0) d ^= (G18 << (bchDigit(d) - bchDigit(G18)));
    return (v << 12) | d;
  }

  function applyFormatInfo(modules, size, mask, testOnly) {
    const bits = formatBits(mask);
    // 竖排（左上角向下 + 左下角向上）
    for (let i = 0; i < 15; i++) {
      const v = !testOnly && ((bits >> i) & 1) === 1;
      if (i < 6) modules[i][8] = v;
      else if (i < 8) modules[i + 1][8] = v;
      else modules[size - 15 + i][8] = v;
    }
    // 横排（右上向左 + 左上角向右；列 6 为时序线，第 9 位起跳过）
    for (let i = 0; i < 15; i++) {
      const v = !testOnly && ((bits >> i) & 1) === 1;
      if (i < 8) modules[8][size - 1 - i] = v;
      else if (i < 9) modules[8][15 - i] = v; // i=8 → modules[8][7]
      else modules[8][14 - i] = v;            // i=9..14 → modules[8][5..0]
    }
    // 暗模块恒为 1（此处再次确保）
    modules[size - 8][8] = true;
  }

  function applyVersionInfo(modules, size, version) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const v = ((bits >> i) & 1) === 1;
      modules[Math.floor(i / 3)][size - 11 + (i % 3)] = v;
      modules[size - 11 + (i % 3)][Math.floor(i / 3)] = v;
    }
  }

  /* ---------- 掩码评分（择优用，实现与 ISO 一致的简化版） ---------- */
  function penalty(modules, size) {
    let score = 0;
    // N1：行/列连续同色 ≥5
    for (let i = 0; i < size; i++) {
      let runR = 1, runC = 1;
      for (let j = 1; j < size; j++) {
        if (modules[i][j] === modules[i][j - 1]) { runR++; if (j === size - 1 && runR >= 5) score += 3 + (runR - 5); }
        else { if (runR >= 5) score += 3 + (runR - 5); runR = 1; }
        if (modules[j][i] === modules[j - 1][i]) { runC++; if (j === size - 1 && runC >= 5) score += 3 + (runC - 5); }
        else { if (runC >= 5) score += 3 + (runC - 5); runC = 1; }
      }
    }
    // N2：2x2 同色块
    for (let i = 0; i < size - 1; i++) {
      for (let j = 0; j < size - 1; j++) {
        const s = (modules[i][j] ? 1 : 0) + (modules[i][j + 1] ? 1 : 0) +
          (modules[i + 1][j] ? 1 : 0) + (modules[i + 1][j + 1] ? 1 : 0);
        if (s === 0 || s === 4) score += 3;
      }
    }
    // N3：行/列 1011101 图样（前后接浅色，简化为检查 7 模块图样）
    const pat = [true, false, true, true, true, false, true];
    for (let i = 0; i < size; i++) {
      for (let j = 0; j <= size - 7; j++) {
        let okR = true, okC = true;
        for (let k = 0; k < 7; k++) {
          if (modules[i][j + k] !== pat[k]) okR = false;
          if (modules[j + k][i] !== pat[k]) okC = false;
        }
        if (okR) score += 40;
        if (okC) score += 40;
      }
    }
    // N4：暗模块占比偏离 50%
    let dark = 0;
    for (let i = 0; i < size; i++) for (let j = 0; j < size; j++) if (modules[i][j]) dark++;
    score += Math.floor(Math.abs(dark * 100 / (size * size) - 50) / 5) * 10;
    return score;
  }

  /* ---------- 绘制 ---------- */
  function draw(canvas, text, modulePx) {
    const px = modulePx || 4;
    const { size, modules } = make(text);
    const quiet = 4; // 静区
    const dim = (size + quiet * 2) * px;
    canvas.width = dim;
    canvas.height = dim;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = '#1A2233';
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y][x]) ctx.fillRect((x + quiet) * px, (y + quiet) * px, px, px);
      }
    }
  }

  const FHQR = { make, draw };
  if (typeof module !== 'undefined' && module.exports) module.exports = FHQR;
  global.FHQR = FHQR;
})(typeof window !== 'undefined' ? window : globalThis);