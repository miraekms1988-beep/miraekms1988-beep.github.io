/* 주간 채권동향 - 프론트엔드
 *
 * 글 본문과 목록 메타데이터는 모두 암호화된 상태로 저장된다.
 * (PBKDF2-SHA256 -> AES-256-CBC, encrypt-then-HMAC-SHA256)
 * 비밀번호가 없으면 서버에서 파일을 직접 받아도 내용을 읽을 수 없다.
 *
 * crypto.subtle 은 보안 컨텍스트에서만 동작한다. file:// 로 열면 실패하므로
 * 반드시 serve.ps1(http://localhost) 또는 HTTPS 로 접근할 것.
 */
'use strict';

const POSTS_DIR = 'posts';
const STORAGE_KEY = 'bw.pw';
const THEME_KEY = 'bw.theme';

// 구독 신청을 받는 곳. 이 사이트는 정적 호스팅이라 폼 제출을 받을 수 없어
// 구글 Apps Script 웹 앱을 접수처로 쓴다. 만드는 법은 docs/signup-setup.md.
// 이 주소는 소스 보기로 누구나 읽을 수 있다. 그래도 되는 이유는
// 이 창구가 '접수'만 하기 때문이다. 명부를 돌려주는 쪽은 키를 따로 확인한다.
// 비어 있으면 잠금화면에 신청 버튼이 나오지 않는다.
const SIGNUP_URL = 'https://script.google.com/macros/s/AKfycbxWgN0pXVPbzgxkER8CJxPPrNefC046e-Z_TfP6eeT8PNc5Ll-vEWFa4o_TCZjI9nvJ/exec';

// 작성자 정보. 이름·소속·연락처는 개인정보라 이 파일에 적어두지 않는다.
// 여기 적으면 정적 호스팅에서 소스 보기만으로 누구나 읽을 수 있다.
// 실제 값은 posts/author.enc.json 에 암호문으로 있고, 잠금해제 때 채워진다.
// 내용을 바꾸려면 data/author.json 을 고치고 다시 발행하면 된다.
let AUTHOR = { name: '', title: '', org: '', team: '', cert: '', tel: '' };

const els = {
  lock: document.getElementById('lock'),
  lockForm: document.getElementById('lock-form'),
  pw: document.getElementById('pw'),
  remember: document.getElementById('remember'),
  unlockBtn: document.getElementById('unlock-btn'),
  lockError: document.getElementById('lock-error'),
  app: document.getElementById('app'),
  view: document.getElementById('view'),
  progress: document.getElementById('progress'),
  backBtn: document.getElementById('back-btn'),
  brand: document.getElementById('brand'),
  themeBtn: document.getElementById('theme-btn'),
  lockBtn: document.getElementById('lock-btn'),
  toast: document.getElementById('toast'),
  footId: document.getElementById('foot-id'),
  signupOpen: document.getElementById('signup-open'),
  signupForm: document.getElementById('signup-form'),
  signupBtn: document.getElementById('signup-btn'),
  signupError: document.getElementById('signup-error'),
  signupCancel: document.getElementById('signup-cancel'),
  signupDone: document.getElementById('signup-done'),
  signupBack: document.getElementById('signup-back'),
};

// 푸터의 작성자 줄. 잠금해제로 AUTHOR 가 채워진 뒤에만 그린다.
function renderFoot() {
  if (!els.footId) return;
  if (!AUTHOR.name) { els.footId.innerHTML = ''; return; }
  els.footId.innerHTML =
    `<strong>${escapeHtml(AUTHOR.name)}</strong> ${escapeHtml(AUTHOR.title)}`
    + (AUTHOR.cert ? ` · ${escapeHtml(AUTHOR.cert)}` : '')
    + `<br>${escapeHtml(AUTHOR.org)} ${escapeHtml(AUTHOR.team)}`
    + (AUTHOR.tel ? `<br>${escapeHtml(AUTHOR.tel)}` : '');
}

const state = {
  manifest: null,
  keys: null,
  index: [],
  cache: new Map(),
  issCache: new Map(),
  chart: null,
};

/* ================= 유틸 ================= */

const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

let toastTimer = null;
function toast(msg) {
  els.toast.textContent = msg;
  els.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { els.toast.hidden = true; }, 2400);
}

/* ================= 암호 ================= */

async function deriveKeys(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey(
    'raw', textEnc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations, hash: 'SHA-256' },
    base, 512);
  const raw = new Uint8Array(bits);
  return {
    aes: await crypto.subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']),
    mac: await crypto.subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']),
  };
}

// 봉투 = { iv, ct, mac }. MAC 은 (iv || ct) 에 대해 계산돼 있다.
async function openEnvelope(keys, env) {
  const iv = b64ToBytes(env.iv);
  const ct = b64ToBytes(env.ct);
  const mac = b64ToBytes(env.mac);

  const signed = new Uint8Array(iv.length + ct.length);
  signed.set(iv, 0);
  signed.set(ct, iv.length);

  const valid = await crypto.subtle.verify('HMAC', keys.mac, mac, signed);
  if (!valid) throw new Error('AUTH_FAILED');

  const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, keys.aes, ct);
  return textDec.decode(plain);
}

// manifest 의 발행 시각을 쿼리로 붙여 캐시를 건너뛴다.
// 이게 없으면 발행 직후에도 서비스워커가 옛 글을 돌려줄 수 있다.
async function fetchJson(path, versioned = true) {
  const v = versioned && state.manifest && state.manifest.updated ? `?v=${state.manifest.updated}` : '';
  const res = await fetch(path + v, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

/* ================= 마크다운 ================= */

// 마크다운 본문에 나타날 일이 없는 제어문자를 자리표시자로 쓴다.
const PH_BRK_L = '\u0011';
const PH_BRK_R = '\u0012';
const PH_CODE_L = '\u0013';
const PH_CODE_R = '\u0014';

function renderInline(src) {
  // 초안 생성기가 기사 제목의 대괄호를 \[ \] 로 escape 해서 넣는다.
  // 링크 문법으로 오인되지 않도록 먼저 자리표시자로 빼둔다.
  let s = src.replace(/\\\[/g, PH_BRK_L).replace(/\\\]/g, PH_BRK_R);

  const codes = [];
  s = s.replace(/`([^`]+)`/g, (_, c) => {
    codes.push(c);
    return PH_CODE_L + (codes.length - 1) + PH_CODE_R;
  });

  s = escapeHtml(s);

  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, text, href) => {
    const safe = /^(https?:|mailto:|#|\/)/i.test(href) ? href : '#';
    const ext = /^https?:/i.test(safe) ? ' target="_blank" rel="noopener noreferrer"' : '';
    return `<a href="${safe}"${ext}>${text}</a>`;
  });

  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/(^|[\s(])_([^_]+)_(?=[\s.,)]|$)/g, '$1<em>$2</em>');

  s = s.replace(new RegExp(PH_CODE_L + '(\\d+)' + PH_CODE_R, 'g'),
    (_, i) => `<code>${escapeHtml(codes[+i])}</code>`);

  return s.split(PH_BRK_L).join('[').split(PH_BRK_R).join(']');
}
function renderTable(rows) {
  const cells = (line) => line.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const head = cells(rows[0]);
  const aligns = cells(rows[1]).map((c) => (c.endsWith(':') && !c.startsWith(':') ? ' class="num"' : ''));

  // 셀 내용을 세 가지로 나눠 그린다.
  //   "4.064 (-0.031)"  값 + 증감  -> 증감을 아랫줄에 작게, 부호에 따라 색
  //   "-0.031"          증감만     -> 색만
  //   그 외                        -> 그대로
  const signOf = (t) => (/^\+/.test(t) ? 'up' : /^-/.test(t) ? 'down' : '');

  const renderCell = (raw, isNum) => {
    const t = raw.trim();
    if (!isNum) return `<td>${renderInline(t)}</td>`;

    // 값 부분에 "2.85~3.30~3.65" 같은 범위가 오는 표도 있다
    const pair = t.match(/^([\d.,~]+)\s*\(([+-]?[\d.,]+)\)$/);
    if (pair) {
      const s = signOf(pair[2]);
      return `<td class="num"><span class="v">${pair[1]}</span>` +
             `<span class="d ${s}">${pair[2]}</span></td>`;
    }
    const s = signOf(t);
    return `<td class="num${s ? ' ' + s : ''}">${renderInline(t)}</td>`;
  };

  // 열 개수를 남겨둔다. 좁은 화면에서 넓은 표만 골라 줄이려면 CSS 쪽에
  // 열이 몇 개인지 알려줄 방법이 있어야 한다.
  let html = `<div class="table-wrap" data-cols="${head.length}"><table><thead><tr>`;
  head.forEach((c, i) => { html += `<th${aligns[i] || ''}>${renderInline(c)}</th>`; });
  html += '</tr></thead><tbody>';
  for (let i = 2; i < rows.length; i++) {
    html += '<tr>';
    cells(rows[i]).forEach((c, j) => { html += renderCell(c, !!aligns[j]); });
    html += '</tr>';
  }
  return html + '</tbody></table></div>';
}

function renderMarkdown(md) {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  let para = [];
  let list = null;      // { type: 'ul'|'ol', items: [] }
  let quote = null;     // string[]
  let notes = null;     // string[] - 표 아래 출처·단서 줄

  const flushPara = () => {
    if (para.length) { out.push(`<p>${renderInline(para.join(' '))}</p>`); para = []; }
  };
  const flushList = () => {
    if (list) {
      out.push(`<${list.type}>${list.items.map((i) => `<li>${renderInline(i)}</li>`).join('')}</${list.type}>`);
      list = null;
    }
  };
  const flushQuote = () => {
    if (quote) {
      out.push(`<blockquote>${quote.map((q) => `<p>${renderInline(q)}</p>`).join('')}</blockquote>`);
      quote = null;
    }
  };
  // "_증감은 … 대비. 자료: …_" 처럼 한 줄 전체가 기울임인 것은 본문이 아니라
  // 표에 딸린 주석이다. 본문과 같은 크기로 두면 시선을 뺏어서, 따로 모아
  // 작게 붙인다. 연달아 나오는 주석은 한 덩어리로 묶는다.
  const flushNotes = () => {
    if (notes) {
      out.push(`<div class="notes">${notes.map((n) => `<span>${renderInline(n)}</span>`).join('')}</div>`);
      notes = null;
    }
  };
  const flushAll = () => { flushPara(); flushList(); flushQuote(); flushNotes(); };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) { flushAll(); continue; }

    // 금리 추이 차트 자리 (초안의 ::chart:: 줄)
    if (trimmed === '::chart::') { flushAll(); out.push('<div data-chart="rates"></div>'); continue; }

    // 표: 헤더 다음 줄이 구분선이어야 한다
    if (trimmed.startsWith('|') && /^\|[\s:|-]+\|$/.test((lines[i + 1] || '').trim())) {
      flushAll();
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) rows.push(lines[i++].trim());
      i--;
      out.push(renderTable(rows));
      continue;
    }

    // 줄 전체가 _…_ 이면 주석으로 본다 (밑줄표시가 중간에만 있는 문장은 제외)
    const note = trimmed.match(/^_([^_].*[^_])_$/);
    if (note) {
      flushPara(); flushList(); flushQuote();
      (notes = notes || []).push(note[1]);
      continue;
    }

    const h = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (h) { flushAll(); const lv = h[1].length; out.push(`<h${lv}>${renderInline(h[2])}</h${lv}>`); continue; }

    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) { flushAll(); out.push('<hr>'); continue; }

    if (trimmed.startsWith('>')) {
      flushPara(); flushList();
      (quote = quote || []).push(trimmed.replace(/^>\s?/, ''));
      continue;
    }

    const ul = trimmed.match(/^[-*]\s+(.*)$/);
    const ol = trimmed.match(/^\d+\.\s+(.*)$/);
    if (ul || ol) {
      flushPara(); flushQuote();
      const type = ul ? 'ul' : 'ol';
      if (!list || list.type !== type) { flushList(); list = { type, items: [] }; }
      list.items.push((ul || ol)[1]);
      continue;
    }

    flushList(); flushQuote(); flushNotes();
    para.push(trimmed);
  }
  flushAll();

  return collapseSources(out.join('\n'));
}

// 참고 기사 절이 남아 있으면 접어둔다. (지금 양식에는 없지만 옛 글 호환용)
function collapseSources(html) {
  const marker = /<h2>([^<]*참고 기사[^<]*)<\/h2>/;
  const m = html.match(marker);
  if (!m) return html;
  const before = html.slice(0, m.index);
  const rest = html.slice(m.index + m[0].length);
  return `${before}<details><summary>${m[1]}</summary>${rest}</details>`;
}

/* ================= 금리 추이 차트 ================= */

const CHART_COLORS = ['#1d4ed8', '#d1343f', '#0f9d58', '#a855f7', '#f59e0b'];

// 의존성 없이 인라인 SVG 로 그린다. 값이 없는 날(null)은 선을 끊는다.
function renderChart(box, chart) {
  const W = 720, H = 300;
  const pad = { t: 16, r: 12, b: 30, l: 46 };
  const iw = W - pad.l - pad.r;
  const ih = H - pad.t - pad.b;

  const all = chart.series.flatMap((s) => s.data).filter((v) => typeof v === 'number');
  if (!all.length) { box.innerHTML = '<p class="chart-empty">금리 데이터가 없습니다.</p>'; return; }

  let min = Math.min(...all), max = Math.max(...all);
  const span = max - min || 1;
  min -= span * 0.12; max += span * 0.12;

  const n = chart.labels.length;
  const x = (i) => pad.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v) => pad.t + ih - ((v - min) / (max - min)) * ih;

  // 가로 눈금 5개
  let grid = '', ticks = '';
  for (let k = 0; k <= 4; k++) {
    const v = min + ((max - min) * k) / 4;
    const yy = y(v);
    grid += `<line x1="${pad.l}" y1="${yy.toFixed(1)}" x2="${W - pad.r}" y2="${yy.toFixed(1)}" class="c-grid"/>`;
    ticks += `<text x="${pad.l - 8}" y="${(yy + 4).toFixed(1)}" class="c-ylab">${v.toFixed(2)}</text>`;
  }

  // 날짜 라벨 (처음/중간/끝)
  const short = (d) => (d ? d.slice(5).replace('-', '/') : '');
  let xlab = '';
  [0, Math.floor((n - 1) / 2), n - 1].forEach((i, k) => {
    if (i < 0 || i >= n) return;
    const anchor = k === 0 ? 'start' : k === 2 ? 'end' : 'middle';
    xlab += `<text x="${x(i).toFixed(1)}" y="${H - 8}" class="c-xlab" text-anchor="${anchor}">${short(chart.labels[i])}</text>`;
  });

  let paths = '', dots = '';
  chart.series.forEach((s, si) => {
    const color = CHART_COLORS[si % CHART_COLORS.length];
    let d = '', pen = false;
    s.data.forEach((v, i) => {
      if (typeof v !== 'number') { pen = false; return; }
      d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)} `;
      pen = true;
    });
    if (d) paths += `<path d="${d.trim()}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;

    // 마지막 값에 점 하나
    for (let i = s.data.length - 1; i >= 0; i--) {
      if (typeof s.data[i] === 'number') {
        dots += `<circle cx="${x(i).toFixed(1)}" cy="${y(s.data[i]).toFixed(1)}" r="3.5" fill="${color}"/>`;
        break;
      }
    }
  });

  const legend = chart.series.map((s, si) => {
    const last = [...s.data].reverse().find((v) => typeof v === 'number');
    const color = CHART_COLORS[si % CHART_COLORS.length];
    return `<span class="c-item"><i style="background:${color}"></i>${escapeHtml(s.name)}
      <b>${last != null ? last.toFixed(3) : '-'}</b></span>`;
  }).join('');

  box.innerHTML = `
    <figure class="chart">
      <div class="chart-legend">${legend}</div>
      <div class="chart-scroll">
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img"
             aria-label="금리 추이 차트">
          ${grid}${paths}${dots}${ticks}${xlab}
        </svg>
      </div>
      <figcaption>최근 ${n}영업일 · 자료: 한국자산평가, 금융투자협회</figcaption>
    </figure>`;
}

// 차트 데이터는 전체 기간을 한 파일로 갖고 있다. 글마다 그 주까지만 잘라서
// 그려야 한다. 안 그러면 7월 글에 8월 금리가 섞여 표와 범례가 어긋난다.
function clipChart(chart, endDate) {
  if (!endDate) return chart;
  let last = -1;
  for (let i = 0; i < chart.labels.length; i++) {
    if (chart.labels[i] <= endDate) last = i; else break;
  }
  if (last < 0 || last === chart.labels.length - 1) return chart;
  return {
    labels: chart.labels.slice(0, last + 1),
    series: chart.series.map((s) => ({ name: s.name, data: s.data.slice(0, last + 1) })),
  };
}

async function mountCharts(root, postDate) {
  const boxes = root.querySelectorAll('[data-chart="rates"]');
  if (!boxes.length) return;

  if (!state.chart) {
    try {
      const env = await fetchJson(`${POSTS_DIR}/rates.enc.json`);
      state.chart = JSON.parse(await openEnvelope(state.keys, env));
    } catch {
      boxes.forEach((b) => { b.innerHTML = '<p class="chart-empty">금리 데이터를 불러오지 못했습니다.</p>'; });
      return;
    }
  }

  // 글 날짜는 예고하는 주의 월요일이라, 정리 대상 주의 금요일은 사흘 전이다.
  // toISOString() 은 UTC 로 바꿔버려서 한국 시간대에서는 하루가 당겨진다.
  // 라벨이 로컬 날짜 문자열이므로 여기서도 로컬 기준으로 만들어야 맞는다.
  let cutoff = null;
  if (postDate) {
    const d = new Date(`${postDate}T00:00:00`);
    if (!isNaN(d)) {
      d.setDate(d.getDate() - 3);
      const p = (n) => String(n).padStart(2, '0');
      cutoff = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
    }
  }
  const data = clipChart(state.chart, cutoff);
  boxes.forEach((b) => renderChart(b, data));
}

/* ================= 서두 요약 ================= */

// 본문에서 그대로 옮겨온 문장들이라 새로 지어낸 말이 섞이지 않는다.
function renderDigest(d) {
  if (!d || !d.headline) return '';
  const points = (d.points || []).map((p) => `<li>${escapeHtml(p)}</li>`).join('');
  return `
    <aside class="digest">
      <div class="digest-label">요약</div>
      <p class="digest-lead">${escapeHtml(d.headline)}</p>
      ${points ? `<ul class="digest-points">${points}</ul>` : ''}
      ${d.ahead ? `<p class="digest-ahead">${escapeHtml(d.ahead)}</p>` : ''}
    </aside>`;
}

/* ================= SPC 발행내역 펼치기 ================= */

// 표의 SPC 칸은 "4곳" 처럼 숫자만 보여준다. 그게 어떤 건이었는지 궁금한 게
// 당연해서, 누르면 그 주 발행내역이 아래에 펼쳐지도록 한다.
// 데이터는 publish.ps1 이 글과 함께 내보낸 meta.issuance 에 들어 있다.
function fmtDate(d) {
  if (!d || d.length !== 8) return d || '';
  return `${+d.slice(4, 6)}/${+d.slice(6, 8)}`;
}

function issuanceRowsHtml(list) {
  const rows = list.map((d) => `
    <tr>
      <td>${escapeHtml(d.spc)}</td>
      <td class="num">${escapeHtml(String(d.rate))}</td>
      <td class="num">${escapeHtml(String(d.days))}일</td>
      <td>${fmtDate(d.issued)}~${fmtDate(d.maturity)}</td>
      <td>${escapeHtml(d.trade)}</td>
      <td>${escapeHtml(d.kind || '')}</td>
    </tr>`).join('');
  return `
    <div class="spc-detail">
      <table class="spc-table">
        <thead><tr><th>SPC</th><th class="num">금리</th><th class="num">잔존</th><th>발행~만기</th><th>거래</th><th>구분</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// 표 종류를 머리글로 판별한다. '매입확약'이면 증권사(fin), '시공사'면 건설사(con).
function mountSpcToggles(root, issuance) {
  if (!issuance) return;

  root.querySelectorAll('.prose table').forEach((table) => {
    const head = [...table.rows[0].cells].map((c) => c.textContent.trim());
    const roleIdx = head.findIndex((h) => h === '매입확약' || h === '시공사');
    // 펼치기 버튼은 '건수' 칸에 단다. SPC 곳수보다 거래 건수 쪽이
    // "이만큼 있다 -> 눌러서 본다" 는 흐름에 더 자연스럽다.
    const countIdx = head.findIndex((h) => h === '건수');
    if (roleIdx < 0 || countIdx < 0) return;
    const role = head[roleIdx] === '시공사' ? 'con' : 'fin';

    [...table.tBodies[0].rows].forEach((tr) => {
      const name = tr.cells[roleIdx] ? tr.cells[roleIdx].textContent.trim() : '';
      const cell = tr.cells[countIdx];
      if (!name || !cell) return;
      const list = issuance[`${role}|${name}`];
      if (!list || !list.length) return;

      cell.innerHTML = `<button class="spc-btn" type="button">${cell.textContent.trim()}</button>`;
      cell.querySelector('.spc-btn').addEventListener('click', () => {
        const next = tr.nextElementSibling;
        if (next && next.classList.contains('spc-row')) { next.remove(); cell.querySelector('.spc-btn').classList.remove('open'); return; }
        const detail = document.createElement('tr');
        detail.className = 'spc-row';
        detail.innerHTML = `<td colspan="${tr.cells.length}">${issuanceRowsHtml(list)}</td>`;
        tr.after(detail);
        cell.querySelector('.spc-btn').classList.add('open');
      });
    });
  });
}

/* ================= 이번 주 이벤트 ================= */

function renderEvents(events) {
  if (!events || !events.length) return '';
  // 관련 기사는 발행 시점에 없다. 이벤트가 아직 안 일어났기 때문이다.
  // 주중에 update-events.ps1 이 채운 파일을 따로 받아 mountEventArticles 가 붙인다.
  // 자리로 찾는다. when 으로 찾으면 안 된다 — 같은 날 이벤트가 둘이면
  // ('13일 PPI', '13일 총재 발언') 둘 다 첫 번째에 붙는다.
  const items = events.map((ev, i) => `
      <li class="ev" data-idx="${i}">
        <div class="ev-head"><span class="ev-when">${escapeHtml(ev.when)}</span></div>
        <p class="ev-text">${escapeHtml(ev.text)}</p>
      </li>`).join('');
  return `
    <section class="events">
      <h2>이번 주 이벤트</h2>
      <ul class="ev-list">${items}</ul>
    </section>`;
}

/* 이벤트에 따라 붙는 기사.
   이벤트가 실제로 일어난 뒤에야 기사가 생기므로 글과 함께 오지 않는다.
   주중에 갱신되는 별도 파일을 받아 해당 이벤트 밑에 붙인다.
   파일이 아직 없으면(404) 조용히 넘어간다 — 발행 직후가 그 상태다. */
async function mountEventArticles(root, week) {
  if (!week) return;

  let data;
  try {
    const env = await fetchJson(`${POSTS_DIR}/${week}.events.enc.json`);
    data = JSON.parse(await openEnvelope(state.keys, env));
  } catch {
    return;   // 아직 갱신 전이거나 붙을 기사가 없다
  }
  if (!data || !Array.isArray(data.events)) return;

  let any = false;
  for (const ev of data.events) {
    const list = (ev.articles || []);
    if (!list.length) continue;
    // idx 는 update-events.ps1 이 붙인 이벤트 순번이다. 글의 이벤트 목록과
    // 같은 함수·같은 초안에서 나오므로 순서가 일치한다.
    const li = root.querySelector(`.ev[data-idx="${Number(ev.idx)}"]`);
    if (!li) continue;

    const items = list.map((a) => `
      <li>
        <a href="${escapeHtml(a.link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.title)}</a>
        <span class="ev-src">${escapeHtml(a.source || '')}</span>
      </li>`).join('');
    li.insertAdjacentHTML('beforeend', `<ul class="ev-links">${items}</ul>`);
    any = true;
  }

  if (any && data.updated) {
    const sec = root.querySelector('.events');
    if (sec) sec.insertAdjacentHTML('beforeend', `<p class="ev-updated">기사 갱신: ${escapeHtml(data.updated)}</p>`);
  }
}

/* ================= 화면 ================= */

function formatDate(iso) {
  const d = new Date(`${iso}T00:00:00`);
  if (isNaN(d)) return iso;
  return `${d.getFullYear()}. ${d.getMonth() + 1}. ${d.getDate()}.`;
}

/* 목록은 최근 5편만 먼저 보여준다.
   글이 쌓일수록 첫 화면이 스크롤만 길어지는데, 들어오는 사람 대부분은
   최근 것을 보러 온다. 한 번 펼치면 세션 동안 펼친 채로 둔다 —
   글을 읽고 뒤로 나왔을 때 다시 접혀 있으면 성가시다. */
const LIST_PAGE = 5;
let listShown = LIST_PAGE;

function renderList() {
  els.backBtn.hidden = true;
  document.title = '주간 채권동향';

  if (!state.index.length) {
    els.view.innerHTML = `
      <div class="empty">
        <p>아직 발행된 글이 없습니다.</p>
        <p>초안을 완성한 뒤 발행하세요.</p>
        <code>.\\publish.ps1 -Path drafts\\draft-....md</code>
      </div>`;
    setProgress(false);
    return;
  }

  // 표지. 글 목록 위에 한 번만 나온다.
  const latest = state.index[0];
  const span = state.index.length > 1
    ? `${formatDate(state.index[state.index.length - 1].date)} ~ ${formatDate(latest.date)}`
    : formatDate(latest.date);

  const hero = `
    <header class="hero">
      <div class="hero-body">
        <p class="hero-kicker">WEEKLY BOND MARKET REVIEW</p>
        <h1 class="hero-title">주간 채권시장 동향</h1>
        <div class="hero-author">
          <span class="hero-avatar" aria-hidden="true">${escapeHtml(AUTHOR.name[0])}</span>
          <span class="hero-who">
            <b>${escapeHtml(AUTHOR.name)} ${escapeHtml(AUTHOR.title)}</b>
            <span>${escapeHtml(AUTHOR.org)} ${escapeHtml(AUTHOR.team)}</span>
            <a class="hero-tel" href="tel:${escapeHtml(AUTHOR.tel.replace(/-/g, ''))}">${escapeHtml(AUTHOR.tel)}</a>
          </span>
          <span class="hero-cert">${escapeHtml(AUTHOR.cert)}</span>
        </div>
        <div class="hero-stats">
          <span><b>${state.index.length}</b>편</span>
          <span class="hero-sep">·</span>
          <span>${escapeHtml(span)}</span>
        </div>
      </div>
    </header>`;

  const total = state.index.length;
  const shown = Math.min(listShown, total);
  const rest = total - shown;

  const cards = state.index.slice(0, shown).map((p) => `
    <a class="card" href="#/p/${encodeURIComponent(p.slug)}">
      <div class="card-meta">
        <span class="chip">${escapeHtml(p.week || '')}</span>
        <span>${formatDate(p.date)}</span>
      </div>
      <h3 class="card-title">${escapeHtml(p.title)}</h3>
      ${p.summary ? `<p class="card-summary">${escapeHtml(p.summary)}</p>` : ''}
    </a>`).join('');

  const more = rest > 0
    ? `<button class="more" id="more-btn" type="button">이전 글 ${rest}편 더 보기</button>`
    : '';

  els.view.innerHTML = `
    ${hero}
    <div class="list-head">
      <h2>발행글</h2>
      <span class="list-count">${shown} / ${total}편</span>
    </div>
    ${cards}
    ${more}`;

  const btn = document.getElementById('more-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      listShown = total;
      renderList();
      // 펼친 자리에서 이어 보도록 방금 드러난 첫 글로 옮긴다.
      const first = els.view.querySelectorAll('.card')[shown];
      if (first) first.scrollIntoView({ block: 'start', behavior: 'smooth' });
    });
  }

  setProgress(false);
}

async function renderPost(slug) {
  const meta = state.index.find((p) => p.slug === slug);
  if (!meta) { location.hash = '#/'; return; }

  els.backBtn.hidden = false;
  document.title = `${meta.title} · 주간 채권동향`;
  els.view.innerHTML = '<div class="empty"><p>불러오는 중…</p></div>';

  let md = state.cache.get(slug);
  if (md === undefined) {
    try {
      const env = await fetchJson(`${POSTS_DIR}/${meta.file}`);
      md = await openEnvelope(state.keys, env);
      state.cache.set(slug, md);
    } catch (err) {
      els.view.innerHTML = `<div class="empty"><p>글을 불러오지 못했습니다.</p><code>${escapeHtml(err.message)}</code></div>`;
      return;
    }
  }

  els.view.innerHTML = `
    <article>
      <header class="post-head">
        <div class="card-meta">
          <span class="chip">${escapeHtml(meta.week || '')}</span>
          <span>${formatDate(meta.date)}</span>
          <span class="readtime">
            <svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2.2"/><path d="M12 7.2v5l3.2 2" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>${readingMinutes(md)}분 읽기</span>
        </div>
        <h1>${escapeHtml(meta.title)}</h1>
        <p class="byline">
          <b>${escapeHtml(AUTHOR.name)} ${escapeHtml(AUTHOR.title)}</b>
          <span>${escapeHtml(AUTHOR.org)} ${escapeHtml(AUTHOR.team)}</span>
        </p>
      </header>
      ${renderDigest(meta.digest)}
      <div class="prose">${renderMarkdown(md)}</div>
      ${renderEvents(meta.events)}
      <footer class="signoff">
        <span class="signoff-mark" aria-hidden="true">채</span>
        <div>
          <b>${escapeHtml(AUTHOR.name)} ${escapeHtml(AUTHOR.title)}</b>
          <span>${escapeHtml(AUTHOR.org)} ${escapeHtml(AUTHOR.team)} · ${escapeHtml(AUTHOR.cert)}</span>
          <span class="signoff-tel">${escapeHtml(AUTHOR.tel)}</span>
        </div>
      </footer>
    </article>`;
  els.view.focus();
  window.scrollTo(0, 0);
  setProgress(true);
  mountCharts(els.view, meta.date);
  mountEventArticles(els.view, meta.week);

  // 발행내역 상세는 이 글을 열 때만 따로 받아온다. 목록에 함께 실으면
  // 잠금해제 한 번에 글 수만큼의 상세가 통째로 딸려온다.
  if (meta.issFile) {
    let iss = state.issCache.get(slug);
    if (iss === undefined) {
      try {
        const env = await fetchJson(`${POSTS_DIR}/${meta.issFile}`);
        iss = JSON.parse(await openEnvelope(state.keys, env));
        state.issCache.set(slug, iss);
      } catch (err) {
        iss = null;
      }
    }
    // 사용자가 그 사이 다른 글로 넘어갔으면 붙이지 않는다.
    if (iss && location.hash === `#/p/${slug}`) mountSpcToggles(els.view, iss);
  }
}

function route() {
  const hash = location.hash || '#/';
  const m = hash.match(/^#\/p\/(.+)$/);
  if (m) renderPost(decodeURIComponent(m[1]));
  else renderList();
}

/* ================= 읽기 시간 ================= */

/* 표·수식은 눈으로 훑고 넘어가므로 글자 수에서 뺀다.
   한글 본문은 분당 500자 남짓 읽는다. 이 글은 숫자가 많아 조금 더 걸리지만,
   짧게 잡아 실제보다 오래 걸리는 것보다 넉넉히 잡는 편이 덜 배신당한다. */
function readingMinutes(md) {
  const text = md
    .replace(/^\|.*$/gm, '')          // 표
    .replace(/^\s*<!--[\s\S]*?-->/g, '')
    .replace(/[#>*_`[\]()]/g, '');
  const chars = text.replace(/\s+/g, '').length;
  return Math.max(1, Math.round(chars / 500));
}

/* ================= 읽기 진행바 ================= */

/* scroll 이벤트마다 레이아웃을 읽으면 스크롤이 끊긴다.
   rAF 로 한 프레임에 한 번만 계산한다. */
const progress = { on: false, ticking: false };

function onScrollFrame() {
  progress.ticking = false;
  if (!progress.on) return;
  const y = window.scrollY || document.documentElement.scrollTop || 0;
  const h = document.documentElement.scrollHeight - window.innerHeight;
  const r = h > 40 ? Math.min(1, Math.max(0, y / h)) : 0;
  els.progress.firstElementChild.style.transform = `scaleX(${r})`;
}

function onScroll() {
  if (progress.ticking) return;
  progress.ticking = true;
  requestAnimationFrame(onScrollFrame);
}

// 글과 목록을 오갈 때 처음 상태로 되돌린다.
function setProgress(isPost) {
  progress.on = isPost;
  els.progress.classList.toggle('on', isPost);
  els.progress.firstElementChild.style.transform = 'scaleX(0)';
}

/* ================= 테마 ================= */

function applyTheme(theme) {
  if (theme) document.documentElement.setAttribute('data-theme', theme);
  else document.documentElement.removeAttribute('data-theme');
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const sysDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const next = cur ? (cur === 'dark' ? 'light' : 'dark') : (sysDark ? 'light' : 'dark');
  applyTheme(next);
  localStorage.setItem(THEME_KEY, next);
}

/* ================= 잠금 해제 ================= */

function showLock(message) {
  els.app.hidden = true;
  els.lock.hidden = false;
  showSignup(false);
  els.lockError.hidden = !message;
  els.lockError.textContent = message || '';
  els.unlockBtn.disabled = false;
  els.unlockBtn.textContent = '열기';
  els.pw.value = '';
  els.pw.focus();
}

/* ================= 구독 신청 ================= */

// 잠금화면 안에서 세 장(비밀번호 / 신청서 / 접수완료) 중 하나만 보인다.
function showSignup(on, done) {
  if (!els.signupForm) return;
  els.lockForm.hidden = !!on || !!done;
  els.signupForm.hidden = !on;
  els.signupDone.hidden = !done;
  if (!on) {
    els.signupError.hidden = true;
    els.signupBtn.disabled = false;
    els.signupBtn.textContent = '신청하기';
  }
}

async function submitSignup() {
  const val = (id) => (document.getElementById(id).value || '').trim();
  const body = {
    name: val('su-name'),
    org: val('su-org'),
    segment: val('su-segment'),
    role: val('su-role'),
    email: val('su-email'),
    phone: val('su-phone'),
    note: val('su-note'),
    hp: val('su-hp'),
  };

  // Content-Type 을 text/plain 으로 둔다. application/json 으로 보내면
  // 브라우저가 사전 요청(preflight)을 먼저 보내는데 Apps Script 는 그걸
  // 처리하지 못해 요청이 통째로 막힌다. 받는 쪽에서 JSON 으로 파싱한다.
  let res;
  try {
    res = await fetch(SIGNUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify(body),
      redirect: 'follow',
    });
  } catch {
    // 네트워크 오류는 'Failed to fetch' 로 온다. 그대로 보여줄 말이 아니다.
    throw new Error('접수처에 연결하지 못했습니다. 잠시 후 다시 시도해주세요.');
  }
  if (!res.ok) throw new Error(`접수처가 응답하지 않았습니다 (${res.status}).`);

  let out;
  try {
    out = await res.json();
  } catch {
    throw new Error('접수처의 응답을 읽지 못했습니다. 잠시 후 다시 시도해주세요.');
  }
  if (!out.ok) throw new Error(out.error || '접수하지 못했습니다.');
}

async function unlock(password, persist) {
  const keys = await deriveKeys(password, state.manifest.kdf.salt, state.manifest.kdf.iterations);
  // 검증용 봉투를 먼저 열어 비밀번호가 맞는지 확인한다.
  await openEnvelope(keys, state.manifest.verify);

  state.keys = keys;

  // 작성자 정보도 암호문으로 받아온다. 실패해도 글은 읽을 수 있어야 하므로 막지 않는다.
  try {
    const authorEnv = await fetchJson(`${POSTS_DIR}/author.enc.json`);
    AUTHOR = Object.assign(AUTHOR, JSON.parse(await openEnvelope(keys, authorEnv)));
    renderFoot();
  } catch { /* 서명란이 비는 정도로 그친다 */ }

  const indexJson = await fetchJson(`${POSTS_DIR}/index.enc.json`);
  const parsed = JSON.parse(await openEnvelope(keys, indexJson));
  state.index = (Array.isArray(parsed) ? parsed.flat() : [parsed]).filter(Boolean);
  state.index.sort((a, b) => (a.date < b.date ? 1 : -1));

  (persist ? localStorage : sessionStorage).setItem(STORAGE_KEY, password);

  els.lock.hidden = true;
  els.app.hidden = false;
  route();
}

function lockUp() {
  sessionStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(STORAGE_KEY);
  state.keys = null;
  state.index = [];
  state.cache.clear();
  state.issCache.clear();
  // 잠그면 화면에 남은 개인정보도 함께 지운다.
  AUTHOR = { name: '', title: '', org: '', team: '', cert: '', tel: '' };
  renderFoot();
  location.hash = '#/';
  showLock('');
}

/* ================= 시작 ================= */

async function boot() {
  applyTheme(localStorage.getItem(THEME_KEY));

  if (!window.crypto || !crypto.subtle) {
    document.body.innerHTML =
      '<div class="empty" style="padding:80px 24px">' +
      '<p><strong>보안 컨텍스트가 아닙니다.</strong></p>' +
      '<p>파일을 직접 여는 대신 로컬 서버로 접속하세요.</p>' +
      '<code>.\\scripts\\serve.ps1</code></div>';
    return;
  }

  try {
    state.manifest = await fetchJson(`${POSTS_DIR}/manifest.json`, false);
  } catch {
    document.body.innerHTML =
      '<div class="empty" style="padding:80px 24px">' +
      '<p><strong>아직 설정되지 않았습니다.</strong></p>' +
      '<p>첫 글을 발행하면 비밀번호와 저장소가 만들어집니다.</p>' +
      '<code>.\\scripts\\publish.ps1 -Path drafts\\draft-....md</code></div>';
    return;
  }

  const saved = sessionStorage.getItem(STORAGE_KEY) || localStorage.getItem(STORAGE_KEY);
  if (saved) {
    try { await unlock(saved, !!localStorage.getItem(STORAGE_KEY)); return; }
    catch { sessionStorage.removeItem(STORAGE_KEY); localStorage.removeItem(STORAGE_KEY); }
  }
  showLock('');
}

els.lockForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = els.pw.value;
  if (!pw) return;
  els.unlockBtn.disabled = true;
  els.unlockBtn.textContent = '확인 중…';
  try {
    await unlock(pw, els.remember.checked);
  } catch (err) {
    showLock(err.message === 'AUTH_FAILED' ? '비밀번호가 맞지 않습니다.' : `열지 못했습니다: ${err.message}`);
  }
});

// 접수처가 아직 연결되지 않았으면 신청 버튼을 아예 감춘다.
// 눌렀는데 아무 일도 안 일어나는 것보다 없는 편이 낫다.
if (!SIGNUP_URL) {
  if (els.signupOpen) els.signupOpen.closest('.lock-alt').hidden = true;
} else {
  els.signupOpen.addEventListener('click', () => {
    showSignup(true);
    document.getElementById('su-name').focus();
  });
  els.signupCancel.addEventListener('click', () => showSignup(false));
  els.signupBack.addEventListener('click', () => showSignup(false));

  els.signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    els.signupError.hidden = true;
    els.signupBtn.disabled = true;
    els.signupBtn.textContent = '보내는 중…';
    try {
      await submitSignup();
      els.signupForm.reset();
      showSignup(false, true);
    } catch (err) {
      els.signupError.textContent = err.message;
      els.signupError.hidden = false;
      els.signupBtn.disabled = false;
      els.signupBtn.textContent = '신청하기';
    }
  });
}

els.themeBtn.addEventListener('click', toggleTheme);
els.lockBtn.addEventListener('click', lockUp);
els.backBtn.addEventListener('click', () => { location.hash = '#/'; });
els.brand.addEventListener('click', () => { location.hash = '#/'; });
window.addEventListener('hashchange', route);
window.addEventListener('scroll', onScroll, { passive: true });

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => { /* 오프라인 캐시는 없어도 동작 */ });
  });
}

boot();
