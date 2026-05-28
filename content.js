// ═══════════════════════════════════════════════════════════════
// SentinelDLP v3 — TeamT5 Internal
// Pure rule-based paste sanitizer. No external deps. No ML load.
// ═══════════════════════════════════════════════════════════════

// ── i18n ──────────────────────────────────────────────────────
const LANG = (navigator.language || 'zh').toLowerCase().startsWith('zh') ? 'zh' : 'en';
const T = {
  zh: {
    title:          'SentinelDLP',
    subtitle:       (n) => `偵測到 ${n} 種敏感資料`,
    section_rule:   '偵測到的類型',
    section_clean:  '🛡 消毒後版本（可直接複製貼出）',
    btn_copy:       '📋 複製消毒版',
    btn_paste:      '繼續貼上原始內容',
    btn_suppress:   '此站不再提示',
    copied:         '✓ 已複製！',
    powered:        'by Kerr · github.com/kerr20801',
    item_found:     (n) => `${n} 處`
  },
  en: {
    title:          'SentinelDLP',
    subtitle:       (n) => `${n} sensitive data type(s) detected`,
    section_rule:   'Detected types',
    section_clean:  '🛡 Sanitized version (safe to paste)',
    btn_copy:       '📋 Copy sanitized',
    btn_paste:      'Paste original',
    btn_suppress:   "Don't show on this site",
    copied:         '✓ Copied!',
    powered:        'by Kerr · github.com/kerr20801',
    item_found:     (n) => `${n} found`
  }
}[LANG];

// ── MD5 (same as sanitize.html — token format compatible) ──────
function md5(str) {
  function safeAdd(x,y){const l=(x&0xffff)+(y&0xffff);return((x>>16)+(y>>16)+(l>>16)<<16)|(l&0xffff);}
  function rol(n,c){return(n<<c)|(n>>>(32-c));}
  function cmn(q,a,b,x,s,t){return safeAdd(rol(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
  function ff(a,b,c,d,x,s,t){return cmn((b&c)|(~b&d),a,b,x,s,t);}
  function gg(a,b,c,d,x,s,t){return cmn((b&d)|(c&~d),a,b,x,s,t);}
  function hh(a,b,c,d,x,s,t){return cmn(b^c^d,a,b,x,s,t);}
  function ii(a,b,c,d,x,s,t){return cmn(c^(b|~d),a,b,x,s,t);}
  const b=unescape(encodeURIComponent(str)),m=[];
  for(let i=0;i<b.length;i++)m[i>>2]=(m[i>>2]||0)|(b.charCodeAt(i)<<((i%4)*8));
  const L=b.length;m[L>>2]|=0x80<<((L%4)*8);m[(((L+8)>>6)<<4)+14]=L*8;
  let a=1732584193,bc=-271733879,c=-1732584194,d=271733878;
  for(let i=0;i<m.length;i+=16){
    const[oa,ob,oc,od]=[a,bc,c,d];
    a=ff(a,bc,c,d,m[i],7,-680876936);d=ff(d,a,bc,c,m[i+1],12,-389564586);c=ff(c,d,a,bc,m[i+2],17,606105819);bc=ff(bc,c,d,a,m[i+3],22,-1044525330);
    a=ff(a,bc,c,d,m[i+4],7,-176418897);d=ff(d,a,bc,c,m[i+5],12,1200080426);c=ff(c,d,a,bc,m[i+6],17,-1473231341);bc=ff(bc,c,d,a,m[i+7],22,-45705983);
    a=ff(a,bc,c,d,m[i+8],7,1770035416);d=ff(d,a,bc,c,m[i+9],12,-1958414417);c=ff(c,d,a,bc,m[i+10],17,-42063);bc=ff(bc,c,d,a,m[i+11],22,-1990404162);
    a=ff(a,bc,c,d,m[i+12],7,1804603682);d=ff(d,a,bc,c,m[i+13],12,-40341101);c=ff(c,d,a,bc,m[i+14],17,-1502002290);bc=ff(bc,c,d,a,m[i+15],22,1236535329);
    a=gg(a,bc,c,d,m[i+1],5,-165796510);d=gg(d,a,bc,c,m[i+6],9,-1069501632);c=gg(c,d,a,bc,m[i+11],14,643717713);bc=gg(bc,c,d,a,m[i],20,-373897302);
    a=gg(a,bc,c,d,m[i+5],5,-701558691);d=gg(d,a,bc,c,m[i+10],9,38016083);c=gg(c,d,a,bc,m[i+15],14,-660478335);bc=gg(bc,c,d,a,m[i+4],20,-405537848);
    a=gg(a,bc,c,d,m[i+9],5,568446438);d=gg(d,a,bc,c,m[i+14],9,-1019803690);c=gg(c,d,a,bc,m[i+3],14,-187363961);bc=gg(bc,c,d,a,m[i+8],20,1163531501);
    a=gg(a,bc,c,d,m[i+13],5,-1444681467);d=gg(d,a,bc,c,m[i+2],9,-51403784);c=gg(c,d,a,bc,m[i+7],14,1735328473);bc=gg(bc,c,d,a,m[i+12],20,-1926607734);
    a=hh(a,bc,c,d,m[i+5],4,-378558);d=hh(d,a,bc,c,m[i+8],11,-2022574463);c=hh(c,d,a,bc,m[i+11],16,1839030562);bc=hh(bc,c,d,a,m[i+14],23,-35309556);
    a=hh(a,bc,c,d,m[i+1],4,-1530992060);d=hh(d,a,bc,c,m[i+4],11,1272893353);c=hh(c,d,a,bc,m[i+7],16,-155497632);bc=hh(bc,c,d,a,m[i+10],23,-1094730640);
    a=hh(a,bc,c,d,m[i+13],4,681279174);d=hh(d,a,bc,c,m[i],11,-358537222);c=hh(c,d,a,bc,m[i+3],16,-722521979);bc=hh(bc,c,d,a,m[i+6],23,76029189);
    a=hh(a,bc,c,d,m[i+9],4,-640364487);d=hh(d,a,bc,c,m[i+12],11,-421815835);c=hh(c,d,a,bc,m[i+15],16,530742520);bc=hh(bc,c,d,a,m[i+2],23,-995338651);
    a=ii(a,bc,c,d,m[i],6,-198630844);d=ii(d,a,bc,c,m[i+7],10,1126891415);c=ii(c,d,a,bc,m[i+14],15,-1416354905);bc=ii(bc,c,d,a,m[i+5],21,-57434055);
    a=ii(a,bc,c,d,m[i+12],6,1700485571);d=ii(d,a,bc,c,m[i+3],10,-1894986606);c=ii(c,d,a,bc,m[i+10],15,-1051523);bc=ii(bc,c,d,a,m[i+1],21,-2054922799);
    a=ii(a,bc,c,d,m[i+8],6,1873313359);d=ii(d,a,bc,c,m[i+15],10,-30611744);c=ii(c,d,a,bc,m[i+6],15,-1560198380);bc=ii(bc,c,d,a,m[i+13],21,1309151649);
    a=ii(a,bc,c,d,m[i+4],6,-145523070);d=ii(d,a,bc,c,m[i+11],10,-1120210379);c=ii(c,d,a,bc,m[i+2],15,718787259);bc=ii(bc,c,d,a,m[i+9],21,-343485551);
    a=safeAdd(a,oa);bc=safeAdd(bc,ob);c=safeAdd(c,oc);d=safeAdd(d,od);
  }
  return[a,bc,c,d].map(v=>(v<0?v+0x100000000:v).toString(16).padStart(8,'0').match(/../g).map(b=>b[1]+b[0]).join('')).join('').slice(0,6);
}
function makeToken(tag, val) { return `[[${tag}_${md5(val)}]]`; }

// ── Rules (改為靜態宣告以優化效能) ─────────────────────────────────
const RULES = [
  { tag:'SSH_TARGET', type:'SSH user@host', icon:'🖥', re: /\b[a-z_][a-z0-9_-]{0,30}@(\d{1,3}\.){3}\d{1,3}\b/gi },
  { tag:'SSH_TARGET', type:'SSH user@host', icon:'🖥', re: /\b[a-z_][a-z0-9_-]{0,30}@[a-z0-9][a-z0-9-.]{2,60}\.[a-z]{2,}\b/gi },
  { tag:'LINUX_PATH', type:'Linux path', icon:'📁', re: /\/home\/[a-zA-Z0-9_.-]+(?:\/[^\s"';<>|&,)\]]*)?/g },
  { tag:'LINUX_PATH', type:'Linux path', icon:'📁', re: /\/etc\/(?:ssl|nginx|apache2|ssh|pki|certs?)[^\s"';<>|&,)\]]*/g },
  { tag:'LINUX_PATH', type:'Linux path', icon:'📁', re: /\/var\/(?:www|log|run|lib)\/[^\s"';<>|&,)\]]*/g },
  { tag:'LINUX_PATH', type:'Linux path', icon:'📁', re: /\/opt\/[a-zA-Z0-9_.-]+(?:\/[^\s"';<>|&,)\]]*)?/g },
  { tag:'LINUX_PATH', type:'Linux path', icon:'📁', re: /\/root\/[^\s"';<>|&,)\]]*/g },
  { tag:'PRIVATE_IP', type:'Private IP', icon:'🌐', re: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
  { tag:'PRIVATE_IP', type:'Private IP', icon:'🌐', re: /\b192\.168\.\d{1,3}\.\d{1,3}\b/g },
  { tag:'PRIVATE_IP', type:'Private IP', icon:'🌐', re: /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g },
  { tag:'GITHUB_PAT', type:'GitHub/GitLab Token', icon:'🔑', re: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|glpat-[A-Za-z0-9_-]{20,}/g },
  { tag:'AWS_KEY', type:'AWS Access Key', icon:'☁️', re: /AKIA[0-9A-Z]{16}/g },
  { tag:'JWT', type:'JWT Token', icon:'🎫', re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { tag:'TG_TOKEN', type:'Telegram Token', icon:'📱', re: /\b\d{8,12}:[A-Za-z0-9_-]{35}\b/g },
  { tag:'CONN_STR', type:'Connection String', icon:'🗄️', re: /(?:mongodb|postgres|mysql|redis|mssql):\/\/[^\s"']+/gi },
  { tag:'PRIV_KEY', type:'Private Key', icon:'🔐', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { tag:'FORTI_ENC', type:'FortiGate ENC', icon:'🔒', re: /ENC\s+[A-Za-z0-9+/=]{20,}/g },
  { tag:'PSK', type:'PSK / Preshared Key', icon:'🔒', re: /(?:preshared-key|pre-shared-key|psk)\s*["']?([^\s"';<>{]+)["']?/gi },
  // Credit Cards — Visa / Mastercard / Amex / UnionPay / JCB
  { tag:'CC_NUM', type:'Credit Card', icon:'💳', re: /\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}\b/g },
  { tag:'CC_NUM', type:'Credit Card', icon:'💳', re: /\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b/g },
  { tag:'CC_NUM', type:'Credit Card', icon:'💳', re: /\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b/g },
  { tag:'CC_NUM', type:'Credit Card', icon:'💳', re: /\b62[0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4,7}\b/g },
  { tag:'CC_NUM', type:'Credit Card', icon:'💳', re: /\b35(?:2[89]|[3-8][0-9])[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b/g },
  // IBAN — 2 letter country code + 2 digits + up to 30 alphanum
  { tag:'IBAN', type:'IBAN', icon:'🏦', re: /\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b/g },
  // SWIFT / BIC — only when preceded by swift/bic/routing keyword
  { tag:'SWIFT', type:'SWIFT / BIC', icon:'🏦', re: /(?:swift|bic|routing)[：:\s]+([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi },
  // Taiwan bank account — only when preceded by 帳號/account keyword
  { tag:'BANK_ACCT', type:'Bank Account', icon:'🏦', re: /(?:帳號|帳户|戶號|account\s*(?:no|number|#)?)[：:\s]*(\d{10,14})/gi },
  { tag:'TW_PHONE', type:'TW Phone', icon:'📞', re: /(?<![,.\d])(?:\+886[-\s]?9|09)\d{2}[-\s]?\d{3}[-\s]?\d{3}(?!\d)/g },
  { tag:'TW_PHONE', type:'TW Phone', icon:'📞', re: /(?<![,.\d])(?:\+886[-\s]?[2-8]|0[2-8])[-\s]?\d{4}[-\s]?\d{4}(?!\d)/g },
  { tag:'EMAIL', type:'Email Address', icon:'📧', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  { tag:'EXT_DOMAIN', type:'Domain', icon:'🌐', re: /(?:^|[\s=:"'(,])([a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.(?:org|net|io|co|tw|com\.tw|edu|gov|biz|info|me|app|dev|cloud|internal|corp|lan|local))\b/gi },
  { tag:'HEURISTIC', type:'Password/Secret field', icon:'🔑', re: /(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key)\s*[=:]\s*["']?([A-Za-z0-9+/\-_]{8,})["']?/gi },
];

const SAFE_VALS = new Set(['true','false','none','null','undefined','placeholder','changeme','xxx','redacted','your_token_here','<password>']);

// ── Core sanitize (修正捕獲組替換邏輯) ─────────────────────────────────
function sanitize(text) {
  let out = text;
  const findings = {};  
  const mapping  = {};

  for (const rule of RULES) {
    out = out.replace(rule.re, (match, p1) => {
      // 針對 Heuristic 與 PSK：精確使用捕獲組 p1 取代原本的 match.match 探測
      if (rule.tag === 'HEURISTIC' || rule.tag === 'PSK' || rule.tag === 'BANK_ACCT' || rule.tag === 'SWIFT') {
        if (!p1 || SAFE_VALS.has(p1.toLowerCase())) return match;
        const tok = makeToken(rule.tag, p1);
        mapping[tok] = p1;
        findings[rule.type] = (findings[rule.type] || 0) + 1;
        return match.replace(p1, tok);
      }
      // 針對 Domain 規則：避免包含前方匹配的符號
      if (rule.tag === 'EXT_DOMAIN') {
        if (!p1) return match;
        const tok = makeToken(rule.tag, p1);
        mapping[tok] = p1;
        findings[rule.type] = (findings[rule.type] || 0) + 1;
        return match.replace(p1, tok);
      }
      const tok = makeToken(rule.tag, match);
      mapping[tok] = match;
      findings[rule.type] = (findings[rule.type] || 0) + 1;
      return tok;
    });
  }

  return { sanitized: out, findings, mapping };
}

// ── Settings state ────────────────────────────────────────────
let _enabled = true;
let _suppressed = [];

chrome.storage.sync.get(['enabled', 'suppressed'], data => {
  if (data.enabled !== undefined) _enabled = data.enabled;
  if (data.suppressed) _suppressed = data.suppressed;
});

// 改用 storage.onChanged 替代監聽跨分頁 runtime 訊息，避免背景分頁群發噴錯
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync') {
    if (changes.enabled !== undefined) _enabled = changes.enabled.newValue;
    if (changes.suppressed !== undefined) _suppressed = changes.suppressed.newValue;
  }
});

// ── Overlay ───────────────────────────────────────────────────
let _overlayEl = null;

function removeOverlay() {
  if (_overlayEl) { _overlayEl.remove(); _overlayEl = null; }
}

function showOverlay(originalText, findings, sanitizedText) {
  removeOverlay();

  const typeList = Object.entries(findings);
  if (typeList.length === 0) return;

  const iconMap = {};
  RULES.forEach(r => { iconMap[r.type] = r.icon; });

  const overlay = document.createElement('div');
  overlay.id = '__sentinel_overlay__';

  overlay.style.cssText = [
    'position:fixed', 'top:16px', 'right:16px', 'z-index:2147483647',
    'width:340px', 'max-height:82vh', 'overflow-y:auto',
    'background:#0f1117', 'border:1.5px solid #ef4444',
    'border-radius:12px',
    'box-shadow:0 8px 40px rgba(239,68,68,.22),0 2px 12px rgba(0,0,0,.4)',
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang TC",sans-serif',
    'font-size:13px', 'color:#e0e0e0', 'line-height:1.5',
  ].join(';');

  const hdr = document.createElement('div');
  hdr.style.cssText = 'padding:13px 15px 10px;border-bottom:1px solid #1f2937;display:flex;align-items:center;justify-content:space-between;gap:8px';
  hdr.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:0">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <rect width="24" height="24" rx="5" fill="#ef4444"/>
        <path d="M7 4h10v2H7V4zm0 3h10v2H7V7zm0 3h6v2H7v-2z" fill="white"/>
        <path d="M5 14l7 6 7-6" stroke="white" stroke-width="2" fill="none"/>
      </svg>
      <div style="min-width:0">
        <div style="font-weight:700;font-size:14px;color:#ef4444">${T.title}</div>
        <div style="font-size:11px;color:#9ca3af;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${T.subtitle(typeList.length)}</div>
      </div>
    </div>
    <button id="__s_close__" style="background:none;border:none;color:#6b7280;cursor:pointer;font-size:17px;padding:0 4px;flex-shrink:0;line-height:1">✕</button>`;
  overlay.appendChild(hdr);

  const body = document.createElement('div');
  body.style.cssText = 'padding:10px 15px 6px';

  const secLabel = document.createElement('div');
  secLabel.style.cssText = 'font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px';
  secLabel.textContent = T.section_rule;
  body.appendChild(secLabel);

  typeList.forEach(([type, count]) => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #1a1d2e';
    row.innerHTML = `
      <span style="font-size:15px">${iconMap[type] || '⚠️'}</span>
      <span style="flex:1;font-size:12px;font-weight:600">${type}</span>
      <span style="font-size:10px;background:#3f0a0a;color:#fca5a5;padding:2px 8px;border-radius:10px;font-weight:700">${T.item_found(count)}</span>`;
    body.appendChild(row);
  });

  overlay.appendChild(body);

  const cleanWrap = document.createElement('div');
  cleanWrap.style.cssText = 'padding:8px 15px 10px;border-top:1px solid #1f2937';

  const cleanLabel = document.createElement('div');
  cleanLabel.style.cssText = 'font-size:10px;color:#86efac;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px';
  cleanLabel.textContent = T.section_clean;
  cleanWrap.appendChild(cleanLabel);

  const cleanBox = document.createElement('div');
  cleanBox.style.cssText = [
    'background:#0a1a10', 'border:1px solid #166534', 'border-radius:6px',
    'padding:9px 11px', 'font-family:Consolas,"Courier New",monospace',
    'font-size:11px', 'line-height:1.6', 'max-height:140px', 'overflow-y:auto',
    'white-space:pre-wrap', 'word-break:break-all', 'color:#86efac',
  ].join(';');
  cleanBox.textContent = sanitizedText;
  cleanWrap.appendChild(cleanBox);

  overlay.appendChild(cleanWrap);

  const btnWrap = document.createElement('div');
  btnWrap.style.cssText = 'padding:8px 15px 13px;display:flex;gap:7px;flex-wrap:wrap';

  const copyBtn = document.createElement('button');
  copyBtn.id = '__s_copy__';
  copyBtn.style.cssText = [
    'flex:1', 'background:#166534', 'border:none', 'color:#86efac',
    'padding:8px 10px', 'border-radius:7px', 'cursor:pointer',
    'font-size:12px', 'font-weight:700', 'font-family:inherit',
  ].join(';');
  copyBtn.textContent = T.btn_copy;
  btnWrap.appendChild(copyBtn);

  const pasteBtn = document.createElement('button');
  pasteBtn.id = '__s_continue__';
  pasteBtn.style.cssText = [
    'background:#1f2937', 'border:1px solid #374151', 'color:#9ca3af',
    'padding:8px 10px', 'border-radius:7px', 'cursor:pointer',
    'font-size:12px', 'font-family:inherit',
  ].join(';');
  pasteBtn.textContent = T.btn_paste;
  btnWrap.appendChild(pasteBtn);

  const suppressBtn = document.createElement('button');
  suppressBtn.id = '__s_suppress__';
  suppressBtn.style.cssText = [
    'width:100%', 'background:none', 'border:1px solid #1f2937',
    'color:#4b5563', 'padding:5px', 'border-radius:6px',
    'cursor:pointer', 'font-size:11px', 'font-family:inherit',
  ].join(';');
  suppressBtn.textContent = T.btn_suppress;
  btnWrap.appendChild(suppressBtn);

  overlay.appendChild(btnWrap);

  const foot = document.createElement('div');
  foot.style.cssText = 'padding:0 15px 10px;font-size:10px;color:#374151;text-align:right';
  foot.textContent = T.powered;
  overlay.appendChild(foot);

  document.body.appendChild(overlay);
  _overlayEl = overlay;

  document.getElementById('__s_close__').onclick    = removeOverlay;
  document.getElementById('__s_continue__').onclick = removeOverlay;

  document.getElementById('__s_copy__').onclick = () => {
    navigator.clipboard.writeText(sanitizedText).then(() => {
      const btn = document.getElementById('__s_copy__');
      if (btn) { btn.textContent = T.copied; btn.style.background = '#14532d'; }
      setTimeout(removeOverlay, 1200);
    }).catch(() => {
      const range = document.createRange();
      range.selectNodeContents(cleanBox);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    });
  };

  document.getElementById('__s_suppress__').onclick = () => {
    _suppressed = [...(_suppressed || []), location.hostname];
    chrome.storage.sync.set({ suppressed: _suppressed });
    removeOverlay();
  };

  setTimeout(removeOverlay, 20000);
}

// ── Paste listener ────────────────────────────────────────────
document.addEventListener('paste', (e) => {
  if (!_enabled) return;
  if ((_suppressed || []).includes(location.hostname)) return;

  const text = e.clipboardData?.getData('text/plain') || '';
  if (!text || text.length < 8) return;

  const { sanitized, findings } = sanitize(text);
  const count = Object.keys(findings).length;
  if (count === 0) return;

  chrome.runtime.sendMessage({
    type: 'finding',
    host: location.hostname,
    count,
    ts: Date.now(),
  }).catch(() => {});

  showOverlay(text, findings, sanitized);
}, true);
