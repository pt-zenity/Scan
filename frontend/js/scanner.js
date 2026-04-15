/* ================================================================
   ProScan v3 — Frontend Logic
   SSE real-time streaming + Arjun / ffuf / ParamMiner / JSExtractor
   ================================================================ */

'use strict';

// ── State ────────────────────────────────────────────────────
let scanResults   = [];
let scanRunning   = false;
let scanId        = null;
let elapsedTimer  = null;
let elapsedSec    = 0;
let evtSource     = null;   // SSE EventSource
let liveFilter    = 'all';
let tableFilter   = 'all';
let liveFindings  = [];
let toolStats     = {};

const TOOLS = [
  { id:'WAF-Detect',    label:'WAF-Detect',  icon:'fas fa-wall' },
  { id:'TechDetect',    label:'TechDetect',  icon:'fas fa-microchip' },
  { id:'HeaderScan',    label:'HeaderScan',  icon:'fas fa-scroll' },
  { id:'JSExtractor',   label:'JSExtract',   icon:'fab fa-js' },
  { id:'Crawler',       label:'Crawler',     icon:'fas fa-spider' },
  { id:'ffuf',          label:'ffuf',        icon:'fas fa-sitemap' },
  { id:'Arjun',         label:'Arjun',       icon:'fas fa-search-plus' },
  { id:'ParamMiner',    label:'ParamMiner',  icon:'fas fa-radiation' },
  { id:'VulnProber',    label:'VulnProber',  icon:'fas fa-bug' },
  { id:'SensitiveFiles',label:'SensFiles',   icon:'fas fa-file-shield' },
  { id:'PortScan',      label:'PortScan',    icon:'fas fa-network-wired' },
];

// ── API check ────────────────────────────────────────────────
(async () => {
  try {
    const r = await fetch('/api/health');
    const d = await r.json();
    document.getElementById('apiStatusText').textContent = `API v${d.version}`;
  } catch {
    document.getElementById('apiStatusText').textContent = 'API Offline';
    document.querySelector('.pulse-dot').className = 'pulse-dot red';
  }
})();

// ── URL Validation ───────────────────────────────────────────
const urlInput = document.getElementById('targetUrl');
const urlValid  = document.getElementById('urlValid');
urlInput.addEventListener('input', validateUrl);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

function validateUrl() {
  const v = urlInput.value.trim();
  if (!v) { urlValid.textContent = ''; return; }
  try { new URL(v); urlValid.innerHTML = '<span style="color:var(--green)">✓</span>'; }
  catch { urlValid.innerHTML = '<span style="color:var(--red)">✗</span>'; }
}

// ── Tabs ─────────────────────────────────────────────────────
document.querySelectorAll('.t-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.t-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab)?.classList.add('active');
  });
});

// ── Sliders ──────────────────────────────────────────────────
document.getElementById('timeout').addEventListener('input', function() {
  document.getElementById('timeoutV').textContent = this.value + 's';
});
document.getElementById('threads').addEventListener('input', function() {
  document.getElementById('threadsV').textContent = this.value;
});

// ── Intensity ────────────────────────────────────────────────
document.querySelectorAll('.int-btn').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.int-btn').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
  });
});

// ── Presets ──────────────────────────────────────────────────
function applyPreset(name) {
  const all = (v) => ['optEndpoints','optArjun','optParamMiner','optJSExtract','optCrawl',
    'optVuln','optHeaders','optWaf','optTech','optPorts'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.checked = v;
  });
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v; };
  const setWL = v => document.querySelector(`input[name="wordlist"][value="${v}"]`).checked = true;
  const setInt = v => document.querySelector(`input[name="intensity"][value="${v}"]`).checked = true;
  const setThr = v => { document.getElementById('threads').value = v; document.getElementById('threadsV').textContent = v; };

  const presets = {
    recon:     () => { all(false); set('optWaf',true); set('optTech',true); set('optHeaders',true); setWL('small'); setInt('light'); setThr(3); },
    params:    () => { all(false); set('optArjun',true); set('optParamMiner',true); set('optJSExtract',true); set('optVuln',true); setWL('small'); setInt('medium'); setThr(5); },
    endpoints: () => { all(false); set('optEndpoints',true); set('optCrawl',true); set('optJSExtract',true); setWL('large'); setInt('medium'); setThr(10); },
    full:      () => { all(true); set('optPorts',false); setWL('large'); setInt('deep'); setThr(15); },
    api:       () => { all(false); set('optEndpoints',true); set('optArjun',true); set('optHeaders',true); set('optWaf',true); setWL('medium'); setInt('medium'); setThr(8);
      document.getElementById('customPaths').value = '/api\n/api/v1\n/api/v2\n/api/v3\n/api/graphql\n/api/swagger\n/openapi.json\n/api/users\n/api/admin\n/api/config'; },
    stealth:   () => { all(false); set('optEndpoints',true); set('optHeaders',true); set('optWaf',true); set('optTech',true); setWL('small'); setInt('light'); setThr(2); },
  };
  if (presets[name]) { presets[name](); showToast(`Preset "${name}" applied`, 's'); }
}

// ── Start Scan ───────────────────────────────────────────────
async function startScan() {
  const target = urlInput.value.trim();
  if (!target) { showToast('Enter a target URL', 'e'); return; }
  try { new URL(target); } catch { showToast('Invalid URL format', 'e'); return; }
  if (scanRunning) return;

  const config = {
    target,
    options: {
      endpoints:   document.getElementById('optEndpoints').checked,
      arjun:       document.getElementById('optArjun').checked,
      paramminer:  document.getElementById('optParamMiner').checked,
      js_extract:  document.getElementById('optJSExtract').checked,
      crawl:       document.getElementById('optCrawl').checked,
      vuln:        document.getElementById('optVuln').checked,
      headers:     document.getElementById('optHeaders').checked,
      waf:         document.getElementById('optWaf').checked,
      tech:        document.getElementById('optTech').checked,
      ports:       document.getElementById('optPorts').checked,
    },
    intensity: document.querySelector('input[name="intensity"]:checked').value,
    timeout:   parseInt(document.getElementById('timeout').value),
    threads:   parseInt(document.getElementById('threads').value),
    wordlist:  document.querySelector('input[name="wordlist"]:checked').value,
    custom_paths:  document.getElementById('customPaths').value.split('\n').map(s=>s.trim()).filter(Boolean),
    custom_params: document.getElementById('customParams').value.split('\n').map(s=>s.trim()).filter(Boolean),
  };

  // Reset state
  scanResults = []; liveFindings = []; toolStats = {};
  scanRunning = true; elapsedSec = 0;

  // UI reset
  resetUI();
  document.getElementById('live-section').classList.remove('hidden');
  document.getElementById('results-section').classList.remove('hidden');
  document.getElementById('report-section').classList.add('hidden');
  document.getElementById('scanBtn').classList.add('running');
  document.getElementById('scanBtn').innerHTML = '<div class="spin"></div><span>Scanning…</span>';
  document.getElementById('stopBtn').classList.remove('hidden');

  // Build tool progress pills
  buildToolPills(config.options);

  setTimeout(() => document.getElementById('live-section').scrollIntoView({ behavior:'smooth', block:'start' }), 100);

  elapsedTimer = setInterval(() => {
    elapsedSec++;
    const m = Math.floor(elapsedSec/60), s = elapsedSec%60;
    document.getElementById('elapsed').textContent = `${m}:${String(s).padStart(2,'0')}`;
  }, 1000);

  termLine(`<span class="tc">[ProScan v3]</span> Target: <span class="tg">${esc(target)}</span>`);
  termLine(`<span class="tgi">[CONFIG]</span> Tools: ${Object.entries(config.options).filter(([,v])=>v).map(([k])=>k).join(', ')}`);
  termLine(`<span class="tgi">[CONFIG]</span> Intensity: <span class="ty">${config.intensity}</span> | Threads: <span class="ty">${config.threads}</span> | Wordlist: <span class="ty">${config.wordlist}</span>`);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
    const data = await res.json();
    if (!data.scan_id) throw new Error(data.error || 'Failed to start scan');
    scanId = data.scan_id;
    termLine(`<span class="tg">[START]</span> Scan ID: <span class="tc">${scanId}</span>`);
    connectSSE(scanId);
  } catch (err) {
    termLine(`<span class="tr">[ERROR]</span> ${esc(err.message)}`);
    showToast(err.message, 'e');
    endScan('error');
  }
}

// ── SSE Stream ───────────────────────────────────────────────
function connectSSE(sid) {
  evtSource = new EventSource(`/api/scan/${sid}/events`);

  evtSource.onmessage = (e) => {
    try {
      const ev = JSON.parse(e.data);
      handleEvent(ev);
    } catch {}
  };

  evtSource.onerror = () => {
    evtSource.close();
    if (scanRunning) {
      // Fallback to polling
      pollFallback(sid);
    }
  };
}

function pollFallback(sid) {
  let lastIdx = 0;
  const iv = setInterval(async () => {
    try {
      const r = await fetch(`/api/scan/${sid}/status`);
      const d = await r.json();
      const newEvs = d.events.slice(lastIdx);
      lastIdx = d.events.length;
      newEvs.forEach(handleEvent);
      setProgress(d.progress || 0);
      document.getElementById('reqsCount').textContent = d.requests || 0;
      document.getElementById('foundCount').textContent = d.findings || 0;
      if (d.status === 'done' || d.status === 'stopped' || d.status === 'error') {
        clearInterval(iv);
        if (d.results) { scanResults = d.results; renderResults(scanResults); }
        endScan(d.status);
      }
    } catch {}
  }, 600);
}

// ── Event Handler ────────────────────────────────────────────
function handleEvent(ev) {
  switch (ev.type) {
    case 'log':
      const lvl = ev.level || 'log';
      const cls = lvl === 'error' ? 'tr' : lvl === 'warn' ? 'tw' : lvl === 'section' ? 'tp' : 'tgi';
      termLine(`<span class="${cls}">${esc(ev.message)}</span>`);
      break;
    case 'section':
      termLine(`<span class="tp tb">━━━ ${esc(ev.title)} ━━━</span>`);
      document.getElementById('activeTool').textContent = ev.title;
      break;
    case 'tool_start':
      termLine(`<span class="tc">[${esc(ev.tool)}]</span> <span class="tgi">${esc(ev.desc)}</span>`, 'section-row');
      updateToolPill(ev.tool, 'running');
      document.getElementById('activeTool').textContent = ev.tool;
      break;
    case 'tool_done':
      termLine(`<span class="tc">[${esc(ev.tool)}]</span> <span class="tg">✓ Done — ${ev.found} found, ${ev.requests} reqs</span>`);
      updateToolPill(ev.tool, 'done', ev.found);
      toolStats[ev.tool] = { found: ev.found, requests: ev.requests };
      updateToolSummary();
      break;
    case 'found':
      const row_cls = ev.severity === 'critical' ? 'crit-row' : ev.severity === 'high' ? 'high-row' : 'found-row';
      termLine(`<span class="tg">[FOUND]</span> <span class="tc">${esc(ev.url)}</span> <span class="ty">[${ev.status}]</span> <span class="tgi">// ${esc(ev.info||'')}</span>`, row_cls);
      addLiveFinding(ev);
      document.getElementById('reqsCount').textContent = parseInt(document.getElementById('reqsCount').textContent||0) + 1;
      document.getElementById('foundCount').textContent = parseInt(document.getElementById('foundCount').textContent||0) + 1;
      // Also add to results table live
      addResultRow(ev);
      break;
    case 'progress':
      setProgress(ev.value);
      break;
    case 'end':
      if (evtSource) evtSource.close();
      // Fetch final results
      fetch(`/api/scan/${scanId}/status`).then(r=>r.json()).then(d => {
        if (d.results && d.results.length > 0) {
          scanResults = d.results;
          renderResults(scanResults);
        }
        endScan('done');
      }).catch(()=>endScan('done'));
      break;
  }
}

// ── Terminal ─────────────────────────────────────────────────
function termLine(html, extraCls='') {
  const body = document.getElementById('termBody');
  const d = document.createElement('div');
  d.className = 'tl' + (extraCls ? ' '+extraCls : '');
  const t = new Date().toLocaleTimeString('en-US',{hour12:false});
  d.innerHTML = `<span class="tm">${t}</span> ${html}`;
  body.appendChild(d);
  body.scrollTop = body.scrollHeight;
}

function clearTerm() {
  document.getElementById('termBody').innerHTML =
    `<span class="term-art">██████╗ ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║
██████╔╝██████╔╝██║   ██║███████╗██║     ███████║██╔██╗██║
██╔═══╝ ██╔══██╗██║   ██║╚════██║██║     ██╔══██║██║╚████║
██║     ██║  ██║╚██████╔╝███████║╚██████╗██║  ██║██║ ╚███║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝</span>
<div class="tl"><span class="tg">[CLEAR]</span> Terminal cleared.</div>`;
}

let wrapEnabled = false;
function toggleWrap() {
  wrapEnabled = !wrapEnabled;
  document.getElementById('termBody').style.whiteSpace = wrapEnabled ? 'pre-wrap' : '';
}

// ── Progress ─────────────────────────────────────────────────
function setProgress(v) {
  v = Math.min(100, Math.max(0, v));
  document.getElementById('gProgress').style.width = v + '%';
  document.getElementById('gProgressPct').textContent = Math.round(v) + '%';
}

// ── Tool Pills ───────────────────────────────────────────────
function buildToolPills(opts) {
  const grid = document.getElementById('toolProgressGrid');
  grid.innerHTML = '';
  const optMap = {
    'WAF-Detect':'waf','TechDetect':'tech','HeaderScan':'headers',
    'JSExtractor':'js_extract','Crawler':'crawl','ffuf':'endpoints',
    'Arjun':'arjun','ParamMiner':'paramminer','VulnProber':'vuln',
    'SensitiveFiles':'endpoints','PortScan':'ports'
  };
  TOOLS.forEach(t => {
    const key = optMap[t.id] || t.id;
    if (!opts[key] && !['WAF-Detect','TechDetect','HeaderScan','SensitiveFiles'].includes(t.id)) return;
    const pill = document.createElement('div');
    pill.className = 'tp-pill';
    pill.id = 'tp-' + t.id.replace(/[^a-zA-Z0-9]/g,'_');
    pill.innerHTML = `<i class="${t.icon} tp-icon"></i><span>${t.label}</span><span class="tp-found" id="tpf-${t.id.replace(/[^a-zA-Z0-9]/g,'_')}"></span>`;
    grid.appendChild(pill);
  });
}

function updateToolPill(toolId, status, found) {
  const id = 'tp-' + toolId.replace(/[^a-zA-Z0-9]/g,'_');
  const pill = document.getElementById(id);
  if (!pill) return;
  pill.className = `tp-pill ${status}`;
  if (status === 'running') {
    pill.querySelector('i').className = 'fas fa-cog fa-spin tp-icon';
  }
  if (found !== undefined && found > 0) {
    const fEl = document.getElementById('tpf-' + toolId.replace(/[^a-zA-Z0-9]/g,'_'));
    if (fEl) fEl.textContent = '+' + found;
  }
}

function updateToolSummary() {
  const ts = toolStats;
  const ffufF = (ts['ffuf']?.found||0) + (ts['SensitiveFiles']?.found||0) + (ts['Crawler']?.found||0) + (ts['JSExtractor']?.found||0);
  const arjunF = ts['Arjun']?.found || 0;
  const pmF    = ts['ParamMiner']?.found || 0;
  const jsF    = ts['JSExtractor']?.found || 0;
  const vulnF  = ts['VulnProber']?.found || 0;
  document.getElementById('ts-ffuf').textContent = ffufF;
  document.getElementById('ts-arjun').textContent = arjunF;
  document.getElementById('ts-pm').textContent = pmF;
  document.getElementById('ts-js').textContent = jsF;
  document.getElementById('ts-vuln').textContent = vulnF;
}

// ── Live Findings Feed ────────────────────────────────────────
function addLiveFinding(ev) {
  liveFindings.push(ev);
  const feed = document.getElementById('findingsFeed');
  const empty = feed.querySelector('.feed-empty');
  if (empty) empty.remove();

  const sev = (ev.severity||'info').toLowerCase();
  if (liveFilter !== 'all' && liveFilter !== sev) return;

  const item = document.createElement('div');
  item.className = `feed-item ${sev}`;
  item.dataset.sev = sev;
  item.onclick = () => fetchAndShowDetail(ev);
  item.innerHTML = `
    <div class="fi-top">
      <span class="fi-tool">${esc(ev.tool||'?')}</span>
      <span class="fi-type">${esc(ev.type||'')}</span>
      <span class="fi-sev ${sev}">${sev}</span>
    </div>
    <div class="fi-url">${esc(ev.url||'')}</div>
    <div class="fi-info">${esc(ev.info||'')}</div>`;
  feed.insertBefore(item, feed.firstChild);
  // Limit feed to 200 items
  while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

function setLiveFilter(f, el) {
  liveFilter = f;
  document.querySelectorAll('.ff').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  // Rebuild feed
  const feed = document.getElementById('findingsFeed');
  feed.innerHTML = '';
  const filtered = liveFindings.filter(ev => f==='all' || (ev.severity||'info') === f);
  if (!filtered.length) {
    feed.innerHTML = '<div class="feed-empty"><i class="fas fa-radar"></i><p>No findings for this filter…</p></div>';
    return;
  }
  [...filtered].reverse().forEach(ev => addLiveFinding_direct(ev, feed));
}

function addLiveFinding_direct(ev, feed) {
  const sev = (ev.severity||'info').toLowerCase();
  const item = document.createElement('div');
  item.className = `feed-item ${sev}`;
  item.dataset.sev = sev;
  item.onclick = () => fetchAndShowDetail(ev);
  item.innerHTML = `
    <div class="fi-top">
      <span class="fi-tool">${esc(ev.tool||'?')}</span>
      <span class="fi-type">${esc(ev.type||'')}</span>
      <span class="fi-sev ${sev}">${sev}</span>
    </div>
    <div class="fi-url">${esc(ev.url||'')}</div>
    <div class="fi-info">${esc(ev.info||'')}</div>`;
  feed.appendChild(item);
}

// ── Results Table ─────────────────────────────────────────────
let rowCount = 0;

function addResultRow(ev) {
  const tbody = document.getElementById('rtbl-body');
  const empty = tbody.querySelector('.empty-r');
  if (empty) empty.remove();

  rowCount++;
  const sev = (ev.severity||'info').toLowerCase();
  const type = (ev.type||'endpoint').toLowerCase();
  const st = ev.status||'-';
  const stCls = String(st).startsWith('2') ? 'st-2' : String(st).startsWith('3') ? 'st-3' : String(st).startsWith('4') ? 'st-4' : String(st).startsWith('5') ? 'st-5' : '';
  const rObj = ev._result || ev; // use full result if available

  const tr = document.createElement('tr');
  tr.dataset.sev = sev;
  tr.dataset.type = type;
  tr.dataset.url = (ev.url||'').toLowerCase();
  tr.dataset.info = (ev.info||'').toLowerCase();
  tr.innerHTML = `
    <td style="color:var(--text3);font-size:11px">${rowCount}</td>
    <td><span class="tool-badge">${esc(ev.tool||'?')}</span></td>
    <td><span class="badge type-${type}">${type}</span></td>
    <td><span class="badge sev-${sev}">${sev}</span></td>
    <td><div class="url-td" title="${escAttr(ev.url||'')}">${esc(ev.url||'-')}</div></td>
    <td><span class="st ${stCls}">${esc(String(st))}</span></td>
    <td style="font-size:11px;color:var(--text3);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(ev.info||'-')}</td>
    <td>
      <button class="ibtn" onclick='openModal(${JSON.stringify(rObj)})' title="Details"><i class="fas fa-eye"></i></button>
      <button class="ibtn" onclick="copyURL('${escAttr(ev.url||'')}')" title="Copy URL"><i class="fas fa-copy"></i></button>
    </td>`;

  tbody.insertBefore(tr, tbody.firstChild);
  applyTableFilters();
  updateResultSummary();
}

function renderResults(results) {
  if (!results || !results.length) return;
  // Clear and re-render all (called at end of scan)
  rowCount = 0;
  const tbody = document.getElementById('rtbl-body');
  tbody.innerHTML = '';
  results.forEach(r => {
    rowCount++;
    const sev = (r.severity||'info').toLowerCase();
    const type = (r.type||'endpoint').toLowerCase();
    const st = r.status||'-';
    const stCls = String(st).startsWith('2')?'st-2':String(st).startsWith('3')?'st-3':String(st).startsWith('4')?'st-4':String(st).startsWith('5')?'st-5':'';
    const tr = document.createElement('tr');
    tr.dataset.sev = sev;
    tr.dataset.type = type;
    tr.dataset.url = (r.url||'').toLowerCase();
    tr.dataset.info = (r.info||'').toLowerCase();
    tr.innerHTML = `
      <td style="color:var(--text3);font-size:11px">${rowCount}</td>
      <td><span class="tool-badge">${esc(r.tool||'?')}</span></td>
      <td><span class="badge type-${type}">${type}</span></td>
      <td><span class="badge sev-${sev}">${sev}</span></td>
      <td><div class="url-td" title="${escAttr(r.url||'')}">${esc(r.url||'-')}</div></td>
      <td><span class="st ${stCls}">${esc(String(st))}</span></td>
      <td style="font-size:11px;color:var(--text3);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.info||'-')}</td>
      <td>
        <button class="ibtn" onclick='openModal(${JSON.stringify(r)})' title="Details"><i class="fas fa-eye"></i></button>
        <button class="ibtn" onclick="copyURL('${escAttr(r.url||'')}')" title="Copy"><i class="fas fa-copy"></i></button>
      </td>`;
    tbody.appendChild(tr);
  });
  updateResultSummary();
}

function updateResultSummary() {
  const rows = document.querySelectorAll('#rtbl-body tr[data-sev]');
  let c=0,h=0,m=0,l=0;
  rows.forEach(r => {
    const s = r.dataset.sev;
    if(s==='critical')c++;
    else if(s==='high')h++;
    else if(s==='medium')m++;
    else l++;
  });
  document.getElementById('sc-crit').textContent = c;
  document.getElementById('sc-high').textContent = h;
  document.getElementById('sc-med').textContent  = m;
  document.getElementById('sc-low').textContent  = l;
  document.getElementById('sc-total').textContent = c+h+m+l;
}

function tableFilter(f, el) {
  tableFilter = f;
  document.querySelectorAll('.fp').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  applyTableFilters();
}

function filterTable() { applyTableFilters(); }

function applyTableFilters() {
  const search = (document.getElementById('filterTxt')?.value||'').toLowerCase();
  const f = tableFilter || 'all';
  document.querySelectorAll('#rtbl-body tr[data-sev]').forEach(row => {
    const sevOK = f==='all'||row.dataset.sev===f||row.dataset.type===f;
    const searchOK = !search||row.dataset.url.includes(search)||row.dataset.info.includes(search);
    row.style.display = sevOK && searchOK ? '' : 'none';
  });
}

// ── Stop Scan ─────────────────────────────────────────────────
function stopScan() {
  if (scanId) fetch(`/api/scan/${scanId}`, { method:'DELETE' }).catch(()=>{});
  if (evtSource) evtSource.close();
  termLine(`<span class="ty">[STOP]</span> Scan stopped by user`);
  endScan('stopped');
}

// ── End Scan ──────────────────────────────────────────────────
function endScan(status) {
  scanRunning = false;
  clearInterval(elapsedTimer);
  if (evtSource) { evtSource.close(); evtSource = null; }
  document.getElementById('scanBtn').classList.remove('running');
  document.getElementById('scanBtn').innerHTML = '<i class="fas fa-play"></i><span>Launch</span>';
  document.getElementById('stopBtn').classList.add('hidden');
  setProgress(100);
  const msgs = {
    done:    [`Scan complete! Found <b>${document.getElementById('foundCount').textContent}</b> items in ${elapsedSec}s`, 's'],
    stopped: ['Scan stopped by user.', 'i'],
    error:   ['Scan encountered an error.', 'e'],
  };
  const [msg, type] = msgs[status] || msgs.done;
  termLine(`<span class="${type==='s'?'tg':type==='e'?'tr':'ty'}">[${status.toUpperCase()}]</span> ${msg}`);
  showToast(msg.replace(/<[^>]+>/g,''), type);
  // Mark all tool pills as done
  document.querySelectorAll('.tp-pill.running').forEach(p => p.className = p.className.replace('running','done'));
}

// ── Reset UI ──────────────────────────────────────────────────
function resetUI() {
  rowCount = 0;
  liveFindings = [];
  setProgress(0);
  document.getElementById('elapsed').textContent = '0:00';
  document.getElementById('reqsCount').textContent = '0';
  document.getElementById('foundCount').textContent = '0';
  document.getElementById('activeTool').textContent = '—';
  document.getElementById('toolProgressGrid').innerHTML = '';
  document.getElementById('rtbl-body').innerHTML = `<tr class="empty-r"><td colspan="8"><div class="empty-s"><i class="fas fa-radar"></i><p>No results yet</p></div></td></tr>`;
  document.getElementById('findingsFeed').innerHTML = `<div class="feed-empty"><i class="fas fa-radar"></i><p>Findings appear here in real-time…</p></div>`;
  ['sc-crit','sc-high','sc-med','sc-low','sc-total','ts-ffuf','ts-arjun','ts-pm','ts-js','ts-vuln'].forEach(id => {
    const el = document.getElementById(id); if(el) el.textContent = '0';
  });
}

// ── Modal ─────────────────────────────────────────────────────
function openModal(r) {
  if (typeof r === 'string') try { r = JSON.parse(r); } catch { return; }
  const sev = (r.severity||'info').toLowerCase();
  const sevCl = sev==='critical'?'r':sev==='high'?'y':sev==='medium'?'y':'g';
  document.getElementById('modalTitle').textContent = `[${(r.tool||'?')}] ${(r.type||'').toUpperCase()} — ${sev.toUpperCase()}`;
  let headersHtml = '';
  const hdrs = r.headers || {};
  if (Object.keys(hdrs).length) {
    headersHtml = `<div class="mrow" style="flex-direction:column;gap:6px"><span class="mk">Response Headers</span>
      <div class="mhdrs">${Object.entries(hdrs).map(([k,v])=>`<div class="mhrow"><span class="mhk">${esc(k)}:</span><span class="mhv">${esc(String(v))}</span></div>`).join('')}</div></div>`;
  }
  document.getElementById('modalBody').innerHTML = `
    <div class="mrow"><span class="mk">URL</span><span class="mv">${esc(r.url||'-')}</span></div>
    <div class="mrow"><span class="mk">Tool</span><span class="mv g">${esc(r.tool||'-')}</span></div>
    <div class="mrow"><span class="mk">Type</span><span class="mv">${esc(r.type||'-')}</span></div>
    <div class="mrow"><span class="mk">Severity</span><span class="mv ${sevCl}">${sev}</span></div>
    <div class="mrow"><span class="mk">Status</span><span class="mv">${esc(String(r.status||'-'))}</span></div>
    <div class="mrow"><span class="mk">Info</span><span class="mv">${esc(r.info||'-')}</span></div>
    <div class="mrow"><span class="mk">Content-Type</span><span class="mv">${esc(r.content_type||'-')}</span></div>
    <div class="mrow"><span class="mk">Size</span><span class="mv">${esc(String(r.size||'-'))}</span></div>
    <div class="mrow"><span class="mk">Response Time</span><span class="mv">${esc(String(r.rt||r.response_time||'-'))}</span></div>
    <div class="mrow"><span class="mk">Description</span><span class="mv" style="white-space:pre-wrap">${esc(r.description||'-')}</span></div>
    <div class="mrow"><span class="mk">Recommendation</span><span class="mv g" style="white-space:pre-wrap">${esc(r.recommendation||'-')}</span></div>
    ${headersHtml}`;
  document.getElementById('modalBg').classList.remove('hidden');
}

function fetchAndShowDetail(ev) {
  // Try to find full result in scanResults
  const full = scanResults.find(r => r.url === ev.url && r.severity === ev.severity && r.tool === ev.tool);
  openModal(full || ev);
}

function closeModal() { document.getElementById('modalBg').classList.add('hidden'); }

// ── Report ────────────────────────────────────────────────────
function generateReport() {
  const results = scanResults.length ? scanResults : [];
  const liveFull = liveFindings;
  const allResults = results.length ? results : liveFull;
  if (!allResults.length) { showToast('No results to report', 'i'); return; }

  const target = urlInput.value.trim();
  document.getElementById('rptMeta').innerHTML = `<span>Target: ${esc(target)}</span><span>Date: ${new Date().toLocaleString()}</span><span>Duration: ${elapsedSec}s | Requests: ${document.getElementById('reqsCount').textContent}</span>`;

  const order = ['critical','high','medium','low','info'];
  const grouped = {};
  allResults.forEach(r => {
    const s = (r.severity||'info').toLowerCase();
    if (!grouped[s]) grouped[s] = [];
    grouped[s].push(r);
  });

  let html = '';
  // Executive summary
  html += `<div class="rpt-sec"><i class="fas fa-chart-pie"></i> Executive Summary</div>`;
  html += `<div class="rpt-find">
    <div class="rpt-fhd"><span class="badge sev-info">Summary</span></div>
    <p>Target: <code>${esc(target)}</code></p>
    <p>Total findings: <strong>${allResults.length}</strong> | Scan time: <strong>${elapsedSec}s</strong></p>
    <p>
      <span style="color:var(--red)">Critical: ${(grouped.critical||[]).length}</span> &nbsp;
      <span style="color:var(--orange)">High: ${(grouped.high||[]).length}</span> &nbsp;
      <span style="color:var(--yellow)">Medium: ${(grouped.medium||[]).length}</span> &nbsp;
      <span style="color:var(--blue)">Low/Info: ${((grouped.low||[]).length+(grouped.info||[]).length)}</span>
    </p>
  </div>`;

  const sevIcons = { critical:'skull-crossbones', high:'triangle-exclamation', medium:'circle-exclamation', low:'circle-info', info:'circle-info' };
  order.forEach(sev => {
    const items = grouped[sev] || [];
    if (!items.length) return;
    html += `<div class="rpt-sec"><i class="fas fa-${sevIcons[sev]}"></i> ${sev.toUpperCase()} (${items.length})</div>`;
    items.forEach((r,i) => {
      html += `<div class="rpt-find">
        <div class="rpt-fhd">
          <span class="badge sev-${sev}">${sev}</span>
          <span class="badge type-${(r.type||'').toLowerCase()}">${r.type||'?'}</span>
          <span class="tool-badge">${r.tool||'?'}</span>
          <span style="font-size:11px;color:var(--text3)">#${i+1}</span>
        </div>
        <p><strong>URL:</strong> <code>${esc(r.url||'-')}</code></p>
        <p><strong>Status:</strong> ${esc(String(r.status||'-'))} | <strong>Info:</strong> ${esc(r.info||'-')}</p>
        ${r.description?`<p><strong>Description:</strong> ${esc(r.description)}</p>`:''}
        ${r.recommendation?`<p><strong>Recommendation:</strong> <span style="color:var(--green)">${esc(r.recommendation)}</span></p>`:''}
      </div>`;
    });
  });

  document.getElementById('rptBody').innerHTML = html;
  document.getElementById('report-section').classList.remove('hidden');
  document.getElementById('report-section').scrollIntoView({ behavior:'smooth' });
  showToast('Report generated!', 's');
}

// ── Export ────────────────────────────────────────────────────
function exportResults(fmt) {
  const data = scanResults.length ? scanResults : liveFindings;
  if (!data.length) { showToast('No results to export', 'i'); return; }
  const target = urlInput.value.trim();

  if (fmt === 'json') {
    dl('proscan_results.json', JSON.stringify({ target, date: new Date().toISOString(), total: data.length, results: data }, null, 2), 'application/json');
  } else if (fmt === 'csv') {
    const hdr = 'Tool,Type,Severity,URL,Status,Info,Description,Recommendation\n';
    const rows = data.map(r => [r.tool,r.type,r.severity,r.url,r.status,r.info,r.description,r.recommendation]
      .map(v=>`"${String(v||'').replace(/"/g,'""')}"`).join(','));
    dl('proscan_results.csv', hdr + rows.join('\n'), 'text/csv');
  } else {
    const lines = ['ProScan v3 Security Report','='.repeat(60),`Target: ${target}`,`Date: ${new Date().toLocaleString()}`,`Total: ${data.length}`,'',
      ...data.map(r=>`[${(r.severity||'info').toUpperCase()}][${r.type}][${r.tool}] ${r.url} (${r.status}) — ${r.info}`)];
    dl('proscan_results.txt', lines.join('\n'), 'text/plain');
  }
  showToast(`Exported as ${fmt.toUpperCase()}`, 's');
}

function dl(name, content, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content],{type}));
  a.download = name; a.click();
}

// ── Toast ──────────────────────────────────────────────────────
function showToast(msg, type='i') {
  const icons = { s:'circle-check', e:'circle-xmark', i:'circle-info' };
  const tc = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<i class="fas fa-${icons[type]||'circle-info'}"></i>${esc(msg)}`;
  tc.appendChild(t);
  setTimeout(()=>t.classList.add('show'),10);
  setTimeout(()=>{t.classList.remove('show');setTimeout(()=>t.remove(),300)},3500);
}

// ── Utility ────────────────────────────────────────────────────
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') }
function escAttr(s){ return String(s||'').replace(/'/g,"\\'").replace(/"/g,'\\"') }
function copyURL(url) {
  navigator.clipboard?.writeText(url).then(()=>showToast('Copied!','s')).catch(()=>{
    const t=document.createElement('textarea'); t.value=url;
    document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove();
    showToast('Copied!','s');
  });
}
