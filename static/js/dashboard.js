// ═══════════════════════════════════════════════════════
//  WEBGUARD — dashboard.js
//  Single source of truth: all scan data lives in WG.state
// ═══════════════════════════════════════════════════════

const WG = {

  /* ── STATE ───────────────────────────────────────── */
  state: {
    scans: [],          // every completed or in-progress scan
    activeScanId: null, // scan currently running
  },

  /* ── VULNERABILITY TEMPLATES (simulated engine) ──── */
  vulnTemplates: [
    { id:'sqli',  name:'SQL Injection',              owasp:'A03:2021', severity:'critical', desc:'User-supplied input is passed unsanitised into SQL queries, allowing database extraction.' },
    { id:'rxss',  name:'Reflected XSS',              owasp:'A03:2021', severity:'high',     desc:'Unsanitised query parameters are reflected in the page, enabling script injection.' },
    { id:'sxss',  name:'Stored XSS',                 owasp:'A03:2021', severity:'high',     desc:'Malicious scripts stored in the database are served to all subsequent visitors.' },
    { id:'bac',   name:'Broken Access Control',      owasp:'A01:2021', severity:'high',     desc:'Authenticated users can access resources or perform actions outside their privilege level.' },
    { id:'idor',  name:'Insecure Direct Object Ref', owasp:'A01:2021', severity:'high',     desc:'Object identifiers in URLs allow unauthorised access to other users\' data.' },
    { id:'csrf',  name:'Missing CSRF Protection',    owasp:'A01:2021', severity:'medium',   desc:'State-changing requests lack tokens, enabling cross-site request forgery.' },
    { id:'auth',  name:'Weak Authentication',        owasp:'A07:2021', severity:'high',     desc:'No account lockout or MFA. Brute-force attacks are feasible.' },
    { id:'csp',   name:'Missing CSP Header',         owasp:'A05:2021', severity:'medium',   desc:'Content-Security-Policy header absent, increasing XSS exploit surface.' },
    { id:'hsts',  name:'Missing HSTS Header',        owasp:'A02:2021', severity:'medium',   desc:'HTTP Strict-Transport-Security not set; downgrade attacks possible.' },
    { id:'sdata', name:'Sensitive Data Exposure',    owasp:'A02:2021', severity:'high',     desc:'PII or credentials visible in HTTP responses or client-side source.' },
    { id:'xxe',   name:'XML External Entity (XXE)',  owasp:'A05:2021', severity:'critical', desc:'XML parser processes external entity references, exposing server files.' },
    { id:'cfg',   name:'Security Misconfiguration',  owasp:'A05:2021', severity:'medium',   desc:'Default credentials or debug endpoints left enabled in production.' },
    { id:'comp',  name:'Vulnerable Component',       owasp:'A06:2021', severity:'medium',   desc:'Outdated library version with known public CVE detected.' },
    { id:'log',   name:'Insufficient Logging',       owasp:'A09:2021', severity:'low',      desc:'Failed login attempts and privilege escalations are not logged.' },
    { id:'ssrf',  name:'Server-Side Request Forgery',owasp:'A10:2021', severity:'critical', desc:'Server fetches attacker-controlled URLs, enabling internal network access.' },
  ],

  /* ── SIMULATE A SCAN RESULT ─────────────────────── */
  simulateScan(url, depth) {
    const counts = { quick: [2,5], standard: [4,9], deep: [7,14] }[depth] || [4,9];
    const n = counts[0] + Math.floor(Math.random() * (counts[1] - counts[0] + 1));
    const shuffled = [...this.vulnTemplates].sort(() => Math.random() - .5);
    const picked = shuffled.slice(0, n);

    const vulns = picked.map((t, i) => ({
      vid: 'V-' + String(i + 1).padStart(3,'0'),
      ...t,
      location: this._fakeEndpoint(url),
      status: 'open',
    }));

    const sevScore = { critical:25, high:15, medium:8, low:3 };
    const penalty = vulns.reduce((sum, v) => sum + (sevScore[v.severity] || 0), 0);
    const score = Math.max(10, Math.min(100, 100 - Math.round(penalty * .6)));

    return { vulns, score };
  },

  _fakeEndpoint(base) {
    const paths = ['/login','/search','/profile','/admin','/api/user','/register','/upload','/reset-password','/dashboard','/api/data'];
    return base.replace(/\/$/, '') + paths[Math.floor(Math.random() * paths.length)];
  },

  /* ── ADD A COMPLETED SCAN ───────────────────────── */
  addScan(url, depth, appType) {
    const { vulns, score } = this.simulateScan(url, depth);
    const critCount = vulns.filter(v => v.severity === 'critical').length;
    const scan = {
      id: 'scan-' + Date.now(),
      url,
      depth,
      appType: appType || 'Web App',
      score,
      vulns,
      criticalCount: critCount,
      date: new Date().toLocaleString('en-GB', { day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }),
      status: 'completed',
    };
    this.state.scans.unshift(scan);
    this._persistState();
    return scan;
  },

  /* ── COMPUTED TOTALS ────────────────────────────── */
  totals() {
    const scans = this.state.scans.filter(s => s.status === 'completed');
    const allVulns = scans.flatMap(s => s.vulns);
    const avgScore = scans.length ? Math.round(scans.reduce((a,s) => a + s.score, 0) / scans.length) : 0;
    return {
      appsScanned: scans.length,
      vulnsFound:  allVulns.length,
      critIssues:  allVulns.filter(v => v.severity === 'critical').length,
      avgScore,
    };
  },

  /* ── REAL SCAN (Django backend) ─────────────────── */
  async runRealScan(url, depth, appType) {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

    const startResp = await fetch('/scanner/start/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken,
      },
      body: JSON.stringify({ url: url, target_type: appType || 'other' }),
    });

    if (!startResp.ok) throw new Error('Scan could not be started');
    const startData = await startResp.json();

    const resultsResp = await fetch(`/scanner/results/${startData.scan_id}/`);
    if (!resultsResp.ok) throw new Error('Could not fetch scan results');
    const results = await resultsResp.json();

    // Map Django's field names to the shape your dashboard already expects
    const vulns = results.vulnerabilities.map((v, i) => ({
      vid: 'V-' + String(i + 1).padStart(3, '0'),
      name: v.name,
      owasp: v.owasp,
      severity: v.severity,
      desc: v.description,
      location: v.url,
      status: v.status || 'open',
    }));

    const critCount = vulns.filter(v => v.severity === 'critical').length;
    const scan = {
      id: 'scan-' + startData.scan_id,
      url: results.url,
      depth,
      appType: appType || 'Web App',
      score: results.score,
      vulns,
      criticalCount: critCount,
      date: new Date().toLocaleString('en-GB', { day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }),
      status: 'completed',
    };
    this.state.scans.unshift(scan);
    this._persistState();
    return scan;
  },

  /* ── PERSIST / LOAD ─────────────────────────────── */
  _persistState() {
    try { sessionStorage.setItem('wg_state', JSON.stringify(this.state)); } catch(e) {}
  },
  _loadState() {
    try {
      const s = sessionStorage.getItem('wg_state');
      if (s) this.state = JSON.parse(s);
    } catch(e) {}
  },
};

// ═══════════════════════════════════════════════════════
//  UI CONTROLLER
// ═══════════════════════════════════════════════════════

/* ── PAGE NAVIGATION ── */
function showPage(name) {
  document.querySelectorAll('.page-content').forEach(p => p.classList.add('hidden'));
  const target = document.getElementById('page-' + name);
  if (target) target.classList.remove('hidden');

  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.classList.toggle('active', item.dataset.page === name);
  });

  const titles = { dashboard:'Dashboard', scan:'New Scan', history:'Scan History',
    reports:'Reports', vulnerabilities:'Vulnerabilities', targets:'Targets',
    owasp:'OWASP Top 10', settings:'Settings' };
  document.getElementById('pageTitle').textContent = titles[name] || name;

  if (window.innerWidth <= 850) document.getElementById('sidebar').classList.remove('open');

  // Refresh data pages
  if (name === 'dashboard')       renderDashboard();
  if (name === 'history')         renderHistory();
  if (name === 'reports')         renderReports();
  if (name === 'vulnerabilities') renderVulnerabilities();
  if (name === 'targets')         renderTargets();
  if (name === 'owasp')           renderOWASP();
}

async function loadAdminRiskSummary() {
  const container = document.getElementById('adminRiskSummary');
  if (!container) return;

  try {
    const resp = await fetch('/scanner/org-summary/');
    const data = await resp.json();

    if (!data.has_data) {
      container.innerHTML = '<p>No scans have been run yet. Once your IT team completes scans, a summary will appear here.</p>';
      return;
    }

    const recentHtml = data.recent.map(r => {
      const color = r.level === 'Good' ? '#16A34A' : r.level === 'Needs Attention' ? '#D97706' : '#DC2626';
      return `<div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #E2E8F0;">
        <span>${r.url}</span>
        <span style="color:${color}; font-weight:600;">${r.level}</span>
      </div>`;
    }).join('');

    container.innerHTML = `
      <p style="font-size:16px; font-weight:600; color:#0F172A; margin-bottom:12px;">${data.overall_message}</p>
      <p>Out of <strong>${data.total_apps}</strong> applications scanned: <strong style="color:#16A34A">${data.good_count}</strong> are in good standing, <strong style="color:#D97706">${data.needs_attention_count}</strong> need attention, and <strong style="color:#DC2626">${data.urgent_count}</strong> require urgent action.</p>
      <div style="margin-top:16px;">
        <div style="font-weight:600; margin-bottom:8px;">Recent Applications</div>
        ${recentHtml}
      </div>
    `;
  } catch (err) {
    console.error('Could not load risk summary:', err);
    container.innerHTML = '<p>Could not load the risk summary at this time.</p>';
  }
}

/* ── RENDER DASHBOARD ── */
function renderDashboard() {
  if (window.USER_ROLE === 'admin') {
    loadAdminRiskSummary();
  }
  const t = WG.totals();
  animateCount('stat-apps',   t.appsScanned);
  animateCount('stat-vulns',  t.vulnsFound);
  animateCount('stat-crit',   t.critIssues);
  animateCount('stat-score',  t.avgScore);

  // Score ring
  const ring = document.getElementById('ringFill');
  const scoreLbl = document.getElementById('scoreRingLabel');
  if (ring) {
    const offset = 314 - (314 * t.avgScore / 100);
    ring.style.strokeDashoffset = t.appsScanned ? offset : 314;
    ring.style.stroke = t.avgScore >= 70 ? 'var(--success)' : t.avgScore >= 50 ? 'var(--warning)' : 'var(--danger)';
  }
  if (scoreLbl) scoreLbl.textContent = t.avgScore || '—';

  // Recent scans table
  const tbody = document.getElementById('recentScansTbody');
  if (!tbody) return;
  const recent = WG.state.scans.slice(0, 5);
  if (recent.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell"><i class="fas fa-radar"></i><br>No scans yet. <button class="btn-link-inline" onclick="showPage('scan')">Start your first scan</button></td></tr>`;
    return;
  }
  tbody.innerHTML = recent.map(s => `
    <tr>
      <td><span class="url-cell"><i class="fas fa-globe"></i>${s.url}</span></td>
      <td><span class="badge-type">${s.appType}</span></td>
      <td>${scoreChip(s.score)}</td>
      <td><span class="vuln-count ${s.criticalCount > 0 ? 'high' : ''}">${s.vulns.length}</span></td>
      <td><span class="status-pill done">Completed</span></td>
      <td class="date-cell">${s.date}</td>
      <td><button class="btn-view" onclick="openReport('${s.id}')">View</button></td>
    </tr>`).join('');

  // Breakdown chart
  renderVulnChart();
  renderSeverityDist();
}

/* ── RENDER HISTORY ── */
function renderHistory() {
  const tbody = document.getElementById('historyTbody');
  if (!tbody) return;
  if (WG.state.scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-cell"><i class="fas fa-clock-rotate-left"></i><br>No scans in history yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = WG.state.scans.map((s, i) => `
    <tr>
      <td class="mono">${String(i+1).padStart(3,'0')}</td>
      <td><span class="url-cell"><i class="fas fa-globe"></i>${s.url}</span></td>
      <td><span class="badge-type">${s.appType}</span></td>
      <td class="capitalize">${s.depth}</td>
      <td>${scoreChip(s.score)}</td>
      <td><span class="vuln-count ${s.criticalCount>0?'high':''}">${s.vulns.length}</span></td>
      <td><span class="status-pill done">Completed</span></td>
      <td class="date-cell">${s.date}</td>
      <td><button class="btn-view" onclick="openReport('${s.id}')">Report</button></td>
    </tr>`).join('');
}

/* ── RENDER REPORTS ── */
function renderReports() {
  const container = document.getElementById('reportsContainer');
  if (!container) return;
  if (WG.state.scans.length === 0) {
    // Don't overwrite — leave the Django-rendered empty state as-is
    return;
  }
  const col = s => s.score >= 70 ? 'green' : s.score >= 50 ? 'orange' : 'red';
  container.innerHTML = WG.state.scans.map(s => `
    <div class="report-card">
      <div class="report-icon ${col(s)}"><i class="fas fa-file-shield"></i></div>
      <div class="report-info">
        <div class="report-title">${s.url}</div>
        <div class="report-meta">${cap(s.depth.charAt(0).toUpperCase()+s.depth.slice(1))} Scan &middot; ${s.vulns.length} vulns &middot; Score: ${s.score}</div>
        <div class="report-date">${s.date}</div>
      </div>
      <div class="report-actions">
        <span class="status-pill done">Ready</span>
        <button class="btn-view" onclick="openReport('${s.id}')"><i class="fas fa-eye"></i> View</button>
        <button class="btn-download" onclick="downloadRealPDF('${s.id}')"><i class="fas fa-download"></i> PDF</button>
      </div>
    </div>`).join('');
}

/* ── RENDER VULNERABILITIES ── */
function renderVulnerabilities() {
  const tbody = document.getElementById('vulnsTbody');
  if (!tbody) return;
  const allVulns = WG.state.scans.flatMap(s =>
    s.vulns.map(v => ({ ...v, scanUrl: s.url, scanId: s.id }))
  );
  if (allVulns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell"><i class="fas fa-bug"></i><br>No vulnerabilities detected yet. Run a scan first.</td></tr>`;
    return;
  }
  tbody.innerHTML = allVulns.map(v => `
    <tr>
      <td class="mono">${v.vid}</td>
      <td title="${v.desc}">${v.name}</td>
      <td><span class="url-cell small"><i class="fas fa-globe"></i>${v.scanUrl}</span></td>
      <td><span class="sev-badge ${v.severity}">${cap(v.severity)}</span></td>
      <td class="mono small">${v.owasp}</td>
      <td>
        <select class="status-select" onchange="updateVulnStatus('${v.scanId}','${v.vid}',this.value)">
          <option value="open"     ${v.status==='open'    ?'selected':''}>Open</option>
          <option value="inreview" ${v.status==='inreview'?'selected':''}>In Review</option>
          <option value="patching" ${v.status==='patching'?'selected':''}>Patching</option>
          <option value="resolved" ${v.status==='resolved'?'selected':''}>Resolved</option>
        </select>
      </td>
      <td class="date-cell">${WG.state.scans.find(s=>s.id===v.scanId)?.date || '—'}</td>
    </tr>`).join('');
}

function updateVulnStatus(scanId, vid, newStatus) {
  const scan = WG.state.scans.find(s => s.id === scanId);
  if (!scan) return;
  const vuln = scan.vulns.find(v => v.vid === vid);
  if (vuln) { vuln.status = newStatus; WG._persistState(); }
}

/* ── RENDER TARGETS ── */
function renderTargets() {
  const container = document.getElementById('targetsContainer');
  if (!container) return;
  const uniqueTargets = [...new Map(WG.state.scans.map(s => [s.url, s])).values()];
  if (uniqueTargets.length === 0) {
    container.innerHTML = `<div class="empty-state"><i class="fas fa-crosshairs"></i><p>No targets scanned yet.</p><button class="btn-primary-cta" onclick="showPage('scan')"><i class="fas fa-radar"></i> Scan a Target</button></div>`;
    return;
  }
  const icons = { 'Student Portal':'fa-user-graduate','LMS':'fa-book-open','Admin Dashboard':'fa-screwdriver-wrench','Other':'fa-globe' };
  container.innerHTML = uniqueTargets.map(s => `
    <div class="target-card">
      <div class="target-icon"><i class="fas ${icons[s.appType]||'fa-globe'}"></i></div>
      <div class="target-info">
        <div class="target-name">${s.url}</div>
        <div class="target-type">${s.appType} &middot; Last scanned ${s.date}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        ${scoreChip(s.score)}
        <button class="btn-view" onclick="openReport('${s.id}')">View</button>
      </div>
    </div>`).join('');
}

/* ── RENDER OWASP ── */
function renderOWASP() {
  const allVulns = WG.state.scans.flatMap(s => s.vulns);
  const owaspMap = {};
  allVulns.forEach(v => {
    if (!owaspMap[v.owasp]) owaspMap[v.owasp] = [];
    owaspMap[v.owasp].push(v);
  });

  const cats = [
    { code:'A01:2021', name:'Broken Access Control' },
    { code:'A02:2021', name:'Cryptographic Failures' },
    { code:'A03:2021', name:'Injection' },
    { code:'A04:2021', name:'Insecure Design' },
    { code:'A05:2021', name:'Security Misconfiguration' },
    { code:'A06:2021', name:'Vulnerable Components' },
    { code:'A07:2021', name:'Auth & Access Failures' },
    { code:'A08:2021', name:'Integrity Failures' },
    { code:'A09:2021', name:'Logging & Monitoring' },
    { code:'A10:2021', name:'SSRF' },
  ];

  const container = document.getElementById('owaspContainer');
  if (!container) return;

  if (WG.state.scans.length === 0) {
    container.innerHTML = `<div class="empty-state full" style="grid-column:1/-1"><i class="fas fa-list-check"></i><p>Run a scan to see your OWASP Top 10 compliance status.</p></div>`;
    return;
  }

  container.innerHTML = cats.map(c => {
    const found = owaspMap[c.code] || [];
    const worst = found.reduce((a, v) => {
      const order = ['critical','high','medium','low'];
      return order.indexOf(v.severity) < order.indexOf(a) ? v.severity : a;
    }, 'none');
    const pass = found.length === 0;
    const badge = pass
      ? `<span class="sev-badge low">Passed</span>`
      : `<span class="sev-badge ${worst}">${found.length} issue${found.length>1?'s':''}</span>`;
    return `
      <div class="owasp-card ${pass?'pass':'fail'}">
        <div class="owasp-num">${c.code.split(':')[0]}</div>
        <div class="owasp-name">${c.name}</div>
        ${badge}
      </div>`;
  }).join('');
}

/* ── RENDER CHARTS ── */
function renderVulnChart() {
  const allVulns = WG.state.scans.flatMap(s => s.vulns);
  const counts = { sqli:0, xss:0, auth:0, config:0, other:0 };
  allVulns.forEach(v => {
    if (v.id==='sqli') counts.sqli++;
    else if (v.id==='rxss'||v.id==='sxss') counts.xss++;
    else if (v.id==='auth'||v.id==='bac'||v.id==='idor') counts.auth++;
    else if (v.id==='cfg'||v.id==='csp'||v.id==='hsts') counts.config++;
    else counts.other++;
  });
  const max = Math.max(...Object.values(counts), 1);
  const bars = ['sqli','xss','auth','config','other'];
  bars.forEach(k => {
    const el = document.getElementById('vcb-' + k);
    if (el) {
      const pct = Math.round((counts[k]/max)*100);
      el.style.height = pct + '%';
      el.title = k.toUpperCase() + ' — ' + counts[k];
      const lbl = document.getElementById('vcb-' + k + '-lbl'); if (lbl) lbl.textContent = counts[k];
    }
  });
}

function renderSeverityDist() {
  const allVulns = WG.state.scans.flatMap(s => s.vulns);
  const total = allVulns.length || 1;
  ['critical','high','medium','low'].forEach(sev => {
    const n = allVulns.filter(v => v.severity === sev).length;
    const bar = document.getElementById('sev-bar-' + sev);
    const cnt = document.getElementById('sev-cnt-' + sev);
    if (bar) bar.style.width = Math.round((n/total)*100) + '%';
    if (cnt) cnt.textContent = n;
  });
}


let currentReportScanId = null;

async function loadExecutiveSummary(scanId) {
  const realId = scanId.replace('scan-', '');
  try {
    const resp = await fetch(`/scanner/executive/${realId}/`);
    if (!resp.ok) throw new Error('Could not load executive summary');
    const data = await resp.json();

    document.getElementById('exec-risk-level').textContent = data.risk_level;
    document.getElementById('exec-risk-message').textContent = data.risk_message;
    document.getElementById('exec-findings-list').innerHTML =
      data.plain_findings.length
        ? data.plain_findings.map(f => `<li>${f}</li>`).join('')
        : '<li>No issues were found during this scan.</li>';
    document.getElementById('exec-recommendation').textContent = data.recommendation;
  } catch (err) {
    console.error(err);
    document.getElementById('exec-risk-level').textContent = 'Unavailable';
    document.getElementById('exec-risk-message').textContent = 'Could not load the executive summary for this scan.';
  }
}

function switchReportView(view) {
  const techBtn = document.getElementById('toggleTechnicalBtn');
  const execBtn = document.getElementById('toggleExecutiveBtn');
  const techView = document.getElementById('technicalReportView');
  const execView = document.getElementById('executiveReportView');

 // Administrator has no Technical tab — always force executive
 if (!techBtn || !techView) {
  if (techView) techView.style.display = 'none';
  if (execView) execView.style.display = '';
  if (execBtn) {
    execBtn.style.background = '#1B4FD8';
    execBtn.style.color = '#fff';
  }
  if (currentReportScanId) loadExecutiveSummary(currentReportScanId);
  return;
}

  if (view === 'technical') {
    techView.style.display = '';
    execView.style.display = 'none';
    techBtn.style.background = '#1B4FD8';
    techBtn.style.color = '#fff';
    execBtn.style.background = '#fff';
    execBtn.style.color = '#1B4FD8';
  } else {
    techView.style.display = 'none';
    execView.style.display = '';
    execBtn.style.background = '#1B4FD8';
    execBtn.style.color = '#fff';
    techBtn.style.background = '#fff';
    techBtn.style.color = '#1B4FD8';
    if (currentReportScanId) loadExecutiveSummary(currentReportScanId);
  }
}

/* ── OPEN REPORT MODAL ── */
function openReport(scanId) {
  currentReportScanId = scanId;
  switchReportView('technical');
  const scan = WG.state.scans.find(s => s.id === scanId);
  if (!scan) return;

  document.getElementById('modal-url').textContent   = scan.url;
  document.getElementById('modal-date').textContent  = scan.date;
  document.getElementById('modal-depth').textContent = cap(scan.depth) + ' Scan';
  document.getElementById('modal-score').textContent = scan.score;
  document.getElementById('modal-score').className   = 'modal-score-big ' + (scan.score>=70?'green':scan.score>=50?'orange':'red');
  document.getElementById('modal-total').textContent = scan.vulns.length;
  document.getElementById('modal-crit').textContent  = scan.vulns.filter(v=>v.severity==='critical').length;
  document.getElementById('modal-high').textContent  = scan.vulns.filter(v=>v.severity==='high').length;
  document.getElementById('modal-med').textContent   = scan.vulns.filter(v=>v.severity==='medium').length;
  document.getElementById('modal-low').textContent   = scan.vulns.filter(v=>v.severity==='low').length;

  const list = document.getElementById('modal-vuln-list');
  list.innerHTML = scan.vulns.map(v => `
    <div class="modal-vuln-item">
      <div class="modal-vuln-header">
        <span class="sev-badge ${v.severity}">${cap(v.severity)}</span>
        <strong>${v.name}</strong>
        <span class="mono small">${v.owasp}</span>
      </div>
      <div class="modal-vuln-loc"><i class="fas fa-location-dot"></i> ${v.location}</div>
      <div class="modal-vuln-desc">${v.desc}</div>
    </div>`).join('');

    document.getElementById('exportPdfBtn').onclick = () => downloadRealPDF(scanId);
  document.getElementById('reportModal').classList.add('open');
}

function closeModal() {
  document.getElementById('reportModal').classList.remove('open');
}

function downloadRealPDF(scanId) {
  const realId = scanId.replace('scan-', '');
  const execView = document.getElementById('executiveReportView');
  const isExecutive = execView && execView.style.display !== 'none';
  const reportType = isExecutive ? 'executive' : 'technical';

  window.location.href = `/scanner/pdf/${realId}/${reportType}/`;
}

/* ── EXPORT PDF (print-to-PDF) ── */
function exportPDF(scanId) {
  const scan = WG.state.scans.find(s => s.id === scanId);
  if (!scan) return;

  const html = `
  <html><head><title>WebGuard Report — ${scan.url}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; color: #0F172A; }
    h1 { color: #1B4FD8; } h2 { color: #1B4FD8; margin-top: 28px; }
    .meta { color: #64748B; font-size: 13px; margin-bottom: 20px; }
    .score-box { background:#EFF6FF; border-left:4px solid #1B4FD8; padding:12px 20px; margin-bottom:20px; }
    .score-num { font-size: 42px; font-weight:700; color:#1B4FD8; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th { background:#1B4FD8; color:#fff; padding:8px 12px; text-align:left; }
    td { padding:8px 12px; border-bottom:1px solid #E2E8F0; }
    .crit{background:#FEF2F2;color:#7F1D1D;padding:2px 8px;border-radius:4px;font-weight:700}
    .high{background:#FEF2F2;color:#DC2626;padding:2px 8px;border-radius:4px;font-weight:700}
    .medium{background:#FFFBEB;color:#D97706;padding:2px 8px;border-radius:4px;font-weight:700}
    .low{background:#F0FDF4;color:#16A34A;padding:2px 8px;border-radius:4px;font-weight:700}
    footer { margin-top:40px; color:#94A3B8; font-size:11px; border-top:1px solid #E2E8F0; padding-top:12px; }
  </style></head>
  <body>
  <h1>🛡 WebGuard Vulnerability Report</h1>
  <div class="meta">
    <strong>Target:</strong> ${scan.url} &nbsp;|&nbsp;
    <strong>Scan Type:</strong> ${cap(scan.depth)} &nbsp;|&nbsp;
    <strong>Date:</strong> ${scan.date} &nbsp;|&nbsp;
    <strong>App Type:</strong> ${scan.appType}
  </div>
  <div class="score-box">
    <div>Security Score</div>
    <div class="score-num">${scan.score}<span style="font-size:18px;color:#64748B"> / 100</span></div>
  </div>
  <h2>Summary</h2>
  <table>
    <tr><th>Category</th><th>Count</th></tr>
    <tr><td>Total Vulnerabilities</td><td>${scan.vulns.length}</td></tr>
    <tr><td>Critical</td><td>${scan.vulns.filter(v=>v.severity==='critical').length}</td></tr>
    <tr><td>High</td><td>${scan.vulns.filter(v=>v.severity==='high').length}</td></tr>
    <tr><td>Medium</td><td>${scan.vulns.filter(v=>v.severity==='medium').length}</td></tr>
    <tr><td>Low</td><td>${scan.vulns.filter(v=>v.severity==='low').length}</td></tr>
  </table>
  <h2>Vulnerability Details</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Severity</th><th>OWASP</th><th>Location</th><th>Description</th></tr>
    ${scan.vulns.map(v=>`<tr>
      <td>${v.vid}</td><td>${v.name}</td>
      <td><span class="${v.severity}">${cap(v.severity)}</span></td>
      <td>${v.owasp}</td><td>${v.location}</td><td>${v.desc}</td>
    </tr>`).join('')}
  </table>
  <footer>Generated by WebGuard · A Caleb University Research Project · ${new Date().toLocaleDateString()}</footer>
  </body></html>`;

  const w = window.open('', '_blank');
  w.document.write(html);
  w.document.close();
  setTimeout(() => w.print(), 500);
}

/* ── SCAN ENGINE ── */
let scanRunning = false;
const consoleLogs = [
  ['[+] Initializing WebGuard scanner engine v1.0...', ''],
  ['[+] Resolving hostname...', ''],
  ['[+] Crawler started — mapping application pages', 'log-ok'],
  ['[~] Testing SQL injection on form inputs...', 'log-warn'],
  ['[~] Fuzzing query parameters for XSS vectors...', 'log-warn'],
  ['[~] Checking authentication endpoints...', 'log-warn'],
  ['[~] Auditing HTTP security headers...', 'log-warn'],
  ['[~] Inspecting SSL/TLS configuration...', 'log-warn'],
  ['[~] Checking for sensitive data exposure...', 'log-warn'],
  ['[~] Running OWASP Top 10 checks...', 'log-warn'],
  ['[+] Analysing collected findings...', ''],
  ['[✓] Report generation complete.', 'log-ok'],
];

function startScan() {
  const urlInput = document.getElementById('targetUrl');
  const url = urlInput.value.trim();
  if (!url || !url.startsWith('http')) {
    urlInput.classList.add('input-error');
    urlInput.placeholder = 'Please enter a valid URL starting with https://';
    setTimeout(() => { urlInput.classList.remove('input-error'); urlInput.placeholder = 'https://example.com'; }, 3000);
    return;
  }
  if (scanRunning) return;
  scanRunning = true;

  const depth = document.querySelector('input[name="depth"]:checked')?.value || 'standard';
  const appType = document.getElementById('appType').value || 'Web App';

  document.getElementById('progressIdle').classList.add('hidden');
  document.getElementById('progressDone').classList.add('hidden');
  document.getElementById('progressActive').classList.remove('hidden');
  document.getElementById('scanTargetLabel').textContent = 'Scanning: ' + url;

  const steps = document.querySelectorAll('.scan-step');
  const progBar = document.getElementById('progBarFill');
  const progPct = document.getElementById('progPct');
  const consoleEl = document.getElementById('consoleLog');
  consoleEl.innerHTML = '';

  steps.forEach(s => s.classList.remove('done','active'));
  progBar.style.width = '0%';

  let stepIdx = 0, logIdx = 0;
  const totalSteps = steps.length;
  let completedScan = null;

  const stepInterval = setInterval(() => {
    if (stepIdx > 0) {
      steps[stepIdx-1].classList.remove('active');
      steps[stepIdx-1].classList.add('done');
    }
    if (stepIdx < totalSteps) {
      steps[stepIdx].classList.add('active');
      stepIdx++;
      const pct = Math.round((stepIdx / totalSteps) * 100);
      progBar.style.width = pct + '%';
      progPct.textContent = pct + '%';
    } else {
      clearInterval(stepInterval);
      steps[totalSteps-1].classList.remove('active');
      steps[totalSteps-1].classList.add('done');
     // Finalise scan — real backend call
     WG.runRealScan(url, depth, appType)
     .then(scan => {
       completedScan = scan;
       setTimeout(() => showScanDone(completedScan), 600);
     })
     .catch(err => {
       console.error(err);
       alert('Scan failed: ' + err.message);
       resetScan();
     });
    }
  }, 1600);

  const logInterval = setInterval(() => {
    if (logIdx < consoleLogs.length) {
      const [text, cls] = consoleLogs[logIdx];
      const line = document.createElement('div');
      if (cls) line.className = cls;
      line.textContent = text;
      consoleEl.appendChild(line);
      consoleEl.scrollTop = consoleEl.scrollHeight;
      logIdx++;
    } else {
      clearInterval(logInterval);
    }
  }, 800);
}

function showScanDone(scan) {
  document.getElementById('progressActive').classList.add('hidden');
  document.getElementById('progressDone').classList.remove('hidden');
  document.getElementById('doneMessage').innerHTML =
    `Found <strong>${scan.vulns.length} vulnerabilities</strong> &mdash; ${scan.criticalCount} critical. Score: <strong>${scan.score}/100</strong>.`;
  document.getElementById('viewReportBtn').onclick = () => openReport(scan.id);
  scanRunning = false;
}

function resetScan() {
  document.getElementById('targetUrl').value = '';
  document.getElementById('progressDone').classList.add('hidden');
  document.getElementById('progressActive').classList.add('hidden');
  document.getElementById('progressIdle').classList.remove('hidden');
  document.querySelectorAll('.scan-step').forEach(s => s.classList.remove('done','active'));
  document.getElementById('progBarFill').style.width = '0%';
  document.getElementById('progPct').textContent = '0%';
  document.getElementById('consoleLog').innerHTML = '';
  scanRunning = false;
}

/* ── HELPERS ── */
function cap(str) { return str ? str.charAt(0).toUpperCase() + str.slice(1) : ''; }

function scoreChip(score) {
  const cls = score >= 70 ? 'good' : score >= 50 ? 'medium' : 'low';
  return `<span class="score-pill ${cls}">${score}</span>`;
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let cur = 0;
  const step = Math.ceil(target / 40) || 1;
  if (target === 0) { el.textContent = '0'; return; }
  const t = setInterval(() => {
    cur = Math.min(cur + step, target);
    el.textContent = cur;
    if (cur >= target) clearInterval(t);
  }, 30);
}

/* ── DEPTH SELECTOR ── */
document.querySelectorAll('.depth-opt').forEach(opt => {
  opt.addEventListener('click', () => {
    document.querySelectorAll('.depth-opt').forEach(o => o.classList.remove('active'));
    opt.classList.add('active');
    opt.querySelector('input').checked = true;
  });
});

/* ── CHECKBOX ITEMS ── */
document.querySelectorAll('.check-item input').forEach(cb => {
  cb.addEventListener('change', () => cb.closest('.check-item').classList.toggle('checked', cb.checked));
});

/* ── SIDEBAR TOGGLE ── */
document.getElementById('sidebarToggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

/* ── NAV CLICKS ── */
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
  item.addEventListener('click', e => { e.preventDefault(); showPage(item.dataset.page); });
});

/* ── MODAL CLOSE ── */
document.getElementById('reportModal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

/* ── INIT ── */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const resp = await fetch('/scanner/all/');
    if (resp.ok) {
      const data = await resp.json();
      WG.state.scans = data.scans;
    }
  } catch (err) {
    console.error('Could not load scan history:', err);
  }
  renderDashboard();
});

// patch renderSeverityDist to also update the bottom-row chart
const _origSevDist = renderSeverityDist;
renderSeverityDist = function() {
  _origSevDist();
  const allVulns = WG.state.scans.flatMap(s => s.vulns);
  const total = allVulns.length || 1;
  ['critical','high','medium','low'].forEach(sev => {
    const n = allVulns.filter(v => v.severity === sev).length;
    const bar2 = document.getElementById('sev-bar-' + sev + '2');
    const cnt2 = document.getElementById('sev-cnt-' + sev + '2');
    if (bar2) bar2.style.width = Math.round((n/total)*100) + '%';
    if (cnt2) cnt2.textContent = n;
  });
};