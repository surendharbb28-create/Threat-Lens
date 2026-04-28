/* ThreatLens — Frontend Logic */
'use strict';

// ── Tab Switching ──────────────────────────────────────────────────────────────
document.querySelectorAll('.scan-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`panel-${tab.dataset.tab}`).classList.add('active');
    hideResults();
  });
});

// ── File Upload ────────────────────────────────────────────────────────────────
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const selectedFile = document.getElementById('selectedFile');
const selectedFileName = document.getElementById('selectedFileName');
const selectedFileSize = document.getElementById('selectedFileSize');
const removeFile = document.getElementById('removeFile');
const scanFileBtn = document.getElementById('scanFileBtn');
let currentFile = null;

if (dropZone) {
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) setFile(fileInput.files[0]);
  });

  removeFile.addEventListener('click', () => clearFile());

  scanFileBtn.addEventListener('click', () => {
    if (currentFile) doFileScan(currentFile);
  });
}

function setFile(file) {
  currentFile = file;
  dropZone.style.display = 'none';
  selectedFile.style.display = 'flex';
  selectedFileName.textContent = file.name;
  selectedFileSize.textContent = humanSize(file.size);
  scanFileBtn.disabled = false;
}

function clearFile() {
  currentFile = null;
  fileInput.value = '';
  dropZone.style.display = '';
  selectedFile.style.display = 'none';
  scanFileBtn.disabled = true;
  hideResults();
}

async function doFileScan(file) {
  setLoading(scanFileBtn, true);
  const form = new FormData();
  form.append('file', file);
  try {
    const res = await fetch('/api/scan/file/', { method: 'POST', body: form });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    showResults(data);
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    setLoading(scanFileBtn, false);
  }
}

// ── URL Scanner ────────────────────────────────────────────────────────────────
const urlInput = document.getElementById('urlInput');
const urlClear = document.getElementById('urlClear');
const scanUrlBtn = document.getElementById('scanUrlBtn');

if (urlInput) {
  urlInput.addEventListener('input', () => {
    const val = urlInput.value.trim();
    scanUrlBtn.disabled = !val;
    urlClear.style.display = val ? '' : 'none';
  });

  urlClear.addEventListener('click', () => {
    urlInput.value = ''; scanUrlBtn.disabled = true;
    urlClear.style.display = 'none'; hideResults();
  });

  scanUrlBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (url) doUrlScan(url);
  });

  urlInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !scanUrlBtn.disabled) doUrlScan(urlInput.value.trim());
  });

  document.querySelectorAll('.example-url').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      urlInput.dispatchEvent(new Event('input'));
    });
  });
}

async function doUrlScan(url) {
  setLoading(scanUrlBtn, true);
  try {
    const res = await fetch('/api/scan/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (data.error) { alert('Error: ' + data.error); return; }
    showResults(data);
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    setLoading(scanUrlBtn, false);
  }
}

// ── Results Rendering ─────────────────────────────────────────────────────────
function showResults(data) {
  const section = document.getElementById('resultsSection');
  section.style.display = '';

  // Animate meter
  const score = data.risk_score || 0;
  animateMeter(score);

  // Badge
  const level = (data.threat_level || 'CLEAN').toLowerCase();
  const badgeLevel = document.getElementById('badgeLevel');
  badgeLevel.textContent = data.threat_level || 'CLEAN';
  badgeLevel.className = 'badge-level ' + level;

  // Summary
  document.getElementById('resultSummary').textContent = data.summary || '';

  // Meta
  const meta = document.getElementById('resultMeta');
  const items = [];
  if (data.scan_type === 'file') {
    items.push(['FILE', data.target]);
    items.push(['SIZE', data.file_size_human]);
    items.push(['MIME', data.mime_type]);
    items.push(['ENTROPY', data.entropy]);
    items.push(['SCAN TIME', data.scan_duration_ms + 'ms']);
  } else {
    items.push(['URL', data.target]);
    items.push(['DOMAIN', data.domain]);
    items.push(['PROTOCOL', data.scheme?.toUpperCase()]);
    items.push(['URL LENGTH', data.url_length + ' chars']);
    items.push(['SCAN TIME', data.scan_duration_ms + 'ms']);
  }
  meta.innerHTML = items.map(([k, v]) =>
    `<div class="meta-item"><span class="meta-key">${k}</span><span class="meta-val">${v || '—'}</span></div>`
  ).join('');

  // Findings
  const findings = data.findings || [];
  const findingsSection = document.getElementById('findingsSection');
  const findingsList = document.getElementById('findingsList');
  document.getElementById('findingsCount').textContent = findings.length;

  if (findings.length > 0) {
    findingsSection.style.display = '';
    findingsList.innerHTML = findings.map(f => `
      <div class="finding-card ${f.severity}">
        <span class="finding-sev ${f.severity}">${f.severity}</span>
        <span class="finding-type">${f.type}</span>
        <span class="finding-detail">${f.detail}</span>
      </div>
    `).join('');
  } else {
    findingsSection.style.display = 'none';
  }

  // Hashes (file only)
  const hashesSection = document.getElementById('hashesSection');
  if (data.scan_type === 'file' && data.md5) {
    hashesSection.style.display = '';
    document.getElementById('hashMD5').textContent = data.md5;
    document.getElementById('hashSHA256').textContent = data.sha256;
  } else {
    hashesSection.style.display = 'none';
  }

  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResults() {
  const section = document.getElementById('resultsSection');
  if (section) section.style.display = 'none';
}

// Scan again button
const scanAgainBtn = document.getElementById('scanAgainBtn');
if (scanAgainBtn) {
  scanAgainBtn.addEventListener('click', () => {
    hideResults();
    clearFile();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

// ── Meter Animation ───────────────────────────────────────────────────────────
function animateMeter(targetScore) {
  const fill = document.getElementById('meterFill');
  const needle = document.getElementById('meterNeedle');
  const scoreEl = document.getElementById('meterScore');
  const totalDash = 251;

  let current = 0;
  const duration = 800;
  const startTime = performance.now();

  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    current = targetScore * eased;

    const offset = totalDash - (totalDash * current / 100);
    fill.setAttribute('stroke-dashoffset', offset);

    // Needle: -90deg = 0%, +90deg = 100%
    const angle = -90 + (180 * current / 100);
    needle.setAttribute('transform', `rotate(${angle}, 100, 100)`);
    scoreEl.textContent = Math.round(current);

    // Color the fill
    const color = scoreToColor(current);
    fill.setAttribute('stroke', color);
    scoreEl.style.color = color;

    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function scoreToColor(score) {
  if (score === 0) return '#00ff88';
  if (score < 20) return '#66ffcc';
  if (score < 45) return '#ffcc00';
  if (score < 70) return '#ff6600';
  return '#ff0040';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function humanSize(bytes) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

function setLoading(btn, loading) {
  const text = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  btn.disabled = loading;
  if (text) text.style.display = loading ? 'none' : '';
  if (loader) loader.style.display = loading ? '' : 'none';
}

// ── Stats auto-refresh ────────────────────────────────────────────────────────
async function refreshStats() {
  try {
    const res = await fetch('/api/stats/');
    const data = await res.json();
    const total = document.getElementById('stat-total');
    const clean = document.getElementById('stat-clean');
    const threats = document.getElementById('stat-threats');
    if (total) total.textContent = data.total || 0;
    if (clean) clean.textContent = data.by_level?.CLEAN || 0;
    if (threats) threats.textContent = (data.by_level?.HIGH || 0) + (data.by_level?.CRITICAL || 0);
  } catch (e) { /* silent */ }
}

// Refresh stats after each scan
const observer = new MutationObserver(() => refreshStats());
const resultsSection = document.getElementById('resultsSection');
if (resultsSection) observer.observe(resultsSection, { attributes: true, attributeFilter: ['style'] });
