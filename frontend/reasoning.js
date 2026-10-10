const esc = v => String(v ?? '-').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

async function init() {
  const noReport = document.getElementById('noReportState');
  const reportState = document.getElementById('reportState');
  let stored;
  try {
    stored = JSON.parse(localStorage.getItem('aegis_last_report') || 'null');
  } catch (e) {
    stored = null;
  }

  if (!stored || !stored.app_info) {
    noReport.classList.remove('hidden');
    reportState.classList.add('hidden');
    return;
  }

  noReport.classList.add('hidden');
  reportState.classList.remove('hidden');

  document.getElementById('appTitle').textContent = stored.app_info.app_name || stored.app_info.file_name || 'Unknown app';
  document.getElementById('findingsBadge').textContent = `${(stored.findings || []).length} findings received`;
  document.getElementById('sourceSummary').innerHTML = `
    <div class="data-row"><small>PACKAGE</small><b>${esc(stored.app_info.package_name)}</b></div>
    <div class="data-row"><small>FILE</small><b>${esc(stored.app_info.file_name)}</b></div>
    <div class="data-row"><small>SHA-256</small><b>${esc(stored.app_info.sha256)}</b></div>
    <div class="data-row"><small>IOCs PROVIDED</small><b>${(stored.iocs || []).length}</b></div>
  `;

  document.getElementById('reasonStatus').textContent = '● REASONING…';

  try {
    const res = await fetch('/api/reason', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stored),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);
    render(data);
  } catch (e) {
    document.getElementById('reasonLoading').textContent = 'Reasoning Agent failed: ' + e.message;
    document.getElementById('reasonStatus').textContent = '● FAILED';
  }
}

function render(data) {
  document.getElementById('reasonLoading').classList.add('hidden');
  document.getElementById('reasonResult').classList.remove('hidden');
  document.getElementById('reasonStatus').textContent = data.available ? '● COMPLETE' : '● UNAVAILABLE';

  document.getElementById('summaryBox').textContent =
    data.summary || (data.error ? `Reasoning Agent could not run: ${data.error}` : 'No summary produced.');

  document.getElementById('intentBox').textContent = data.likely_intent || 'Not determined';
  document.getElementById('confidenceBox').textContent = data.confidence_reason || 'No confidence reasoning provided.';

  const chain = data.attack_chain || [];
  document.getElementById('attackChainBox').innerHTML = chain.length
    ? chain.map((step, i) => `<div class="chain-step"><span>${i + 1}</span><p>${esc(step)}</p></div>`).join('')
    : '<div class="empty">Insufficient evidence to reconstruct an attack chain.</div>';

  const concerning = data.concerning_findings || [];
  document.getElementById('concerningBox').innerHTML = concerning.length
    ? concerning.map(f => `
        <article class="finding" style="--sev:#ffad63">
          <div class="finding-head"><h3>${esc(f.title || f.rule_id)}</h3><span class="badge">${esc(f.rule_id)}</span></div>
          <p>${esc(f.why)}</p>
        </article>`).join('')
    : '<div class="empty" style="padding:0 24px">No individual findings were singled out.</div>';

  const mitre = data.mitre_techniques || [];
  document.getElementById('mitreBox').innerHTML = mitre.length
    ? mitre.map(m => `<div class="data-row"><small>${esc(m.mitre_id)}</small><b>${esc(m.mitre_technique)} · ${esc(m.finding_title)}</b></div>`).join('')
    : '<div class="empty">No MITRE ATT&CK Mobile techniques were mapped from current findings.</div>';
}

init();
