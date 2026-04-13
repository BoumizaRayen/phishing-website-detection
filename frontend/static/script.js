/* PhishGuard AI — Premium Script */

document.addEventListener('DOMContentLoaded', () => {
  /* ── DOM Nodes ──────────────────────────────── */
  const form             = document.getElementById('scan-form');
  const urlInput         = document.getElementById('url-input');
  const scanBtn          = document.getElementById('scan-btn');
  const errorToast       = document.getElementById('error-message');
  const loadingState     = document.getElementById('loading-state');
  const resultSection    = document.getElementById('result-section');
  const btnReset         = document.getElementById('btn-reset');
  const btnExportPdf     = document.getElementById('btn-export-pdf');
  const historyContainer = document.getElementById('history-container');

  // Result nodes
  const verdictBanner    = document.getElementById('verdict-banner');
  const verdictLabel     = document.getElementById('verdict-label');
  const verdictSvg       = document.getElementById('verdict-svg');
  const verdictIconWrap  = document.getElementById('verdict-icon-wrap');
  const riskChip         = document.getElementById('risk-chip');
  const threatValue      = document.getElementById('threat-value');
  const threatFill       = document.getElementById('threat-fill');
  const metaContent      = document.getElementById('meta-content');
  const featuresList     = document.getElementById('features-list');
  const vtPanel          = document.getElementById('vt-panel');
  const vtContent        = document.getElementById('vt-content');
  const analysisTime     = document.getElementById('analysis-time');

  /* ── Init History ───────────────────────────── */
  renderHistory();

  /* ── Form Submit ────────────────────────────── */
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    // Reset UI
    hide(errorToast);
    hide(resultSection);
    show(loadingState);
    scanBtn.disabled = true;

    try {
      const res = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Erreur serveur inattendue');
      displayResults(data);
    } catch (err) {
      hide(loadingState);
      errorToast.textContent = err.message;
      show(errorToast);
    } finally {
      scanBtn.disabled = false;
    }
  });

  /* ── Reset ──────────────────────────────────── */
  btnReset.addEventListener('click', () => {
    hide(resultSection);
    hide(errorToast);
    urlInput.value = '';
    urlInput.focus();
  });

  /* ── PDF Export ─────────────────────────────── */
  btnExportPdf.addEventListener('click', () => {
    const el = document.getElementById('export-target');
    html2pdf().set({
      margin: 0.5,
      filename: `phishguard-${Date.now()}.pdf`,
      image: { type: 'jpeg', quality: 0.97 },
      html2canvas: { scale: 2, backgroundColor: '#0d1829' },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
    }).from(el).save();
  });

  /* ── Display Results ────────────────────────── */
  function displayResults(data) {
    hide(loadingState);

    const isPhishing     = data.is_phishing;
    const riskLevel      = data.risk_level;     // 'low' | 'medium' | 'high' | 'critical'
    const confidencePct  = (data.confidence * 100).toFixed(1);

    // 1. Verdict Banner
    verdictBanner.className = `verdict-banner ${isPhishing ? 'phishing' : 'legitimate'}`;

    if (isPhishing) {
      verdictSvg.innerHTML = `
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`;
      verdictLabel.textContent = 'Phishing Détecté';
    } else {
      verdictSvg.innerHTML = `
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>`;
      verdictLabel.textContent = 'Site Légitime';
    }

    // 2. Risk Chip
    const riskLabels = { low: 'Risque Faible', medium: 'Risque Modéré', high: 'Risque Élevé', critical: 'Critique ⚠' };
    riskChip.className = `risk-chip ${riskLevel}`;
    riskChip.textContent = riskLabels[riskLevel] || riskLevel;

    // 3. Threat Score
    threatValue.textContent = `${confidencePct}%`;
    threatValue.style.color = isPhishing ? 'var(--danger-light)' : 'var(--success-light)';
    setTimeout(() => {
      threatFill.style.width = `${confidencePct}%`;
      threatFill.className = `threat-fill ${riskLevel}`;
    }, 80);

    // 4. Meta Card
    const fetchState = data.fetch_info?.html_available ? '✓ Extraction URL + DOM' : '⚠ Extraction URL seule';
    const redirects  = data.fetch_info?.redirect_count ?? 0;
    metaContent.innerHTML = `
      <span>${fetchState}</span>
      <span>Redirections : <strong>${redirects}</strong></span>
      <span>Durée d'analyse : <strong>${data.analysis_duration_ms} ms</strong></span>
    `;

    // 5. SHAP Features
    featuresList.innerHTML = '';
    (data.top_features || []).forEach(f => {
      const shap      = f.shap_value ?? 0;
      const isPush    = shap > 0; // positive => pushes toward phishing
      const widthPct  = Math.min(100, Math.abs(shap) * 35).toFixed(1);
      const valueStr  = formatValue(f.value);
      const shapSign  = shap > 0 ? '+' : '';

      const li = document.createElement('li');
      li.className = 'feature-item';
      li.innerHTML = `
        <div class="feature-shap-indicator ${isPush ? 'fi-phishing' : 'fi-legit'}">
          ${isPush ? '↑' : '↓'}
        </div>
        <div class="feature-body">
          <div class="feature-name">${f.label || f.feature}</div>
          <div class="shap-bar-track">
            <div class="shap-bar-fill ${isPush ? 'phishing' : 'legitimate'}" style="width:${widthPct}%"></div>
          </div>
        </div>
        <div class="feature-right">
          <span class="feature-val">${valueStr}</span>
          <span class="feature-shap-val">SHAP ${shapSign}${shap.toFixed(3)}</span>
        </div>
      `;
      featuresList.appendChild(li);
    });

    if (!data.top_features?.length) {
      featuresList.innerHTML = '<li class="feature-item"><span style="color:var(--text-muted)">Aucune feature significative.</span></li>';
    }

    // 6. VirusTotal
    if (data.virustotal_report) {
      const vt = data.virustotal_report;
      let vtHtml = '';
      if (vt.positives > 0) {
        vtHtml = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--danger-light)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span style="color:var(--danger-light)"><strong>VirusTotal:</strong> ${vt.positives}/${vt.total} moteurs ont signalé cette URL.</span>`;
      } else {
        vtHtml = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success-light)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
          <span style="color:var(--success-light)"><strong>VirusTotal:</strong> Aucun moteur ne signale cette URL (${vt.total} scannés).</span>`;
      }
      vtHtml += ` <a href="${vt.permalink}" target="_blank">Voir rapport →</a>`;
      vtContent.innerHTML = vtHtml;
      analysisTime.textContent = `Analyse complète en ${data.analysis_duration_ms} ms`;
      show(vtPanel);
    } else {
      analysisTime.textContent = `Analyse complète en ${data.analysis_duration_ms} ms`;
      vtContent.innerHTML = `<span>VirusTotal non configuré</span>`;
      show(vtPanel);
    }

    // 7. Show result
    show(resultSection);

    // 8. Add to history
    saveHistory({ url: data.url, verdict: data.verdict, risk: data.risk_level });
  }

  /* ── History ───────────────────────────────── */
  function saveHistory({ url, verdict, risk }) {
    let h = getHistory();
    h = h.filter(i => i.url !== url);
    h.unshift({ url, verdict, risk });
    h = h.slice(0, 5);
    localStorage.setItem('phishguard_history', JSON.stringify(h));
    renderHistory();
  }

  function getHistory() {
    return JSON.parse(localStorage.getItem('phishguard_history') || '[]');
  }

  function renderHistory() {
    const h = getHistory();
    if (!h.length) {
      historyContainer.innerHTML = '<div class="history-empty">Aucun historique récent.</div>';
      return;
    }
    historyContainer.innerHTML = h.map(item => `
      <div class="history-item" data-url="${item.url}">
        <span class="history-item-url">${item.url}</span>
        <div class="history-item-meta">
          <div class="history-dot ${item.verdict}"></div>
          <span class="history-item-verdict ${item.verdict}">${item.verdict} · ${item.risk}</span>
        </div>
      </div>
    `).join('');

    historyContainer.querySelectorAll('.history-item').forEach(el => {
      el.addEventListener('click', () => {
        urlInput.value = el.dataset.url;
        form.dispatchEvent(new Event('submit'));
      });
    });
  }

  /* ── Helpers ────────────────────────────────── */
  function show(el) { el.classList.remove('hidden'); }
  function hide(el) { el.classList.add('hidden'); }

  function formatValue(v) {
    if (v === null || v === undefined) return '?';
    if (v === 0 || v === 1) return v === 1 ? 'Oui' : 'Non';
    if (typeof v === 'number' && !Number.isInteger(v)) return v.toFixed(3);
    return v;
  }
});
