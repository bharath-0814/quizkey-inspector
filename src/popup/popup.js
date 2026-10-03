/**
 * QuizKey Inspector - Popup Controller
 * 
 * Manages user interactions with the extension popup:
 * - Displays active site domain and Authorized Audit Mode status
 * - Authorizes or disables auditing for the current domain
 * - Renders questions detected, answer mappings, and confidence metrics
 * - Displays technical evidence details for security reviewers
 */

document.addEventListener('DOMContentLoaded', () => {
  const siteDomain = document.getElementById('site-domain');
  const auditBadge = document.getElementById('audit-badge');
  const auditNotice = document.getElementById('audit-notice');
  const btnToggleAuth = document.getElementById('btn-toggle-auth');

  const metricQuestions = document.getElementById('metric-questions');
  const metricMappings = document.getElementById('metric-mappings');
  const countHigh = document.getElementById('count-high');
  const countMedium = document.getElementById('count-medium');
  const countLow = document.getElementById('count-low');

  const btnScan = document.getElementById('btn-scan');
  const btnRescan = document.getElementById('btn-rescan');
  const btnEvidence = document.getElementById('btn-evidence');
  const btnClear = document.getElementById('btn-clear');

  const findingsList = document.getElementById('findings-list');
  const findingsCount = document.getElementById('findings-count');
  const emptyStateText = document.getElementById('empty-state-text');

  let showEvidence = true;
  let isAuthorized = false;
  let currentDomain = '';

  init();

  async function init() {
    setupEventListeners();
    await fetchActiveTabStatus();
  }

  function setupEventListeners() {
    btnToggleAuth.addEventListener('click', async () => {
      if (isAuthorized) {
        // Disable audit for this site
        const res = await sendMessageToTab({ action: 'DISABLE_SITE' });
        if (res && res.success) {
          isAuthorized = false;
          renderAuthStatus(false, currentDomain);
          renderMetrics(null, []);
        }
      } else {
        // Authorize audit for this site
        const res = await sendMessageToTab({ action: 'AUTHORIZE_SITE' });
        if (res && res.success) {
          isAuthorized = true;
          renderAuthStatus(true, currentDomain);
          renderMetrics(res.metrics, res.findings);
        }
      }
    });

    btnScan.addEventListener('click', async () => {
      const res = await sendMessageToTab({ action: 'SCAN_PAGE' });
      if (res && res.success) {
        renderMetrics(res.metrics, res.findings);
      }
    });

    btnRescan.addEventListener('click', async () => {
      const res = await sendMessageToTab({ action: 'RESCAN' });
      if (res && res.success) {
        renderMetrics(res.metrics, res.findings);
      }
    });

    btnEvidence.addEventListener('click', () => {
      showEvidence = !showEvidence;
      btnEvidence.textContent = showEvidence ? '📋 Hide Evidence' : '📋 View Evidence';
      const evidenceEls = document.querySelectorAll('.finding-card-evidence');
      evidenceEls.forEach(el => {
        el.style.display = showEvidence ? 'block' : 'none';
      });
    });

    btnClear.addEventListener('click', async () => {
      await sendMessageToTab({ action: 'CLEAR_FINDINGS' });
      renderMetrics({
        questionsDetected: 0,
        answerMappingsCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0
      }, []);
    });
  }

  async function fetchActiveTabStatus() {
    const res = await sendMessageToTab({ action: 'GET_STATUS' });
    if (res && res.success) {
      isAuthorized = !!res.isAuthorized;
      currentDomain = res.currentDomain || 'Current Page';
      renderAuthStatus(isAuthorized, currentDomain);
      if (isAuthorized) {
        renderMetrics(res.metrics, res.findings);
      } else {
        renderUnauthorizedState();
      }
    } else {
      renderNoTabState();
    }
  }

  function renderAuthStatus(authorized, domain) {
    siteDomain.textContent = domain || 'Unknown domain';
    if (authorized) {
      auditBadge.className = 'audit-badge audit-authorized';
      auditBadge.textContent = 'AUTHORIZED';
      auditNotice.textContent = 'Authorized Audit Mode is ACTIVE for this domain. Client data analysis is enabled.';
      btnToggleAuth.className = 'btn btn-auth btn-auth-danger';
      btnToggleAuth.textContent = '⚠️ Disable Audit For This Site';
      btnScan.disabled = false;
      btnRescan.disabled = false;
    } else {
      auditBadge.className = 'audit-badge audit-unauthorized';
      auditBadge.textContent = 'NOT AUTHORIZED';
      auditNotice.textContent = 'Auditing is disabled by default for safety. Only authorize sites you own or have explicit permission to audit.';
      btnToggleAuth.className = 'btn btn-auth';
      btnToggleAuth.textContent = '🛡️ Authorize Audit For This Site';
      btnScan.disabled = true;
      btnRescan.disabled = true;
    }
  }

  function renderMetrics(metrics, findings) {
    if (!metrics) {
      metricQuestions.textContent = '0';
      metricMappings.textContent = '0';
      countHigh.textContent = '0';
      countMedium.textContent = '0';
      countLow.textContent = '0';
      findingsCount.textContent = '0';
      renderFindings([]);
      return;
    }

    metricQuestions.textContent = String(metrics.questionsDetected || 0);
    metricMappings.textContent = String(metrics.answerMappingsCount || 0);
    countHigh.textContent = String(metrics.highCount || 0);
    countMedium.textContent = String(metrics.mediumCount || 0);
    countLow.textContent = String(metrics.lowCount || 0);
    findingsCount.textContent = String(findings ? findings.length : 0);

    renderFindings(findings || []);
  }

  function renderFindings(findings) {
    findingsList.textContent = '';

    if (!findings || findings.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      if (isAuthorized) {
        if (Number(metricQuestions.textContent) > 0) {
          empty.innerHTML = '<strong>🟢 NO CLIENT-SIDE ANSWER KEY DETECTED</strong><br><small style="color: #64748b; margin-top: 4px; display: block;">This assessment appears to grade server-side. No client-side grading metadata was leaked.</small>';
        } else {
          empty.textContent = 'No questions detected on this page.';
        }
      } else {
        empty.textContent = 'Audit disabled. Authorize this site to view findings.';
      }
      findingsList.appendChild(empty);
      return;
    }

    for (const f of findings) {
      const card = document.createElement('div');
      card.className = `finding-card finding-card-${(f.confidence || 'low').toLowerCase()}`;

      // Card Header
      const header = document.createElement('div');
      header.className = 'finding-card-header';

      const qTitle = document.createElement('div');
      qTitle.className = 'finding-card-question';
      qTitle.textContent = f.questionText || (f.questionId ? `Question #${f.questionId}` : 'MCQ Item');

      const badge = document.createElement('span');
      badge.className = `finding-badge finding-badge-${(f.confidence || 'low').toLowerCase()}`;
      badge.textContent = f.confidence;

      header.appendChild(qTitle);
      header.appendChild(badge);
      card.appendChild(header);

      // Card Answer
      const answerDiv = document.createElement('div');
      answerDiv.className = 'finding-card-answer';
      
      const label = document.createElement('span');
      label.textContent = 'Correct option: ';
      const val = document.createElement('strong');
      val.textContent = f.displayAnswer || String(f.answerValue);

      answerDiv.appendChild(label);
      answerDiv.appendChild(val);
      card.appendChild(answerDiv);

      // Card Evidence
      const evidenceDiv = document.createElement('div');
      evidenceDiv.className = 'finding-card-evidence';
      evidenceDiv.style.display = showEvidence ? 'block' : 'none';

      const sourceDiv = document.createElement('div');
      sourceDiv.textContent = `Source: ${f.source || 'Client payload'}`;

      const detailDiv = document.createElement('div');
      detailDiv.textContent = `Evidence: ${f.evidence || 'Application data match'}`;

      evidenceDiv.appendChild(sourceDiv);
      evidenceDiv.appendChild(detailDiv);
      card.appendChild(evidenceDiv);

      findingsList.appendChild(card);
    }
  }

  function renderUnauthorizedState() {
    renderMetrics(null, []);
    findingsList.textContent = '';
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'Auditing is not enabled for this site. Click "Authorize Audit For This Site" to inspect.';
    findingsList.appendChild(empty);
  }

  function renderNoTabState() {
    siteDomain.textContent = 'Unavailable (non-web page)';
    auditBadge.className = 'audit-badge audit-unauthorized';
    auditBadge.textContent = 'INACTIVE';
    auditNotice.textContent = 'Navigate to a quiz or assessment webpage to activate the inspector.';
    btnToggleAuth.disabled = true;
    btnScan.disabled = true;
    btnRescan.disabled = true;
    renderMetrics(null, []);
  }

  async function sendMessageToTab(message) {
    if (typeof chrome === 'undefined' || !chrome.tabs) return null;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) return null;

      return await new Promise((resolve) => {
        chrome.tabs.sendMessage(tab.id, message, (response) => {
          if (chrome.runtime.lastError) {
            resolve(null);
          } else {
            resolve(response);
          }
        });
      });
    } catch {
      return null;
    }
  }
});
