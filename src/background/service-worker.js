/**
 * QuizKey Inspector - Background Service Worker
 * 
 * Manifest V3 Service Worker:
 * - Manages extension toolbar badge based on authorized audit findings
 * - Listens for tab activation and metric updates
 * - 100% local operation: Zero telemetry, zero external network requests.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('[QuizKey Inspector] Installed successfully.');
  // By default, initialize empty authorized domains list or include localhost for testing
  chrome.storage.local.get(['authorizedDomains'], (data) => {
    if (!data.authorizedDomains) {
      chrome.storage.local.set({ authorizedDomains: ['localhost', '127.0.0.1'] });
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'UPDATE_SCAN_METRICS' && sender.tab) {
    const tabId = sender.tab.id;
    const metrics = message.metrics;
    const isAuthorized = message.isAuthorized;

    if (tabId) {
      updateBadge(tabId, metrics, isAuthorized);
    }
    sendResponse({ success: true });
  }
  return true;
});

function updateBadge(tabId, metrics, isAuthorized) {
  if (!tabId || !chrome.action) return;

  if (!isAuthorized || !metrics) {
    chrome.action.setBadgeText({ tabId: tabId, text: '' });
    return;
  }

  const count = metrics.answerMappingsCount || 0;
  const highCount = metrics.highCount || 0;

  if (count > 0) {
    chrome.action.setBadgeText({ tabId: tabId, text: String(count) });
    chrome.action.setBadgeBackgroundColor({
      tabId: tabId,
      color: highCount > 0 ? '#ef4444' : '#f59e0b'
    });
  } else if (metrics.questionsDetected > 0) {
    chrome.action.setBadgeText({ tabId: tabId, text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#10b981' });
  } else {
    chrome.action.setBadgeText({ tabId: tabId, text: '' });
  }
}
