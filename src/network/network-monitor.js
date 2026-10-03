/**
 * QuizKey Inspector - Network Monitor
 * 
 * Runs in the target page's MAIN world at document_start.
 * Passively observes legitimate network responses naturally received by the browser session.
 * 
 * RULES:
 * 1. ZERO additional or exploratory requests are made.
 * 2. Original requests and responses are completely unaffected.
 * 3. Only inspects naturally received payloads.
 */

(function initNetworkMonitor() {
  if (window.__quizkey_monitor_installed__) return;
  window.__quizkey_monitor_installed__ = true;

  const EVENT_NAME = '__quizkey_network_data__';

  function dispatchPayload(url, method, data) {
    try {
      const event = new CustomEvent(EVENT_NAME, {
        detail: {
          url: String(url || ''),
          method: String(method || 'GET').toUpperCase(),
          data: data,
          timestamp: Date.now()
        }
      });
      document.dispatchEvent(event);
    } catch {
      // ignore
    }
  }

  function isJsonContent(contentType, text) {
    if (contentType && contentType.toLowerCase().includes('json')) return true;
    if (typeof text === 'string') {
      const trimmed = text.trim();
      return (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
             (trimmed.startsWith('[') && trimmed.endsWith(']'));
    }
    return false;
  }

  // 1. Intercept window.fetch
  if (typeof window.fetch === 'function') {
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
      const response = await originalFetch.apply(this, args);
      try {
        const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
        const method = args[1]?.method || 'GET';

        // Clone response to avoid consuming the original body stream
        const clone = response.clone();
        const contentType = clone.headers.get('content-type') || '';

        clone.text().then(text => {
          if (isJsonContent(contentType, text)) {
            try {
              const data = JSON.parse(text);
              dispatchPayload(url, method, data);
            } catch {
              // Not valid JSON
            }
          }
        }).catch(() => {});
      } catch {
        // Never disrupt page execution
      }
      return response;
    };
  }

  // 2. Intercept XMLHttpRequest
  if (typeof window.XMLHttpRequest === 'function') {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__quizkey_req_url = url;
      this.__quizkey_req_method = method;
      return originalOpen.apply(this, [method, url, ...rest]);
    };

    XMLHttpRequest.prototype.send = function (...args) {
      this.addEventListener('load', function () {
        try {
          if (this.status >= 200 && this.status < 400) {
            const text = this.responseText;
            const contentType = this.getResponseHeader('content-type') || '';
            if (isJsonContent(contentType, text)) {
              try {
                const data = JSON.parse(text);
                dispatchPayload(this.__quizkey_req_url, this.__quizkey_req_method, data);
              } catch {
                // Not JSON
              }
            }
          }
        } catch {
          // ignore
        }
      });
      return originalSend.apply(this, args);
    };
  }
})();
