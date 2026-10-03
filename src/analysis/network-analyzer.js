/**
 * Assessment Security Scanner - Network Analyzer
 * 
 * Analyzes network response payloads received from the passive network monitor.
 * Correlates API payloads with assessment questions and answers.
 */

import { JsonAnalyzer } from './json-analyzer.js';
import { ExposureCategory } from '../shared/types.js';

export class NetworkAnalyzer {
  /**
   * Analyzes an intercepted network payload
   * @param {{ url: string, method: string, data: any }} payload 
   * @returns {Array<Object>} List of candidate findings
   */
  static analyzeResponse(payload) {
    if (!payload || !payload.data) return [];

    const url = payload.url || 'API Endpoint';
    const source = `API Response: ${url}`;

    // Pass through JSON analyzer
    const findings = JsonAnalyzer.analyze(payload.data, source);

    // Enhance category with API_RESPONSE
    return findings.map(f => ({
      ...f,
      category: ExposureCategory.API_RESPONSE,
      endpoint: url
    }));
  }

  /**
   * Sets up event listener for the passive network monitor
   * @param {function(Array<Object>): void} onFindingsCallback 
   * @returns {function(): void} cleanup function
   */
  static listenForNetworkEvents(onFindingsCallback) {
    const handler = (event) => {
      try {
        const detail = event.detail;
        if (detail && detail.data) {
          const findings = this.analyzeResponse(detail);
          if (findings.length > 0 && typeof onFindingsCallback === 'function') {
            onFindingsCallback(findings);
          }
        }
      } catch {
        // ignore
      }
    };

    document.addEventListener('__quizkey_network_data__', handler);
    return () => {
      document.removeEventListener('__quizkey_network_data__', handler);
    };
  }
}
