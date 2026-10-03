/**
 * QuizKey Inspector - Central Detector
 * 
 * Orchestrates DOM, Script, Storage, and Network analyzers
 * against the target webpage and correlates findings to on-screen questions.
 */

import { DomAnalyzer } from '../analysis/dom-analyzer.js';
import { ScriptAnalyzer } from '../analysis/script-analyzer.js';
import { StorageAnalyzer } from '../analysis/storage-analyzer.js';
import { Correlator } from '../analysis/correlator.js';
import { ConfidenceLevel } from '../shared/types.js';

export class Detector {
  constructor() {
    this.networkFindings = [];
    this.cachedResults = null;
    this.lastScanTime = 0;
  }

  /**
   * Registers network findings passively captured from the page session
   * @param {Array<Object>} findings 
   */
  addNetworkFindings(findings) {
    if (Array.isArray(findings)) {
      this.networkFindings.push(...findings);
    }
  }

  /**
   * Clears accumulated findings and cache
   */
  clear() {
    this.networkFindings = [];
    this.cachedResults = null;
    this.lastScanTime = 0;
  }

  /**
   * Performs an inspection pass of the current page environment
   * @param {Document} [doc=document] 
   * @param {Window} [win=window] 
   * @returns {Object} Scan results and metrics
   */
  scan(doc = typeof document !== 'undefined' ? document : null, win = typeof window !== 'undefined' ? window : null) {
    if (!doc) {
      return {
        domQuestions: [],
        findings: [],
        metrics: {
          questionsDetected: 0,
          answerMappingsCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          hasExposure: false,
          statusText: 'NO QUESTIONS DETECTED'
        }
      };
    }

    // 1. Identify questions already rendered on the page
    const domQuestions = DomAnalyzer.extractQuestions(doc);

    // 2. Safely inspect inline scripts and embedded JSON
    const scriptTags = Array.from(doc.querySelectorAll('script'));
    const scriptFindings = ScriptAnalyzer.analyzeScripts(scriptTags);

    // 3. Inspect browser storage
    const storageFindings = StorageAnalyzer.analyzeStorage(win);

    // 4. Combine all passively discovered findings
    const allRawFindings = [
      ...scriptFindings,
      ...storageFindings,
      ...this.networkFindings
    ];

    // 5. Correlate raw findings with on-screen questions
    const correlatedFindings = Correlator.correlate(domQuestions, allRawFindings);

    // 6. Aggregate metrics
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const f of correlatedFindings) {
      if (f.confidence === ConfidenceLevel.HIGH) highCount++;
      else if (f.confidence === ConfidenceLevel.MEDIUM) mediumCount++;
      else if (f.confidence === ConfidenceLevel.LOW) lowCount++;
    }

    const hasExposure = (highCount > 0 || mediumCount > 0);

    let statusText = 'NO QUESTIONS DETECTED';
    if (domQuestions.length > 0) {
      statusText = hasExposure
        ? 'CLIENT-SIDE ANSWER KEY DETECTED'
        : 'NO CLIENT-SIDE ANSWER KEY DETECTED';
    }

    const results = {
      domQuestions: domQuestions,
      rawFindingsCount: allRawFindings.length,
      findings: correlatedFindings,
      metrics: {
        questionsDetected: domQuestions.length,
        answerMappingsCount: correlatedFindings.length,
        highCount: highCount,
        mediumCount: mediumCount,
        lowCount: lowCount,
        hasExposure: hasExposure,
        statusText: statusText
      },
      timestamp: Date.now()
    };

    this.cachedResults = results;
    this.lastScanTime = Date.now();
    return results;
  }
}
