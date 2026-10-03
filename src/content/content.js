/**
 * QuizKey Inspector - Content Script Entry Point
 * 
 * Runs in the isolated world on target assessment/quiz pages.
 * Implements Authorized Audit Mode: only performs active auditing
 * and overlay injection on sites explicitly authorized by the auditor.
 */

import { Detector } from './detector.js';
import { Renderer } from './renderer.js';
import { DomObserver } from './observers.js';
import { NetworkAnalyzer } from '../analysis/network-analyzer.js';
import { getDomainFromUrl, isDomainAuthorized } from '../shared/utils.js';
import { AuditStatus } from '../shared/types.js';

class QuizKeyContentController {
  constructor() {
    this.detector = new Detector();
    this.observer = null;
    this.cleanupNetwork = null;
    this.isAuthorized = false;
    this.currentDomain = getDomainFromUrl(window.location.href);
    this.isInitialized = false;
  }

  async init() {
    if (this.isInitialized) return;
    this.isInitialized = true;

    // 1. Check if current domain is authorized for security auditing
    await this.checkAuthorization();

    // 2. Passively observe network responses from MAIN world monitor
    this.cleanupNetwork = NetworkAnalyzer.listenForNetworkEvents((networkFindings) => {
      this.detector.addNetworkFindings(networkFindings);
      if (this.isAuthorized) {
        this.runScan();
      }
    });

    // 3. Set up MutationObserver for dynamically loaded questions
    this.observer = new DomObserver(() => {
      if (this.isAuthorized) {
        this.runScan();
      }
    }, 250);
    this.observer.start(document.body);

    // 4. Listen for extension popup / background messaging
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        this.handleMessage(request, sendResponse);
        return true;
      });
    }

    // 5. If authorized, run initial scan
    if (this.isAuthorized) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => this.runScan());
      } else {
        this.runScan();
      }
    }
  }

  /**
   * Checks authorization status for the current domain
   */
  async checkAuthorization() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      try {
        const data = await chrome.storage.local.get(['authorizedDomains']);
        const domains = data.authorizedDomains || [];
        this.isAuthorized = isDomainAuthorized(this.currentDomain, domains);
      } catch {
        this.isAuthorized = false;
      }
    } else {
      // Default to unauthorized for safety
      this.isAuthorized = false;
    }
    return this.isAuthorized;
  }

  /**
   * Authorizes the current domain and starts scanning
   */
  async authorizeCurrentSite() {
    this.isAuthorized = true;
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      try {
        const data = await chrome.storage.local.get(['authorizedDomains']);
        const domains = data.authorizedDomains || [];
        if (!isDomainAuthorized(this.currentDomain, domains)) {
          domains.push(this.currentDomain);
          await chrome.storage.local.set({ authorizedDomains: domains });
        }
      } catch {
        // ignore
      }
    }
    return this.runScan();
  }

  /**
   * Disables audit mode for the current domain and cleans up
   */
  async disableCurrentSite() {
    this.isAuthorized = false;
    Renderer.clear();
    this.detector.clear();

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      try {
        const data = await chrome.storage.local.get(['authorizedDomains']);
        const domains = (data.authorizedDomains || []).filter(
          d => (d || '').toLowerCase() !== this.currentDomain.toLowerCase()
        );
        await chrome.storage.local.set({ authorizedDomains: domains });
      } catch {
        // ignore
      }
    }
    this.notifyBackground(null);
  }

  /**
   * Runs page inspection and renders overlays if authorized
   */
  runScan() {
    const results = this.detector.scan(document, window);

    if (this.isAuthorized) {
      Renderer.render(results.findings, true);
    } else {
      Renderer.clear();
    }

    this.notifyBackground(results.metrics);
    return results;
  }

  /**
   * Handles incoming extension messages
   */
  async handleMessage(request, sendResponse) {
    switch (request.action) {
      case 'GET_STATUS':
      case 'GET_SCAN_STATUS': {
        await this.checkAuthorization();
        const results = this.detector.cachedResults || this.detector.scan(document, window);
        sendResponse({
          success: true,
          isAuthorized: this.isAuthorized,
          currentDomain: this.currentDomain,
          metrics: results.metrics,
          findings: this.serializeFindings(results.findings)
        });
        break;
      }

      case 'AUTHORIZE_SITE': {
        const results = await this.authorizeCurrentSite();
        sendResponse({
          success: true,
          isAuthorized: true,
          currentDomain: this.currentDomain,
          metrics: results.metrics,
          findings: this.serializeFindings(results.findings)
        });
        break;
      }

      case 'DISABLE_SITE': {
        await this.disableCurrentSite();
        sendResponse({
          success: true,
          isAuthorized: false,
          currentDomain: this.currentDomain
        });
        break;
      }

      case 'SCAN_PAGE':
      case 'RESCAN': {
        await this.checkAuthorization();
        const results = this.runScan();
        sendResponse({
          success: true,
          isAuthorized: this.isAuthorized,
          currentDomain: this.currentDomain,
          metrics: results.metrics,
          findings: this.serializeFindings(results.findings)
        });
        break;
      }

      case 'CLEAR_FINDINGS': {
        this.detector.clear();
        Renderer.clear();
        sendResponse({ success: true });
        break;
      }

      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  }

  /**
   * Serializes findings safely without DOM node handles
   */
  serializeFindings(findings) {
    if (!Array.isArray(findings)) return [];
    return findings.map(f => ({
      category: f.category,
      questionId: f.questionId,
      questionText: f.questionText,
      answerValue: f.answerValue,
      answerIndex: f.answerIndex,
      displayAnswer: f.displayAnswer,
      source: f.source,
      evidence: f.evidence,
      confidence: f.confidence,
      score: f.score,
      reasons: f.reasons
    }));
  }

  /**
   * Notifies background worker to update toolbar badge
   */
  notifyBackground(metrics) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({
          action: 'UPDATE_SCAN_METRICS',
          isAuthorized: this.isAuthorized,
          metrics: metrics
        }).catch(() => {});
      } catch {
        // ignore
      }
    }
  }
}

const quizKeyContent = new QuizKeyContentController();
quizKeyContent.init();

export { quizKeyContent, QuizKeyContentController };
