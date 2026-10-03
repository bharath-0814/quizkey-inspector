/**
 * QuizKey Inspector - Overlay Renderer
 * 
 * Injects non-destructive, accessible security-audit overlays
 * directly beneath vulnerable questions on the inspected page.
 * 
 * STRICT RULES:
 * 1. Never clicks, selects, or checks radio/checkbox inputs.
 * 2. Never submits any form or assessment.
 * 3. Never alters target page state or functions.
 * 4. Safe against XSS: uses document.createElement and textContent exclusively.
 */

import { ConfidenceLevel } from '../shared/types.js';
import { createElement } from '../shared/utils.js';

export class Renderer {
  /**
   * Renders security findings onto the inspected page
   * @param {Array<Object>} findings 
   * @param {boolean} [isAuthorized=true]
   */
  static render(findings, isAuthorized = true) {
    // Remove any previously injected overlays and highlights
    this.clear();

    if (!isAuthorized || !Array.isArray(findings)) return;

    for (const finding of findings) {
      // Only render overlay for HIGH or MEDIUM confidence findings
      if (finding.confidence === ConfidenceLevel.HIGH || finding.confidence === ConfidenceLevel.MEDIUM) {
        this.renderQuestionOverlay(finding);
      }
    }
  }

  /**
   * Injects the security overlay for a single question
   * @param {Object} finding 
   */
  static renderQuestionOverlay(finding) {
    const q = finding.domQuestion;
    if (!q || !q.element) return;

    // Check if overlay already exists
    if (q.element.querySelector('.quizkey-inspector-overlay')) return;

    // 1. Visually highlight the identified option
    if (finding.matchedOption && finding.matchedOption.element) {
      finding.matchedOption.element.classList.add('quizkey-highlighted-option');
      finding.matchedOption.element.setAttribute('data-quizkey-highlighted', 'true');
    }

    // 2. Build the overlay panel matching the exact format:
    // ┌─────────────────────────────────┐
    // │ 🔎 QUIZKEY INSPECTOR            │
    // │                                 │
    // │ Client-side answer exposed      │
    // │                                 │
    // │ Correct option: B. UDP          │
    // │ Confidence: HIGH                │
    // │                                 │
    // │ Evidence: API response          │
    // └─────────────────────────────────┘

    const overlay = createElement('div', {
      className: `quizkey-inspector-overlay quizkey-confidence-${finding.confidence.toLowerCase()}`,
      role: 'region',
      'aria-label': 'QuizKey Inspector Audit Result',
      'data-quizkey-overlay': 'true'
    });

    // Header: 🔎 QUIZKEY INSPECTOR
    const header = createElement('div', { className: 'quizkey-overlay-header' }, [
      createElement('span', { className: 'quizkey-overlay-icon' }, '🔎'),
      createElement('strong', { className: 'quizkey-overlay-title' }, ' QUIZKEY INSPECTOR')
    ]);

    // Subtitle: AUTHOR ANSWER KEY EXPOSED
    const subtitle = createElement('div', { className: 'quizkey-overlay-subtitle' }, 'AUTHOR ANSWER KEY EXPOSED');

    // Body Grid
    const body = createElement('div', { className: 'quizkey-overlay-body' });

    // Correct Option
    const correctOptRow = createElement('div', { className: 'quizkey-overlay-row' }, [
      createElement('span', { className: 'quizkey-overlay-label' }, 'Correct option: '),
      createElement('strong', { className: 'quizkey-overlay-answer' }, finding.displayAnswer || String(finding.answerValue))
    ]);
    body.appendChild(correctOptRow);

    // Confidence
    const confidenceBadge = createElement('span', {
      className: `quizkey-badge quizkey-badge-${finding.confidence.toLowerCase()}`
    }, finding.confidence);
    const confidenceRow = createElement('div', { className: 'quizkey-overlay-row' }, [
      createElement('span', { className: 'quizkey-overlay-label' }, 'Confidence: '),
      confidenceBadge
    ]);
    body.appendChild(confidenceRow);

    // Evidence
    const evidenceText = finding.evidence || finding.source || 'Client payload';
    const evidenceRow = createElement('div', { className: 'quizkey-overlay-row' }, [
      createElement('span', { className: 'quizkey-overlay-label' }, 'Evidence: '),
      createElement('span', { className: 'quizkey-overlay-evidence' }, evidenceText)
    ]);
    body.appendChild(evidenceRow);

    if (finding.questionId) {
      const qIdRow = createElement('div', { className: 'quizkey-overlay-row quizkey-overlay-meta' }, [
        createElement('span', { className: 'quizkey-overlay-label' }, 'Question ID: '),
        createElement('span', {}, String(finding.questionId))
      ]);
      body.appendChild(qIdRow);
    }

    overlay.appendChild(header);
    overlay.appendChild(subtitle);
    overlay.appendChild(body);

    // 3. Inject directly underneath the question's options
    const lastOption = q.options && q.options.length > 0 ? q.options[q.options.length - 1].element : null;
    if (lastOption && lastOption.parentElement && lastOption.parentElement !== q.element) {
      lastOption.parentElement.insertAdjacentElement('afterend', overlay);
    } else {
      q.element.appendChild(overlay);
    }
  }

  /**
   * Removes all injected overlays and option highlights from the DOM
   */
  static clear() {
    const overlays = document.querySelectorAll('[data-quizkey-overlay="true"], .quizkey-inspector-overlay');
    overlays.forEach(o => o.remove());

    const highlighted = document.querySelectorAll('[data-quizkey-highlighted="true"], .quizkey-highlighted-option');
    highlighted.forEach(el => {
      el.classList.remove('quizkey-highlighted-option');
      el.removeAttribute('data-quizkey-highlighted');
    });
  }
}
