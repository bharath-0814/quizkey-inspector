/**
 * Assessment Security Scanner - DOM Analyzer
 * 
 * Inspects rendered DOM for assessment questions, options,
 * hidden inputs, data attributes, ARIA attributes, and embedded answer indicators.
 */

import { ExposureCategory } from '../shared/types.js';
import { normalizeText, parseOptionIndex } from '../shared/utils.js';
import { EncodingAnalyzer } from './encoding-analyzer.js';

export class DomAnalyzer {
  /**
   * Discovers all question containers rendered on the page
   * @param {Document|Element} root 
   * @returns {Array<Object>} List of extracted DOM questions
   */
  static extractQuestions(root = document) {
    const questions = [];

    // Selectors identifying question containers
    const questionSelectors = [
      '[data-question-id]',
      '[data-question]',
      '.question-container',
      '.question-item',
      '.question-card',
      '.assessment-question',
      '.assessment-item',
      '.quiz-question',
      '.quiz-item',
      '.mcq-question',
      '.mcq-item',
      'fieldset.question',
      'fieldset',
      '.question',
      '.problem'
    ];

    const potentialContainers = root.querySelectorAll(questionSelectors.join(', '));
    const processedNodes = new Set();

    for (const container of potentialContainers) {
      // Ensure we don't pick child question containers inside parent question containers
      if (processedNodes.has(container)) continue;

      // Ensure container has at least 2 options / inputs
      const options = this.extractOptions(container);
      if (options.length < 2) continue;

      // Extract question text
      const questionText = this.extractQuestionText(container);
      if (!questionText || questionText.length < 3) continue;

      // Extract question ID
      const questionId = this.extractQuestionId(container);

      // Check for direct DOM grading flags on question or options
      const domFindings = this.checkDomGradingFlags(container, questionId, questionText, options);

      questions.push({
        element: container,
        questionId: questionId,
        questionText: questionText,
        normalizedText: normalizeText(questionText),
        options: options,
        domFindings: domFindings
      });

      processedNodes.add(container);
    }

    // Fallback: If no standard containers matched, look for form radio groups
    if (questions.length === 0) {
      const fallbackQuestions = this.extractRadioGroupQuestions(root);
      questions.push(...fallbackQuestions);
    }

    return questions;
  }

  /**
   * Extracts question prompt/text from a container
   * @param {Element} container 
   * @returns {string}
   */
  static extractQuestionText(container) {
    // Check dedicated question title/prompt elements
    const textSelectors = [
      '.question-text',
      '.question-title',
      '.question-prompt',
      '.prompt',
      'legend',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      '.title',
      '[data-question-text]',
      'p'
    ];

    for (const sel of textSelectors) {
      const el = container.querySelector(sel);
      if (el) {
        // Exclude options if p or legend is inside
        const text = el.textContent.trim();
        if (text.length > 3) {
          return text;
        }
      }
    }

    // Fallback: clone container, remove options, and take remaining text
    try {
      const clone = container.cloneNode(true);
      const options = clone.querySelectorAll('input, label, .option, .choice, button');
      options.forEach(o => o.remove());
      const remaining = clone.textContent.trim();
      if (remaining.length > 3) return remaining;
    } catch {
      // ignore
    }

    return '';
  }

  /**
   * Extracts question ID from element attributes
   * @param {Element} container 
   * @returns {string|null}
   */
  static extractQuestionId(container) {
    const idAttrs = ['data-question-id', 'data-id', 'data-qid', 'id', 'name'];
    for (const attr of idAttrs) {
      const val = container.getAttribute(attr);
      if (val) {
        return val.replace(/^(?:question[_-]?|q[_-]?)/i, '');
      }
    }
    return null;
  }

  /**
   * Extracts individual option elements from a question container
   * @param {Element} container 
   * @returns {Array<Object>}
   */
  static extractOptions(container) {
    const options = [];

    // Selectors for option items
    const optionSelectors = [
      '.option',
      '.choice',
      '.quiz-option',
      '.answer-option',
      '.mcq-option',
      'label',
      '[data-option-id]',
      '[data-option]'
    ];

    let optionEls = Array.from(container.querySelectorAll(optionSelectors.join(', ')));

    // Filter out labels that are not options (e.g. empty or label for something else)
    if (optionEls.length < 2) {
      // Try finding radio inputs and their containers
      const radios = container.querySelectorAll('input[type="radio"], input[type="checkbox"]');
      if (radios.length >= 2) {
        optionEls = Array.from(radios).map(r => r.closest('label') || r.parentElement || r);
      }
    }

    // Deduplicate option elements
    const uniqueEls = [];
    const seen = new Set();
    for (const el of optionEls) {
      // Don't nest options inside each other
      if (!seen.has(el)) {
        uniqueEls.push(el);
        seen.add(el);
      }
    }

    uniqueEls.forEach((el, index) => {
      const rawText = el.textContent.trim();
      const normalized = normalizeText(rawText);
      const input = el.querySelector('input') || (el.tagName === 'INPUT' ? el : null);
      const value = input ? input.value : (el.getAttribute('data-value') || '');

      // Check letter prefix e.g. "B. UDP"
      const letterMatch = rawText.match(/^([A-H])[:.)-]\s*(.*)$/i);
      const letter = letterMatch ? letterMatch[1].toUpperCase() : String.fromCharCode(65 + index);
      const cleanOptionText = letterMatch ? letterMatch[2].trim() : rawText;

      options.push({
        element: el,
        inputElement: input,
        index: index,
        letter: letter,
        text: cleanOptionText,
        rawText: rawText,
        value: value,
        normalizedText: normalized,
        optionId: el.getAttribute('data-option-id') || el.id || value || String(index)
      });
    });

    return options;
  }

  /**
   * Inspects question and option DOM elements for direct answer flags
   * (e.g. data-correct="true", hidden answer inputs, etc.)
   * @param {Element} container 
   * @param {string|null} questionId 
   * @param {string} questionText 
   * @param {Array<Object>} options 
   * @returns {Array<Object>}
   */
  static checkDomGradingFlags(container, questionId, questionText, options) {
    const findings = [];

    // 1. Inspect hidden inputs inside container
    const hiddenInputs = container.querySelectorAll('input[type="hidden"]');
    for (const input of hiddenInputs) {
      const name = (input.name || input.id || '').toLowerCase();
      const val = input.value;
      if (!val) continue;

      if (/^(?:correct|answer|key|solution|correct_answer|correct_index)/i.test(name)) {
        // Check if value is Base64 encoded
        const b64 = EncodingAnalyzer.decodeBase64(val);
        let resolvedVal = val;
        let optIdx = null;

        if (b64.success) {
          if (b64.isJson && b64.parsedJson) {
            if (b64.parsedJson.correctIndex !== undefined) optIdx = Number(b64.parsedJson.correctIndex);
            resolvedVal = b64.parsedJson.answer || b64.parsedJson.correctAnswer || b64.parsedJson.correct || b64.decoded;
          } else {
            resolvedVal = b64.decoded;
            optIdx = parseOptionIndex(resolvedVal);
          }
        } else {
          optIdx = parseOptionIndex(val);
        }

        findings.push({
          category: ExposureCategory.HIDDEN_DOM_DATA,
          questionId: questionId,
          questionText: questionText,
          answerValue: resolvedVal,
          answerIndex: optIdx,
          source: `Hidden input: <input type="hidden" name="${input.name}">`,
          evidence: `Hidden input exposes answer value: "${val}"${b64.success ? ` (Decoded Base64: "${resolvedVal}")` : ''}`,
          domDirectAttribute: true
        });
      }
    }

    // 2. Inspect data-* attributes on the question container itself
    const qAttrs = container.attributes;
    for (let i = 0; i < qAttrs.length; i++) {
      const attr = qAttrs[i];
      const name = attr.name.toLowerCase();
      const val = attr.value;

      if (/^data-(?:correct|answer|solution|correct-index|correct-answer|answer-key)$/i.test(name)) {
        const b64 = EncodingAnalyzer.decodeBase64(val);
        let resolvedVal = val;
        let optIdx = null;

        if (b64.success) {
          if (b64.isJson && b64.parsedJson) {
            if (b64.parsedJson.correctIndex !== undefined) optIdx = Number(b64.parsedJson.correctIndex);
            resolvedVal = b64.parsedJson.answer || b64.parsedJson.correctAnswer || b64.parsedJson.correct || b64.decoded;
          } else {
            resolvedVal = b64.decoded;
            optIdx = parseOptionIndex(resolvedVal);
          }
        } else {
          optIdx = parseOptionIndex(val);
        }

        findings.push({
          category: ExposureCategory.HIDDEN_DOM_DATA,
          questionId: questionId,
          questionText: questionText,
          answerValue: resolvedVal,
          answerIndex: optIdx,
          source: `Question attribute [${attr.name}]`,
          evidence: `Container attribute "${attr.name}" = "${val}"${b64.success ? ` (Decoded Base64: "${resolvedVal}")` : ''}`,
          domDirectAttribute: true
        });
      }
    }

    // 3. Inspect individual option elements for correct flags
    for (const opt of options) {
      const el = opt.element;
      const attrs = el.attributes;
      let isFlagged = false;
      let flagEvidence = '';

      // Check attributes: data-correct="true", data-is-correct="1"
      for (let i = 0; i < attrs.length; i++) {
        const attr = attrs[i];
        const name = attr.name.toLowerCase();
        const val = attr.value.toLowerCase();

        if (/^data-(?:correct|is-correct|solution|right-choice)$/i.test(name)) {
          if (val === 'true' || val === '1' || val === 'correct') {
            isFlagged = true;
            flagEvidence = `Attribute [${attr.name}="${attr.value}"]`;
            break;
          }
        }
      }

      // Check CSS classes before grading: .is-correct, .correct-answer
      if (!isFlagged && el.classList) {
        if (el.classList.contains('is-correct') || el.classList.contains('correct-answer') || el.classList.contains('correct-option')) {
          isFlagged = true;
          flagEvidence = `CSS Class "${el.className}" on option element`;
        }
      }

      // Check ARIA attributes
      if (!isFlagged) {
        const ariaDesc = el.getAttribute('aria-description') || '';
        const ariaLabel = el.getAttribute('aria-label') || '';
        if (/correct/i.test(ariaDesc) || /correct/i.test(ariaLabel)) {
          isFlagged = true;
          flagEvidence = `ARIA attribute indicates correct option`;
        }
      }

      if (isFlagged) {
        findings.push({
          category: ExposureCategory.HIDDEN_DOM_DATA,
          questionId: questionId,
          questionText: questionText,
          answerValue: opt.text,
          answerIndex: opt.index,
          source: `Option DOM element (${opt.letter})`,
          evidence: flagEvidence,
          domDirectAttribute: true
        });
      }
    }

    return findings;
  }

  /**
   * Fallback extractor for radio button groups
   * @param {Document|Element} root 
   * @returns {Array<Object>}
   */
  static extractRadioGroupQuestions(root) {
    const radioGroups = new Map();
    const radios = root.querySelectorAll('input[type="radio"]');

    radios.forEach(r => {
      const name = r.name || 'default';
      if (!radioGroups.has(name)) {
        radioGroups.set(name, []);
      }
      radioGroups.get(name).push(r);
    });

    const questions = [];
    for (const [groupName, groupRadios] of radioGroups.entries()) {
      if (groupRadios.length < 2) continue;

      // Find common parent
      const parent = groupRadios[0].closest('form') || groupRadios[0].parentElement?.parentElement || document.body;
      const options = groupRadios.map((r, idx) => {
        const label = r.closest('label') || r.parentElement;
        const text = label ? label.textContent.trim() : r.value;
        return {
          element: label || r,
          inputElement: r,
          index: idx,
          letter: String.fromCharCode(65 + idx),
          text: text,
          rawText: text,
          value: r.value,
          normalizedText: normalizeText(text),
          optionId: r.value || String(idx)
        };
      });

      const questionText = this.extractQuestionText(parent) || `Question (${groupName})`;

      questions.push({
        element: parent,
        questionId: groupName,
        questionText: questionText,
        normalizedText: normalizeText(questionText),
        options: options,
        domFindings: []
      });
    }

    return questions;
  }
}
