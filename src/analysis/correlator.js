/**
 * Assessment Security Scanner - Correlation Engine
 * 
 * Correlates detected raw findings from all analyzers (DOM, scripts, storage, network)
 * with the rendered DOM assessment questions.
 * Maps detected answer keys to specific options and computes confidence levels.
 */

import { ConfidenceEngine } from './confidence.js';
import { ConfidenceLevel, ExposureCategory } from '../shared/types.js';
import { normalizeText, calculateTextSimilarity, parseOptionIndex } from '../shared/utils.js';

export class Correlator {
  /**
   * Correlates raw findings with DOM questions
   * 
   * @param {Array<Object>} domQuestions 
   * @param {Array<Object>} rawFindings 
   * @returns {Array<Object>} List of correlated findings
   */
  static correlate(domQuestions, rawFindings) {
    const results = [];
    if (!domQuestions || domQuestions.length === 0) return results;

    for (let qIdx = 0; qIdx < domQuestions.length; qIdx++) {
      const q = domQuestions[qIdx];
      let bestMatch = null;
      let highestScore = 0;

      // 1. First check if DOM question has direct findings from DomAnalyzer
      if (q.domFindings && q.domFindings.length > 0) {
        for (const df of q.domFindings) {
          const correlated = this.correlateSingle(q, df, qIdx);
          if (correlated && correlated.score > highestScore) {
            highestScore = correlated.score;
            bestMatch = correlated;
          }
        }
      }

      // 2. Correlate against all collected raw findings
      for (const finding of rawFindings) {
        const correlated = this.correlateSingle(q, finding, qIdx);
        if (correlated && correlated.score > highestScore) {
          highestScore = correlated.score;
          bestMatch = correlated;
        }
      }

      if (bestMatch && bestMatch.confidence !== ConfidenceLevel.NONE) {
        results.push(bestMatch);
      }
    }

    return results;
  }

  /**
   * Attempts to correlate a single finding with a single DOM question
   * @param {Object} q 
   * @param {Object} finding 
   * @param {number} qIdx 
   * @returns {Object|null}
   */
  static correlateSingle(q, finding, qIdx) {
    const signals = {
      exactQuestionIdMatch: false,
      exactQuestionTextMatch: false,
      normalizedQuestionTextMatch: false,
      exactOptionListMatch: false,
      answerMatchesOptionValue: false,
      answerIndexMatchesOption: false,
      idMatchOnOption: false,
      domDirectAttribute: !!finding.domDirectAttribute,
      structuralQuizRelationship: !!finding.structural,
      scoringRule: !!finding.isScoringRule,
      keywordOnly: false,
      isInstructionOrPrompt: false
    };

    // 1. Question ID matching
    if (q.questionId && finding.questionId) {
      const qIdStr = String(q.questionId).trim();
      const findIdStr = String(finding.questionId).trim();
      if (qIdStr === findIdStr || qIdStr === `q${findIdStr}` || findIdStr === `q${qIdStr}`) {
        signals.exactQuestionIdMatch = true;
      }
    } else if (finding.questionId !== null && Number(finding.questionId) === qIdx + 1) {
      // 1-based sequential question index match
      signals.exactQuestionIdMatch = true;
    }

    // 2. Question text matching
    if (finding.questionText && q.questionText) {
      if (finding.questionText.trim() === q.questionText.trim()) {
        signals.exactQuestionTextMatch = true;
      } else {
        const similarity = calculateTextSimilarity(q.questionText, finding.questionText);
        if (similarity >= 0.85) {
          signals.normalizedQuestionTextMatch = true;
        } else if (similarity < 0.3 && !signals.exactQuestionIdMatch) {
          // Unrelated question
          return null;
        }
      }
    }

    // False positive check on question text or finding
    if (ConfidenceEngine.isFalsePositiveText(finding.questionText || q.questionText)) {
      signals.isInstructionOrPrompt = true;
    }

    // 3. Option list matching
    if (finding.options && Array.isArray(finding.options) && finding.options.length > 0) {
      let matchedCount = 0;
      for (const optText of finding.options) {
        const normOpt = normalizeText(String(optText));
        if (q.options.some(o => o.normalizedText === normOpt || (o.rawText || o.text || '').toLowerCase().includes(normOpt))) {
          matchedCount++;
        }
      }
      if (matchedCount >= 2 && matchedCount === finding.options.length) {
        signals.exactOptionListMatch = true;
      }
    }

    // 4. Resolve which DOM option corresponds to the answer
    let matchedOption = null;
    let targetIndex = null;

    // A. Match by explicit correctOptionId or correctResponseId
    const targetIds = [finding.correctOptionId, finding.correctResponseId].filter(Boolean).map(String);
    if (targetIds.length > 0) {
      for (const opt of q.options) {
        const optIds = [
          opt.optionId,
          opt.value,
          opt.element?.getAttribute ? opt.element.getAttribute('data-option-id') : null,
          opt.element?.getAttribute ? opt.element.getAttribute('data-response-id') : null,
          opt.element?.id,
          opt.inputElement?.value
        ].filter(Boolean).map(String);

        if (targetIds.some(tid => optIds.includes(tid))) {
          matchedOption = opt;
          targetIndex = opt.index;
          signals.answerMatchesOptionValue = true;
          signals.idMatchOnOption = true;
          break;
        }
      }
    }

    // B. Handle option order randomization:
    // If the author defined an options list and an answerIndex, determine the target answer
    // text/ID from author configuration FIRST, then correlate to rendered DOM options.
    const authorList = finding.authorOptions || finding.options;
    if (!matchedOption && authorList && Array.isArray(authorList) && finding.answerIndex !== null && finding.answerIndex !== undefined) {
      const authorItem = authorList[finding.answerIndex];
      if (authorItem !== undefined) {
        const authorTargetText = typeof authorItem === 'object' && authorItem !== null
          ? (authorItem.text || authorItem.value || authorItem.label || authorItem.content)
          : String(authorItem);

        const authorTargetId = typeof authorItem === 'object' && authorItem !== null
          ? (authorItem.id || authorItem.optionId || authorItem.responseId)
          : null;

        // Try ID match in DOM options
        if (authorTargetId) {
          const authorTargetIdStr = String(authorTargetId);
          for (const opt of q.options) {
            const optIds = [
              opt.optionId,
              opt.value,
              opt.element?.getAttribute ? opt.element.getAttribute('data-option-id') : null,
              opt.element?.getAttribute ? opt.element.getAttribute('data-response-id') : null,
              opt.element?.id,
              opt.inputElement?.value
            ].filter(Boolean).map(String);

            if (optIds.includes(authorTargetIdStr)) {
              matchedOption = opt;
              targetIndex = opt.index;
              signals.answerMatchesOptionValue = true;
              signals.idMatchOnOption = true;
              break;
            }
          }
        }

        // Try Text match in DOM options (handles shuffled/randomized order)
        if (!matchedOption && authorTargetText) {
          const normTarget = normalizeText(String(authorTargetText));
          for (const opt of q.options) {
            if (opt.normalizedText === normTarget ||
                (opt.text && opt.text.trim().toLowerCase() === String(authorTargetText).trim().toLowerCase()) ||
                opt.value === String(authorTargetText) ||
                (opt.rawText && opt.rawText.toLowerCase().includes(normTarget))) {
              matchedOption = opt;
              targetIndex = opt.index;
              signals.answerMatchesOptionValue = true;
              break;
            }
          }
        }
      }
    }

    // C. Match by finding.answerValue against DOM options
    if (!matchedOption && finding.answerValue !== null && finding.answerValue !== undefined) {
      const valStr = String(finding.answerValue).trim();
      const normVal = normalizeText(valStr);

      // 1. Single letter index ('A', 'B', 'C', 'D') when finding is a letter or number key
      if (valStr.length === 1 && /^[A-H]$/i.test(valStr)) {
        const letterIdx = parseOptionIndex(valStr);
        if (letterIdx !== null && letterIdx >= 0 && letterIdx < q.options.length) {
          targetIndex = letterIdx;
          matchedOption = q.options[letterIdx];
          signals.answerIndexMatchesOption = true;
        }
      }

      // 2. Exact or normalized option text match
      if (!matchedOption) {
        for (const opt of q.options) {
          if (opt.normalizedText === normVal || (opt.text && opt.text.trim().toLowerCase() === valStr.toLowerCase()) || opt.value === valStr) {
            matchedOption = opt;
            targetIndex = opt.index;
            signals.answerMatchesOptionValue = true;
            break;
          }
        }
      }

      // 3. Option ID or element attribute match
      if (!matchedOption) {
        for (const opt of q.options) {
          const optIds = [
            opt.optionId,
            opt.value,
            opt.element?.getAttribute ? opt.element.getAttribute('data-option-id') : null,
            opt.element?.getAttribute ? opt.element.getAttribute('data-response-id') : null,
            opt.element?.id,
            opt.inputElement?.value
          ].filter(Boolean).map(String);

          if (optIds.includes(valStr)) {
            matchedOption = opt;
            targetIndex = opt.index;
            signals.answerMatchesOptionValue = true;
            signals.idMatchOnOption = true;
            break;
          }
        }
      }
    }

    // D. Direct index fallback (only when no author list mismatch occurred)
    if (!matchedOption && finding.answerIndex !== null && finding.answerIndex !== undefined) {
      const idx = Number(finding.answerIndex);
      if (idx >= 0 && idx < q.options.length) {
        targetIndex = idx;
        matchedOption = q.options[idx];
        signals.answerIndexMatchesOption = true;
      }
    }

    // If no option could be mapped and no question matched, abort
    if (!signals.exactQuestionIdMatch && !signals.exactQuestionTextMatch && !signals.normalizedQuestionTextMatch && !signals.domDirectAttribute) {
      return null;
    }

    // Evaluate confidence score
    const evalResult = ConfidenceEngine.evaluateSignals(signals);

    // Build display answer string
    let displayAnswer = '';
    if (matchedOption) {
      displayAnswer = `Option ${matchedOption.index + 1} — ${matchedOption.text}`;
      if (matchedOption.letter && matchedOption.text) {
        displayAnswer = `${matchedOption.letter}. ${matchedOption.text}`;
      }
    } else if (finding.answerValue !== null) {
      displayAnswer = String(finding.answerValue);
    }

    return {
      category: finding.category || ExposureCategory.ANSWER_KEY,
      questionId: q.questionId || finding.questionId || `q_${qIdx + 1}`,
      questionText: q.questionText,
      domQuestion: q,
      matchedOption: matchedOption,
      answerValue: finding.answerValue,
      answerIndex: targetIndex,
      displayAnswer: displayAnswer,
      source: finding.source || 'Client-side application data',
      evidence: finding.evidence || 'Discovered in browser state',
      confidence: evalResult.level,
      score: evalResult.score,
      reasons: evalResult.reasons
    };
  }
}
