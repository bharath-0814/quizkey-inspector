/**
 * Assessment Security Scanner - Confidence Engine
 * 
 * Multi-signal scoring algorithm to assess the confidence of detected
 * client-side grading data and filter out false positives.
 */

import { ConfidenceLevel, ScoreThresholds } from '../shared/types.js';

export class ConfidenceEngine {
  /**
   * Evaluates the confidence score based on correlation signals
   * 
   * Signals:
   * - exactQuestionIdMatch: +100
   * - exactQuestionTextMatch: +90
   * - normalizedQuestionTextMatch: +85
   * - exactOptionListMatch: +70
   * - answerMatchesOptionValue: +80
   * - answerIndexMatchesOption: +75
   * - domDirectAttribute: +95 (e.g. data-correct="true" on option element)
   * - structuralQuizRelationship: +50 (object containing question + options + answer together)
   * - keywordOnly: +30
   * 
   * @param {Object} signals 
   * @returns {{ score: number, level: string, reasons: Array<string> }}
   */
  static evaluateSignals(signals) {
    let score = 0;
    const reasons = [];

    if (signals.domDirectAttribute) {
      score = Math.max(score, 95);
      reasons.push('Direct DOM attribute on option element (score +95)');
    }

    if (signals.exactQuestionIdMatch && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
      score = Math.max(score, 100);
      reasons.push('Exact question ID match with correlated option (score: 100)');
    } else if (signals.exactQuestionIdMatch) {
      score = Math.max(score, 75);
      reasons.push('Question ID match (score: 75)');
    }

    if (signals.exactQuestionTextMatch && signals.answerIndexMatchesOption) {
      score = Math.max(score, 90);
      reasons.push('Exact question text match with answer index (score: 90)');
    } else if (signals.exactQuestionTextMatch && (signals.answerMatchesOptionValue || signals.idMatchOnOption)) {
      score = Math.max(score, 85);
      reasons.push('Exact question text match with answer value (score: 85)');
    } else if (signals.normalizedQuestionTextMatch && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
      score = Math.max(score, 80);
      reasons.push('Normalized question text match with answer (score: 80)');
    }

    if (signals.exactOptionListMatch && (signals.answerIndexMatchesOption || signals.answerMatchesOptionValue)) {
      score = Math.max(score, 85);
      reasons.push('Full option list match with answer (score: 85)');
    }

    if (signals.structuralQuizRelationship && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
      score = Math.max(score, 80);
      reasons.push('Structured assessment payload containing question, options, and grading key');
    }

    if (signals.scoringRule) {
      if (signals.exactQuestionIdMatch || signals.exactQuestionTextMatch) {
        score = Math.max(score, 85);
        reasons.push('Author response scoring metadata correlated with question (score: 85)');
      } else {
        score = Math.max(score, 65);
        reasons.push('Author response scoring metadata detected without exact question match (score: 65)');
      }
    }

    // Penalties / False Positive guards
    if (signals.isInstructionOrPrompt) {
      // e.g. text containing "Choose the correct answer below"
      score = Math.min(score, 20);
      reasons.push('Demoted: text appears to be general instruction/prompt, not answer key');
    }

    if (signals.keywordOnly) {
      score = Math.max(score, 30);
      reasons.push('Keyword match without structural relationship (score: 30)');
    }

    // Classify into ConfidenceLevel
    let level = ConfidenceLevel.NONE;
    if (score >= ScoreThresholds.HIGH) {
      level = ConfidenceLevel.HIGH;
    } else if (score >= ScoreThresholds.MEDIUM) {
      level = ConfidenceLevel.MEDIUM;
    } else if (score >= ScoreThresholds.LOW) {
      level = ConfidenceLevel.LOW;
    }

    return { score, level, reasons };
  }

  /**
   * Determines if a text snippet is likely a benign UI label or instruction
   * rather than an actual answer key
   * @param {string} text 
   * @returns {boolean}
   */
  static isFalsePositiveText(text) {
    if (!text || typeof text !== 'string') return false;
    const lower = text.toLowerCase();
    const benignPatterns = [
      /select the correct answer/i,
      /choose the correct/i,
      /which of the following is correct/i,
      /indicate the correct option/i,
      /mark the correct/i,
      /all of the above are correct/i, // benign if in option text
      /none of the above is correct/i
    ];

    // If it's an instruction
    if (/^(please\s+)?(select|choose|pick|find|identify|mark)\s+the\s+correct/i.test(lower)) {
      return true;
    }

    return false;
  }
}
