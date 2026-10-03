/**
 * Assessment Security Scanner - JSON & Application State Analyzer
 * 
 * Recursively inspects JavaScript objects, JSON trees, and application state
 * to identify structured assessment payloads containing grading data or answer keys.
 */

import { ExposureCategory, ConfidenceLevel } from '../shared/types.js';
import { parseOptionIndex } from '../shared/utils.js';
import { EncodingAnalyzer } from './encoding-analyzer.js';

export class JsonAnalyzer {
  /**
   * Main entry point: recursively analyzes an arbitrary object or array
   * 
   * @param {any} root 
   * @param {string} sourceName - e.g. "API Response: /api/quiz", "localStorage", "Inline Script"
   * @param {number} [maxDepth=10]
   * @returns {Array<Object>} list of raw candidate findings
   */
  static analyze(root, sourceName = 'Application State', maxDepth = 10) {
    if (!root || typeof root !== 'object') {
      return [];
    }

    const findings = [];
    const visited = new WeakSet();

    const traverse = (current, depth, path) => {
      if (!current || typeof current !== 'object' || depth > maxDepth) {
        return;
      }

      if (visited.has(current)) {
        return;
      }
      visited.add(current);

      // Check if the current object represents an assessment question with answers
      const questionFinding = this.checkQuestionObject(current, sourceName, path);
      if (questionFinding) {
        findings.push(questionFinding);
      }

      // Check if the current object represents an answer-key dictionary
      const keyMapFindings = this.checkAnswerKeyDictionary(current, sourceName, path);
      if (keyMapFindings.length > 0) {
        findings.push(...keyMapFindings);
      }

      // Recurse on array elements or object properties
      if (Array.isArray(current)) {
        for (let i = 0; i < current.length; i++) {
          traverse(current[i], depth + 1, `${path}[${i}]`);
        }
      } else {
        for (const [key, val] of Object.entries(current)) {
          // If value is a string, check if it's encoded JSON or Base64
          if (typeof val === 'string' && val.length > 4) {
            const decodings = EncodingAnalyzer.analyzeValue(val);
            for (const dec of decodings) {
              if (dec.isJson && dec.decoded && typeof dec.decoded === 'object') {
                traverse(dec.decoded, depth + 1, `${path}.${key}[decoded_${dec.type}]`);
              }
            }
          } else if (val && typeof val === 'object') {
            traverse(val, depth + 1, `${path}.${key}`);
          }
        }
      }
    };

    traverse(root, 0, 'root');
    return findings;
  }

  /**
   * Checks if an object represents an assessment item with an embedded answer
   * @param {Object} obj 
   * @param {string} source 
   * @param {string} path 
   * @returns {Object|null}
   */
  static checkQuestionObject(obj, source, path) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;

    // Detect question text/prompt property
    const questionKeys = ['question', 'prompt', 'text', 'questionText', 'title', 'q', 'itemText'];
    let questionText = null;
    let questionKeyFound = null;

    for (const key of questionKeys) {
      if (typeof obj[key] === 'string' && obj[key].trim().length > 0) {
        questionText = obj[key].trim();
        questionKeyFound = key;
        break;
      }
    }

    // Detect question ID
    const idKeys = ['id', 'questionId', 'qid', 'itemId', 'key', '_id'];
    let questionId = null;
    for (const key of idKeys) {
      if (obj[key] !== undefined && obj[key] !== null) {
        questionId = String(obj[key]);
        break;
      }
    }

    // Detect options list
    const optionsKeys = ['options', 'choices', 'answers', 'choicesList', 'alternatives', 'items'];
    let options = null;
    let optionsKeyFound = null;

    for (const key of optionsKeys) {
      if (Array.isArray(obj[key]) && obj[key].length >= 2) {
        options = obj[key];
        optionsKeyFound = key;
        break;
      }
    }

    // Even if options is not an array, if questionText exists and answer key exists:
    // Check answer indicator properties
    const answerIndexKeys = [
      'correctIndex', 'correct_index', 'solutionIndex', 'solution_index',
      'correctOptionIndex', 'answerIndex', 'answer_index', 'correctIdx'
    ];

    const answerValueKeys = [
      'correctAnswer', 'correct_answer', 'correctOption', 'correct_option',
      'correctChoice', 'correct_choice', 'answerKey', 'answer_key',
      'solution', 'rightAnswer', 'validOption', 'correct', 'answer'
    ];

    let answerValue = null;
    let answerIndex = null;
    let evidence = null;

    // 1. Check explicit answerIndex keys
    for (const key of answerIndexKeys) {
      if (obj[key] !== undefined && obj[key] !== null) {
        const parsed = Number(obj[key]);
        if (!isNaN(parsed)) {
          answerIndex = parsed;
          answerValue = options && options[parsed] !== undefined
            ? (typeof options[parsed] === 'object' ? (options[parsed].text || options[parsed].value) : options[parsed])
            : `Option ${parsed + 1}`;
          evidence = `Property "${key}": ${obj[key]}`;
          break;
        }
      }
    }

    // 2. Check explicit answerValue keys
    if (answerValue === null) {
      for (const key of answerValueKeys) {
        // Skip generic "answer" or "correct" if it's a boolean or not indicative
        if (obj[key] !== undefined && obj[key] !== null) {
          const val = obj[key];

          // If it's a boolean, might be isCorrect on a question? Usually on option, not question.
          if (typeof val === 'boolean') continue;

          // If it's a number, it could be an index or numeric answer
          if (typeof val === 'number') {
            if (options && val >= 0 && val < options.length) {
              answerIndex = val;
              const opt = options[val];
              answerValue = typeof opt === 'object' ? (opt.text || opt.value) : opt;
            } else {
              answerValue = val;
            }
            evidence = `Property "${key}": ${val}`;
            break;
          }

          // If string or other
          if (typeof val === 'string' && val.trim().length > 0) {
            // Check if string is Base64 encoded JSON
            const decodings = EncodingAnalyzer.analyzeValue(val);
            let finalVal = val;
            let encodedEvidence = '';
            for (const dec of decodings) {
              if (dec.type === 'base64') {
                finalVal = dec.isJson && dec.decoded?.correct ? dec.decoded.correct : dec.decoded;
                encodedEvidence = ` (Base64 decoded from "${val}")`;
                break;
              }
            }

            answerValue = finalVal;
            // 1. Check if value matches an option text in the options array
            if (options && options.length > 0) {
              const normFinal = String(finalVal).trim().toLowerCase();
              const matchIdx = options.findIndex(o => {
                const optStr = typeof o === 'object' && o !== null ? (o.text || o.value || o.label || '') : String(o);
                return optStr.trim().toLowerCase() === normFinal;
              });
              if (matchIdx !== -1) {
                answerIndex = matchIdx;
              }
            }

            // 2. If not matched, check if value maps to a letter index ('A' -> 0, 'B' -> 1)
            if (answerIndex === null) {
              const idx = parseOptionIndex(String(finalVal));
              if (idx !== null && options && idx < options.length) {
                answerIndex = idx;
              }
            }
            evidence = `Property "${key}": "${val}"${encodedEvidence}`;
            break;
          }
        }
      }
    }

    // 3. Check if options themselves contain an `isCorrect` or `correct: true` flag
    if (answerValue === null && options) {
      for (let i = 0; i < options.length; i++) {
        const opt = options[i];
        if (opt && typeof opt === 'object') {
          if (opt.isCorrect === true || opt.is_correct === true || opt.correct === true || opt.correct === 1) {
            answerIndex = i;
            answerValue = opt.text || opt.value || opt.label || `Option ${i + 1}`;
            evidence = `Option[${i}] has flag isCorrect: true`;
            break;
          }
        }
      }
    }

    // If we have found an answer, build the normalized finding!
    if (answerValue !== null || answerIndex !== null) {
      // Normalize options to string array if present
      const normalizedOptions = options ? options.map(o => {
        if (typeof o === 'object' && o !== null) {
          return String(o.text || o.value || o.label || JSON.stringify(o));
        }
        return String(o);
      }) : [];

      return {
        category: ExposureCategory.ANSWER_KEY,
        questionId: questionId,
        questionText: questionText,
        options: normalizedOptions,
        answerValue: answerValue,
        answerIndex: answerIndex,
        source: source,
        path: path,
        evidence: evidence || `Grading data present at ${path}`,
        structural: true
      };
    }

    return null;
  }

  /**
   * Checks if an object represents an answer-key mapping (e.g. { "1": "B", "2": "C" })
   * @param {Object} obj 
   * @param {string} source 
   * @param {string} path 
   * @returns {Array<Object>}
   */
  static checkAnswerKeyDictionary(obj, source, path) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return [];

    const findings = [];
    const keyPatterns = /^(answer[_-]?keys?|solutions?|correct[_-]?answers?)$/i;

    for (const [prop, val] of Object.entries(obj)) {
      if (keyPatterns.test(prop) && val && typeof val === 'object') {
        if (Array.isArray(val)) {
          // e.g. solutions: [1, 2, 0, 3] or solutions: ["B", "C", "A"]
          val.forEach((ans, idx) => {
            findings.push({
              category: ExposureCategory.ANSWER_KEY,
              questionId: idx + 1,
              questionText: null,
              answerValue: ans,
              answerIndex: typeof ans === 'number' ? ans : parseOptionIndex(String(ans)),
              source: source,
              path: `${path}.${prop}[${idx}]`,
              evidence: `Answer list "${prop}[${idx}]": ${ans}`,
              structural: false
            });
          });
        } else {
          // e.g. answerKey: { "1": "B", "2": "UDP" }
          for (const [qId, ans] of Object.entries(val)) {
            findings.push({
              category: ExposureCategory.ANSWER_KEY,
              questionId: qId,
              questionText: null,
              answerValue: ans,
              answerIndex: typeof ans === 'number' ? ans : parseOptionIndex(String(ans)),
              source: source,
              path: `${path}.${prop}.${qId}`,
              evidence: `Answer map "${prop}.${qId}": ${ans}`,
              structural: false
            });
          }
        }
      }
    }

    return findings;
  }
}
