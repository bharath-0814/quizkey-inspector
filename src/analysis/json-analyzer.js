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
    const optionsKeys = ['options', 'choices', 'answers', 'choicesList', 'alternatives', 'items', 'responses'];
    let options = null;
    let optionsKeyFound = null;

    for (const key of optionsKeys) {
      if (Array.isArray(obj[key]) && obj[key].length >= 2) {
        options = obj[key];
        optionsKeyFound = key;
        break;
      }
    }

    // Answer indicator keys
    const answerIndexKeys = [
      'correctIndex', 'correct_index', 'solutionIndex', 'solution_index',
      'correctOptionIndex', 'answerIndex', 'answer_index', 'correctIdx'
    ];

    const answerValueKeys = [
      'correctAnswer', 'correct_answer', 'correctOption', 'correct_option',
      'correctResponse', 'correct_response', 'correctChoice', 'correct_choice',
      'answerKey', 'answer_key', 'solution', 'rightAnswer', 'validOption',
      'correct', 'answer'
    ];

    let answerValue = null;
    let answerIndex = null;
    let correctOptionId = null;
    let correctResponseId = null;
    let isScoringRule = false;
    let evidence = null;

    // 1. Check explicit correctOptionId / correctResponseId keys
    for (const key of ['correctOptionId', 'correct_option_id']) {
      if (obj[key] !== undefined && obj[key] !== null) {
        correctOptionId = String(obj[key]);
        break;
      }
    }
    for (const key of ['correctResponseId', 'correct_response_id']) {
      if (obj[key] !== undefined && obj[key] !== null) {
        correctResponseId = String(obj[key]);
        break;
      }
    }

    if (correctOptionId || correctResponseId) {
      const targetId = correctOptionId || correctResponseId;
      if (options && Array.isArray(options)) {
        const matchIdx = options.findIndex(o => {
          if (typeof o === 'object' && o !== null) {
            return String(o.id) === targetId || String(o.optionId) === targetId ||
                   String(o.responseId) === targetId || String(o.key) === targetId ||
                   String(o.identifier) === targetId || String(o.value) === targetId;
          }
          return String(o) === targetId;
        });
        if (matchIdx !== -1) {
          answerIndex = matchIdx;
          const opt = options[matchIdx];
          answerValue = typeof opt === 'object' ? (opt.text || opt.value || opt.label || opt.content || targetId) : opt;
        } else {
          answerValue = targetId;
        }
      } else {
        answerValue = targetId;
      }
      evidence = `Property "${correctOptionId ? 'correctOptionId' : 'correctResponseId'}": "${targetId}"`;
    }

    // 2. Check explicit answerIndex keys
    if (answerValue === null && answerIndex === null) {
      for (const key of answerIndexKeys) {
        if (obj[key] !== undefined && obj[key] !== null) {
          const parsed = Number(obj[key]);
          if (!isNaN(parsed)) {
            answerIndex = parsed;
            if (options && options[parsed] !== undefined) {
              const opt = options[parsed];
              answerValue = typeof opt === 'object' ? (opt.text || opt.value || opt.label || opt.content) : opt;
              if (typeof opt === 'object' && opt !== null) {
                if (opt.id || opt.optionId) correctOptionId = String(opt.id || opt.optionId);
                if (opt.responseId) correctResponseId = String(opt.responseId);
              }
            } else {
              answerValue = `Option ${parsed + 1}`;
            }
            evidence = `Property "${key}": ${obj[key]}`;
            break;
          }
        }
      }
    }

    // 3. Check explicit answerValue keys
    if (answerValue === null && answerIndex === null) {
      for (const key of answerValueKeys) {
        if (obj[key] !== undefined && obj[key] !== null) {
          const val = obj[key];

          // Skip generic booleans on question
          if (typeof val === 'boolean') continue;

          // Skip dictionary maps in checkQuestionObject (e.g. answerKey: { "1": "B" }) - handled by checkAnswerKeyDictionary
          if ((key === 'answerKey' || key === 'answer_key' || key === 'solutions') && typeof val === 'object') {
            continue;
          }

          // Object response (e.g. correctResponse: { id: "opt_2", text: "UDP" })
          if (typeof val === 'object' && !Array.isArray(val)) {
            if (val.id || val.optionId) correctOptionId = String(val.id || val.optionId);
            if (val.responseId) correctResponseId = String(val.responseId);
            answerValue = val.text || val.value || val.label || val.id || val.responseId;
            if (options && options.length > 0) {
              const matchIdx = options.findIndex(o => {
                if (typeof o === 'object' && o !== null) {
                  return (correctOptionId && (String(o.id) === correctOptionId || String(o.optionId) === correctOptionId)) ||
                         (correctResponseId && String(o.responseId) === correctResponseId) ||
                         (o.text && o.text === answerValue);
                }
                return String(o) === String(answerValue);
              });
              if (matchIdx !== -1) answerIndex = matchIdx;
            }
            evidence = `Property "${key}": ${JSON.stringify(val)}`;
            break;
          }

          // Numeric index or value
          if (typeof val === 'number') {
            if (options && val >= 0 && val < options.length) {
              answerIndex = val;
              const opt = options[val];
              answerValue = typeof opt === 'object' ? (opt.text || opt.value || opt.label || opt.content) : opt;
              if (typeof opt === 'object' && opt !== null) {
                if (opt.id || opt.optionId) correctOptionId = String(opt.id || opt.optionId);
                if (opt.responseId) correctResponseId = String(opt.responseId);
              }
            } else {
              answerValue = val;
            }
            evidence = `Property "${key}": ${val}`;
            break;
          }

          // String value
          if (typeof val === 'string' && val.trim().length > 0) {
            // Check Base64
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
            if (options && options.length > 0) {
              const normFinal = String(finalVal).trim().toLowerCase();
              const matchIdx = options.findIndex(o => {
                const optStr = typeof o === 'object' && o !== null ? (o.text || o.value || o.label || o.content || '') : String(o);
                const optId = typeof o === 'object' && o !== null ? (o.id || o.optionId || o.responseId || '') : '';
                return optStr.trim().toLowerCase() === normFinal || String(optId).trim().toLowerCase() === normFinal;
              });
              if (matchIdx !== -1) {
                answerIndex = matchIdx;
                const opt = options[matchIdx];
                if (typeof opt === 'object' && opt !== null) {
                  if (opt.id || opt.optionId) correctOptionId = String(opt.id || opt.optionId);
                  if (opt.responseId) correctResponseId = String(opt.responseId);
                }
              }
            }

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

    // 4. Check if options contain an isCorrect / correct flag
    if (answerValue === null && options && Array.isArray(options)) {
      for (let i = 0; i < options.length; i++) {
        const opt = options[i];
        if (opt && typeof opt === 'object') {
          if (opt.isCorrect === true || opt.is_correct === true || opt.correct === true || opt.correct === 1) {
            answerIndex = i;
            answerValue = opt.text || opt.value || opt.label || opt.content || `Option ${i + 1}`;
            if (opt.id || opt.optionId) correctOptionId = String(opt.id || opt.optionId);
            if (opt.responseId) correctResponseId = String(opt.responseId);
            evidence = `Option[${i}] has flag isCorrect: true`;
            break;
          }
        }
      }
    }

    // 5. Check if options have author response scoring (e.g. score > 0 or points > 0)
    if (answerValue === null && options && Array.isArray(options)) {
      let maxScore = -Infinity;
      let maxScoreIdx = -1;
      let hasScoring = false;

      for (let i = 0; i < options.length; i++) {
        const opt = options[i];
        if (opt && typeof opt === 'object') {
          const scoreVal = opt.score !== undefined ? opt.score : (opt.points !== undefined ? opt.points : (opt.weight !== undefined ? opt.weight : undefined));
          if (typeof scoreVal === 'number' && !isNaN(scoreVal)) {
            hasScoring = true;
            if (scoreVal > maxScore) {
              maxScore = scoreVal;
              maxScoreIdx = i;
            }
          }
        }
      }

      if (hasScoring && maxScore > 0 && maxScoreIdx !== -1) {
        const allSame = options.every(o => typeof o === 'object' && (o.score === maxScore || o.points === maxScore || o.weight === maxScore));
        if (!allSame) {
          const scoredOpt = options[maxScoreIdx];
          answerIndex = maxScoreIdx;
          answerValue = scoredOpt.text || scoredOpt.value || scoredOpt.label || scoredOpt.content || `Option ${maxScoreIdx + 1}`;
          if (scoredOpt.id || scoredOpt.optionId) correctOptionId = String(scoredOpt.id || scoredOpt.optionId);
          if (scoredOpt.responseId) correctResponseId = String(scoredOpt.responseId);
          evidence = `Option[${maxScoreIdx}] configured with author grading score/points: ${maxScore}`;
          isScoringRule = true;
        }
      }
    }

    // If an answer or grading indicator was found, build normalized finding
    if (answerValue !== null || answerIndex !== null || correctOptionId !== null || correctResponseId !== null) {
      const normalizedOptions = options ? options.map(o => {
        if (typeof o === 'object' && o !== null) {
          return String(o.text || o.value || o.label || o.content || JSON.stringify(o));
        }
        return String(o);
      }) : [];

      return {
        category: ExposureCategory.ANSWER_KEY,
        questionId: questionId,
        questionText: questionText,
        options: normalizedOptions,
        authorOptions: options,
        answerValue: answerValue,
        answerIndex: answerIndex,
        correctOptionId: correctOptionId,
        correctResponseId: correctResponseId,
        isScoringRule: isScoringRule,
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
