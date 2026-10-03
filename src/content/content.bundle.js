(() => {
  // src/shared/types.js
  var ConfidenceLevel = {
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
    NONE: "NONE"
  };
  var ExposureCategory = {
    ANSWER_KEY: "Assessment answer key",
    HIDDEN_DOM_DATA: "Hidden DOM metadata",
    EMBEDDED_JSON: "Embedded application state",
    BROWSER_STORAGE: "Client browser storage",
    API_RESPONSE: "Client-side API response",
    ENCODED_DATA: "Encoded client-side data"
  };
  var ScoreThresholds = {
    HIGH: 80,
    MEDIUM: 60,
    LOW: 40
  };

  // src/shared/utils.js
  function getDomainFromUrl(urlString) {
    if (!urlString || typeof urlString !== "string") return "unknown";
    if (urlString.startsWith("file://")) return "local-files (file://)";
    try {
      const parsed = new URL(urlString);
      return parsed.hostname || "unknown";
    } catch {
      return "unknown";
    }
  }
  function isDomainAuthorized(domain, authorizedList) {
    if (!Array.isArray(authorizedList)) return false;
    const cleanDomain = (domain || "").trim().toLowerCase();
    return authorizedList.some((d) => (d || "").trim().toLowerCase() === cleanDomain);
  }
  function normalizeText(text) {
    if (typeof text !== "string") return "";
    return text.trim().replace(/^([qQ]\d+[:.)-]?|\d+[:.)-]|[a-zA-Z][:.)-])\s*/, "").replace(/\s+/g, " ").toLowerCase();
  }
  function cleanPunctuation(text) {
    if (typeof text !== "string") return "";
    return text.replace(/[?.,!;:()'"[\]{}]/g, "").trim().toLowerCase();
  }
  function calculateTextSimilarity(a, b) {
    const normA = cleanPunctuation(normalizeText(a));
    const normB = cleanPunctuation(normalizeText(b));
    if (!normA || !normB) return 0;
    if (normA === normB) return 1;
    if (normA.includes(normB) || normB.includes(normA)) {
      const ratio = Math.min(normA.length, normB.length) / Math.max(normA.length, normB.length);
      return Math.max(0.8, ratio);
    }
    const wordsA = new Set(normA.split(/\s+/).filter((w) => w.length > 2));
    const wordsB = new Set(normB.split(/\s+/).filter((w) => w.length > 2));
    if (wordsA.size === 0 || wordsB.size === 0) return 0;
    let intersection = 0;
    for (const word of wordsA) {
      if (wordsB.has(word)) intersection++;
    }
    const union = (/* @__PURE__ */ new Set([...wordsA, ...wordsB])).size;
    return union > 0 ? intersection / union : 0;
  }
  function createElement(tag, attributes = {}, children = []) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) {
      if (key === "className") {
        el.className = value;
      } else if (key === "style" && typeof value === "object") {
        Object.assign(el.style, value);
      } else if (key.startsWith("on") && typeof value === "function") {
        el.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (value !== null && value !== void 0) {
        el.setAttribute(key, String(value));
      }
    }
    const childList = Array.isArray(children) ? children : [children];
    for (const child of childList) {
      if (child instanceof Node) {
        el.appendChild(child);
      } else if (child !== null && child !== void 0) {
        el.appendChild(document.createTextNode(String(child)));
      }
    }
    return el;
  }
  function parseOptionIndex(val) {
    if (typeof val === "number") {
      return val;
    }
    if (typeof val !== "string") return null;
    const trimmed = val.trim().toUpperCase();
    if (/^\d+$/.test(trimmed)) {
      return parseInt(trimmed, 10);
    }
    if (/^[A-H]$/.test(trimmed)) {
      return trimmed.charCodeAt(0) - 65;
    }
    const optionMatch = trimmed.match(/(?:OPTION|CHOICE)\s*([A-H]|\d+)/i);
    if (optionMatch) {
      const matched = optionMatch[1].toUpperCase();
      if (/^\d+$/.test(matched)) {
        return parseInt(matched, 10) - 1;
      }
      return matched.charCodeAt(0) - 65;
    }
    return null;
  }

  // src/analysis/encoding-analyzer.js
  var EncodingAnalyzer = class {
    /**
     * Attempts to safely decode Base64 strings
     * @param {string} str 
     * @returns {{ success: boolean, decoded: string|null, isJson: boolean, parsedJson: any }}
     */
    static decodeBase64(str) {
      if (typeof str !== "string" || str.length < 4) {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }
      const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
      const cleanStr = str.trim();
      if (!base64Regex.test(cleanStr)) {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }
      try {
        let decodedStr;
        if (typeof atob === "function") {
          decodedStr = atob(cleanStr);
        } else if (typeof Buffer !== "undefined") {
          decodedStr = Buffer.from(cleanStr, "base64").toString("utf-8");
        } else {
          return { success: false, decoded: null, isJson: false, parsedJson: null };
        }
        const isPrintable = /^[\x20-\x7E\s\u00A0-\uFFFF]*$/.test(decodedStr);
        if (!isPrintable || decodedStr.length === 0) {
          return { success: false, decoded: null, isJson: false, parsedJson: null };
        }
        const jsonCheck = this.parseJsonSafe(decodedStr);
        return {
          success: true,
          decoded: decodedStr,
          isJson: jsonCheck.success,
          parsedJson: jsonCheck.data
        };
      } catch {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }
    }
    /**
     * Attempts to safely decode URL-encoded strings
     * @param {string} str 
     * @returns {{ success: boolean, decoded: string|null, isJson: boolean, parsedJson: any }}
     */
    static decodeUrl(str) {
      if (typeof str !== "string" || !str.includes("%")) {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }
      try {
        const decoded = decodeURIComponent(str);
        if (decoded === str) {
          return { success: false, decoded: null, isJson: false, parsedJson: null };
        }
        const jsonCheck = this.parseJsonSafe(decoded);
        return {
          success: true,
          decoded,
          isJson: jsonCheck.success,
          parsedJson: jsonCheck.data
        };
      } catch {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }
    }
    /**
     * Attempts to parse escaped JSON or double-serialized JSON
     * @param {string} str 
     * @returns {{ success: boolean, data: any }}
     */
    static parseJsonSafe(str) {
      if (typeof str !== "string") {
        return { success: false, data: null };
      }
      const trimmed = str.trim();
      if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
        if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length > 4) {
          try {
            const unescaped = JSON.parse(trimmed);
            if (typeof unescaped === "string") {
              return this.parseJsonSafe(unescaped);
            }
          } catch {
          }
        }
        return { success: false, data: null };
      }
      try {
        const data = JSON.parse(trimmed);
        return { success: true, data };
      } catch {
        return { success: false, data: null };
      }
    }
    /**
     * Universal analyzer: inspects a value for any embedded encoding
     * @param {string} value 
     * @returns {Array<{ type: string, raw: string, decoded: any, isJson: boolean }>}
     */
    static analyzeValue(value) {
      if (typeof value !== "string") return [];
      const results = [];
      const directJson = this.parseJsonSafe(value);
      if (directJson.success) {
        results.push({
          type: "json",
          raw: value,
          decoded: directJson.data,
          isJson: true
        });
      }
      const b64 = this.decodeBase64(value);
      if (b64.success) {
        results.push({
          type: "base64",
          raw: value,
          decoded: b64.isJson ? b64.parsedJson : b64.decoded,
          isJson: b64.isJson
        });
      }
      const url = this.decodeUrl(value);
      if (url.success) {
        results.push({
          type: "url",
          raw: value,
          decoded: url.isJson ? url.parsedJson : url.decoded,
          isJson: url.isJson
        });
      }
      return results;
    }
  };

  // src/analysis/dom-analyzer.js
  var DomAnalyzer = class {
    /**
     * Discovers all question containers rendered on the page
     * @param {Document|Element} root 
     * @returns {Array<Object>} List of extracted DOM questions
     */
    static extractQuestions(root = document) {
      const questions = [];
      const questionSelectors = [
        "[data-question-id]",
        "[data-question]",
        ".question-container",
        ".question-item",
        ".question-card",
        ".assessment-question",
        ".assessment-item",
        ".quiz-question",
        ".quiz-item",
        ".mcq-question",
        ".mcq-item",
        "fieldset.question",
        "fieldset",
        ".question",
        ".problem"
      ];
      const potentialContainers = root.querySelectorAll(questionSelectors.join(", "));
      const processedNodes = /* @__PURE__ */ new Set();
      for (const container of potentialContainers) {
        if (processedNodes.has(container)) continue;
        const options = this.extractOptions(container);
        if (options.length < 2) continue;
        const questionText = this.extractQuestionText(container);
        if (!questionText || questionText.length < 3) continue;
        const questionId = this.extractQuestionId(container);
        const domFindings = this.checkDomGradingFlags(container, questionId, questionText, options);
        questions.push({
          element: container,
          questionId,
          questionText,
          normalizedText: normalizeText(questionText),
          options,
          domFindings
        });
        processedNodes.add(container);
      }
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
      const textSelectors = [
        ".question-text",
        ".question-title",
        ".question-prompt",
        ".prompt",
        "legend",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        ".title",
        "[data-question-text]",
        "p"
      ];
      for (const sel of textSelectors) {
        const el = container.querySelector(sel);
        if (el) {
          const text = el.textContent.trim();
          if (text.length > 3) {
            return text;
          }
        }
      }
      try {
        const clone = container.cloneNode(true);
        const options = clone.querySelectorAll("input, label, .option, .choice, button");
        options.forEach((o) => o.remove());
        const remaining = clone.textContent.trim();
        if (remaining.length > 3) return remaining;
      } catch {
      }
      return "";
    }
    /**
     * Extracts question ID from element attributes
     * @param {Element} container 
     * @returns {string|null}
     */
    static extractQuestionId(container) {
      const idAttrs = ["data-question-id", "data-id", "data-qid", "id", "name"];
      for (const attr of idAttrs) {
        const val = container.getAttribute(attr);
        if (val) {
          return val.replace(/^(?:question[_-]?|q[_-]?)/i, "");
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
      const optionSelectors = [
        ".option",
        ".choice",
        ".quiz-option",
        ".answer-option",
        ".mcq-option",
        "label",
        "[data-option-id]",
        "[data-option]"
      ];
      let optionEls = Array.from(container.querySelectorAll(optionSelectors.join(", ")));
      if (optionEls.length < 2) {
        const radios = container.querySelectorAll('input[type="radio"], input[type="checkbox"]');
        if (radios.length >= 2) {
          optionEls = Array.from(radios).map((r) => r.closest("label") || r.parentElement || r);
        }
      }
      const uniqueEls = [];
      const seen = /* @__PURE__ */ new Set();
      for (const el of optionEls) {
        if (!seen.has(el)) {
          uniqueEls.push(el);
          seen.add(el);
        }
      }
      uniqueEls.forEach((el, index) => {
        const rawText = el.textContent.trim();
        const normalized = normalizeText(rawText);
        const input = el.querySelector("input") || (el.tagName === "INPUT" ? el : null);
        const value = input ? input.value : el.getAttribute("data-value") || "";
        const letterMatch = rawText.match(/^([A-H])[:.)-]\s*(.*)$/i);
        const letter = letterMatch ? letterMatch[1].toUpperCase() : String.fromCharCode(65 + index);
        const cleanOptionText = letterMatch ? letterMatch[2].trim() : rawText;
        options.push({
          element: el,
          inputElement: input,
          index,
          letter,
          text: cleanOptionText,
          rawText,
          value,
          normalizedText: normalized,
          optionId: el.getAttribute("data-option-id") || el.id || value || String(index)
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
      const hiddenInputs = container.querySelectorAll('input[type="hidden"]');
      for (const input of hiddenInputs) {
        const name = (input.name || input.id || "").toLowerCase();
        const val = input.value;
        if (!val) continue;
        if (/^(?:correct|answer|key|solution|correct_answer|correct_index)/i.test(name)) {
          const b64 = EncodingAnalyzer.decodeBase64(val);
          let resolvedVal = val;
          let optIdx = null;
          if (b64.success) {
            if (b64.isJson && b64.parsedJson) {
              if (b64.parsedJson.correctIndex !== void 0) optIdx = Number(b64.parsedJson.correctIndex);
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
            questionId,
            questionText,
            answerValue: resolvedVal,
            answerIndex: optIdx,
            source: `Hidden input: <input type="hidden" name="${input.name}">`,
            evidence: `Hidden input exposes answer value: "${val}"${b64.success ? ` (Decoded Base64: "${resolvedVal}")` : ""}`,
            domDirectAttribute: true
          });
        }
      }
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
              if (b64.parsedJson.correctIndex !== void 0) optIdx = Number(b64.parsedJson.correctIndex);
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
            questionId,
            questionText,
            answerValue: resolvedVal,
            answerIndex: optIdx,
            source: `Question attribute [${attr.name}]`,
            evidence: `Container attribute "${attr.name}" = "${val}"${b64.success ? ` (Decoded Base64: "${resolvedVal}")` : ""}`,
            domDirectAttribute: true
          });
        }
      }
      for (const opt of options) {
        const el = opt.element;
        const attrs = el.attributes;
        let isFlagged = false;
        let flagEvidence = "";
        for (let i = 0; i < attrs.length; i++) {
          const attr = attrs[i];
          const name = attr.name.toLowerCase();
          const val = attr.value.toLowerCase();
          if (/^data-(?:correct|is-correct|solution|right-choice)$/i.test(name)) {
            if (val === "true" || val === "1" || val === "correct") {
              isFlagged = true;
              flagEvidence = `Attribute [${attr.name}="${attr.value}"]`;
              break;
            }
          }
        }
        if (!isFlagged && el.classList) {
          if (el.classList.contains("is-correct") || el.classList.contains("correct-answer") || el.classList.contains("correct-option")) {
            isFlagged = true;
            flagEvidence = `CSS Class "${el.className}" on option element`;
          }
        }
        if (!isFlagged) {
          const ariaDesc = el.getAttribute("aria-description") || "";
          const ariaLabel = el.getAttribute("aria-label") || "";
          if (/correct/i.test(ariaDesc) || /correct/i.test(ariaLabel)) {
            isFlagged = true;
            flagEvidence = `ARIA attribute indicates correct option`;
          }
        }
        if (isFlagged) {
          findings.push({
            category: ExposureCategory.HIDDEN_DOM_DATA,
            questionId,
            questionText,
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
      const radioGroups = /* @__PURE__ */ new Map();
      const radios = root.querySelectorAll('input[type="radio"]');
      radios.forEach((r) => {
        const name = r.name || "default";
        if (!radioGroups.has(name)) {
          radioGroups.set(name, []);
        }
        radioGroups.get(name).push(r);
      });
      const questions = [];
      for (const [groupName, groupRadios] of radioGroups.entries()) {
        if (groupRadios.length < 2) continue;
        const parent = groupRadios[0].closest("form") || groupRadios[0].parentElement?.parentElement || document.body;
        const options = groupRadios.map((r, idx) => {
          const label = r.closest("label") || r.parentElement;
          const text = label ? label.textContent.trim() : r.value;
          return {
            element: label || r,
            inputElement: r,
            index: idx,
            letter: String.fromCharCode(65 + idx),
            text,
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
          questionText,
          normalizedText: normalizeText(questionText),
          options,
          domFindings: []
        });
      }
      return questions;
    }
  };

  // src/analysis/json-analyzer.js
  var JsonAnalyzer = class {
    /**
     * Main entry point: recursively analyzes an arbitrary object or array
     * 
     * @param {any} root 
     * @param {string} sourceName - e.g. "API Response: /api/quiz", "localStorage", "Inline Script"
     * @param {number} [maxDepth=10]
     * @returns {Array<Object>} list of raw candidate findings
     */
    static analyze(root, sourceName = "Application State", maxDepth = 10) {
      if (!root || typeof root !== "object") {
        return [];
      }
      const findings = [];
      const visited = /* @__PURE__ */ new WeakSet();
      const traverse = (current, depth, path) => {
        if (!current || typeof current !== "object" || depth > maxDepth) {
          return;
        }
        if (visited.has(current)) {
          return;
        }
        visited.add(current);
        const questionFinding = this.checkQuestionObject(current, sourceName, path);
        if (questionFinding) {
          findings.push(questionFinding);
        }
        const keyMapFindings = this.checkAnswerKeyDictionary(current, sourceName, path);
        if (keyMapFindings.length > 0) {
          findings.push(...keyMapFindings);
        }
        if (Array.isArray(current)) {
          for (let i = 0; i < current.length; i++) {
            traverse(current[i], depth + 1, `${path}[${i}]`);
          }
        } else {
          for (const [key, val] of Object.entries(current)) {
            if (typeof val === "string" && val.length > 4) {
              const decodings = EncodingAnalyzer.analyzeValue(val);
              for (const dec of decodings) {
                if (dec.isJson && dec.decoded && typeof dec.decoded === "object") {
                  traverse(dec.decoded, depth + 1, `${path}.${key}[decoded_${dec.type}]`);
                }
              }
            } else if (val && typeof val === "object") {
              traverse(val, depth + 1, `${path}.${key}`);
            }
          }
        }
      };
      traverse(root, 0, "root");
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
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
      const questionKeys = ["question", "prompt", "text", "questionText", "title", "q", "itemText"];
      let questionText = null;
      let questionKeyFound = null;
      for (const key of questionKeys) {
        if (typeof obj[key] === "string" && obj[key].trim().length > 0) {
          questionText = obj[key].trim();
          questionKeyFound = key;
          break;
        }
      }
      const idKeys = ["id", "questionId", "qid", "itemId", "key", "_id"];
      let questionId = null;
      for (const key of idKeys) {
        if (obj[key] !== void 0 && obj[key] !== null) {
          questionId = String(obj[key]);
          break;
        }
      }
      const optionsKeys = ["options", "choices", "answers", "choicesList", "alternatives", "items", "responses"];
      let options = null;
      let optionsKeyFound = null;
      for (const key of optionsKeys) {
        if (Array.isArray(obj[key]) && obj[key].length >= 2) {
          options = obj[key];
          optionsKeyFound = key;
          break;
        }
      }
      const answerIndexKeys = [
        "correctIndex",
        "correct_index",
        "solutionIndex",
        "solution_index",
        "correctOptionIndex",
        "answerIndex",
        "answer_index",
        "correctIdx"
      ];
      const answerValueKeys = [
        "correctAnswer",
        "correct_answer",
        "correctOption",
        "correct_option",
        "correctResponse",
        "correct_response",
        "correctChoice",
        "correct_choice",
        "answerKey",
        "answer_key",
        "solution",
        "rightAnswer",
        "validOption",
        "correct",
        "answer"
      ];
      let answerValue = null;
      let answerIndex = null;
      let correctOptionId = null;
      let correctResponseId = null;
      let isScoringRule = false;
      let evidence = null;
      for (const key of ["correctOptionId", "correct_option_id"]) {
        if (obj[key] !== void 0 && obj[key] !== null) {
          correctOptionId = String(obj[key]);
          break;
        }
      }
      for (const key of ["correctResponseId", "correct_response_id"]) {
        if (obj[key] !== void 0 && obj[key] !== null) {
          correctResponseId = String(obj[key]);
          break;
        }
      }
      if (correctOptionId || correctResponseId) {
        const targetId = correctOptionId || correctResponseId;
        if (options && Array.isArray(options)) {
          const matchIdx = options.findIndex((o) => {
            if (typeof o === "object" && o !== null) {
              return String(o.id) === targetId || String(o.optionId) === targetId || String(o.responseId) === targetId || String(o.key) === targetId || String(o.identifier) === targetId || String(o.value) === targetId;
            }
            return String(o) === targetId;
          });
          if (matchIdx !== -1) {
            answerIndex = matchIdx;
            const opt = options[matchIdx];
            answerValue = typeof opt === "object" ? opt.text || opt.value || opt.label || opt.content || targetId : opt;
          } else {
            answerValue = targetId;
          }
        } else {
          answerValue = targetId;
        }
        evidence = `Property "${correctOptionId ? "correctOptionId" : "correctResponseId"}": "${targetId}"`;
      }
      if (answerValue === null && answerIndex === null) {
        for (const key of answerIndexKeys) {
          if (obj[key] !== void 0 && obj[key] !== null) {
            const parsed = Number(obj[key]);
            if (!isNaN(parsed)) {
              answerIndex = parsed;
              if (options && options[parsed] !== void 0) {
                const opt = options[parsed];
                answerValue = typeof opt === "object" ? opt.text || opt.value || opt.label || opt.content : opt;
                if (typeof opt === "object" && opt !== null) {
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
      if (answerValue === null && answerIndex === null) {
        for (const key of answerValueKeys) {
          if (obj[key] !== void 0 && obj[key] !== null) {
            const val = obj[key];
            if (typeof val === "boolean") continue;
            if ((key === "answerKey" || key === "answer_key" || key === "solutions") && typeof val === "object") {
              continue;
            }
            if (typeof val === "object" && !Array.isArray(val)) {
              if (val.id || val.optionId) correctOptionId = String(val.id || val.optionId);
              if (val.responseId) correctResponseId = String(val.responseId);
              answerValue = val.text || val.value || val.label || val.id || val.responseId;
              if (options && options.length > 0) {
                const matchIdx = options.findIndex((o) => {
                  if (typeof o === "object" && o !== null) {
                    return correctOptionId && (String(o.id) === correctOptionId || String(o.optionId) === correctOptionId) || correctResponseId && String(o.responseId) === correctResponseId || o.text && o.text === answerValue;
                  }
                  return String(o) === String(answerValue);
                });
                if (matchIdx !== -1) answerIndex = matchIdx;
              }
              evidence = `Property "${key}": ${JSON.stringify(val)}`;
              break;
            }
            if (typeof val === "number") {
              if (options && val >= 0 && val < options.length) {
                answerIndex = val;
                const opt = options[val];
                answerValue = typeof opt === "object" ? opt.text || opt.value || opt.label || opt.content : opt;
                if (typeof opt === "object" && opt !== null) {
                  if (opt.id || opt.optionId) correctOptionId = String(opt.id || opt.optionId);
                  if (opt.responseId) correctResponseId = String(opt.responseId);
                }
              } else {
                answerValue = val;
              }
              evidence = `Property "${key}": ${val}`;
              break;
            }
            if (typeof val === "string" && val.trim().length > 0) {
              const decodings = EncodingAnalyzer.analyzeValue(val);
              let finalVal = val;
              let encodedEvidence = "";
              for (const dec of decodings) {
                if (dec.type === "base64") {
                  finalVal = dec.isJson && dec.decoded?.correct ? dec.decoded.correct : dec.decoded;
                  encodedEvidence = ` (Base64 decoded from "${val}")`;
                  break;
                }
              }
              answerValue = finalVal;
              if (options && options.length > 0) {
                const normFinal = String(finalVal).trim().toLowerCase();
                const matchIdx = options.findIndex((o) => {
                  const optStr = typeof o === "object" && o !== null ? o.text || o.value || o.label || o.content || "" : String(o);
                  const optId = typeof o === "object" && o !== null ? o.id || o.optionId || o.responseId || "" : "";
                  return optStr.trim().toLowerCase() === normFinal || String(optId).trim().toLowerCase() === normFinal;
                });
                if (matchIdx !== -1) {
                  answerIndex = matchIdx;
                  const opt = options[matchIdx];
                  if (typeof opt === "object" && opt !== null) {
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
      if (answerValue === null && options && Array.isArray(options)) {
        for (let i = 0; i < options.length; i++) {
          const opt = options[i];
          if (opt && typeof opt === "object") {
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
      if (answerValue === null && options && Array.isArray(options)) {
        let maxScore = -Infinity;
        let maxScoreIdx = -1;
        let hasScoring = false;
        for (let i = 0; i < options.length; i++) {
          const opt = options[i];
          if (opt && typeof opt === "object") {
            const scoreVal = opt.score !== void 0 ? opt.score : opt.points !== void 0 ? opt.points : opt.weight !== void 0 ? opt.weight : void 0;
            if (typeof scoreVal === "number" && !isNaN(scoreVal)) {
              hasScoring = true;
              if (scoreVal > maxScore) {
                maxScore = scoreVal;
                maxScoreIdx = i;
              }
            }
          }
        }
        if (hasScoring && maxScore > 0 && maxScoreIdx !== -1) {
          const allSame = options.every((o) => typeof o === "object" && (o.score === maxScore || o.points === maxScore || o.weight === maxScore));
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
      if (answerValue !== null || answerIndex !== null || correctOptionId !== null || correctResponseId !== null) {
        const normalizedOptions = options ? options.map((o) => {
          if (typeof o === "object" && o !== null) {
            return String(o.text || o.value || o.label || o.content || JSON.stringify(o));
          }
          return String(o);
        }) : [];
        return {
          category: ExposureCategory.ANSWER_KEY,
          questionId,
          questionText,
          options: normalizedOptions,
          authorOptions: options,
          answerValue,
          answerIndex,
          correctOptionId,
          correctResponseId,
          isScoringRule,
          source,
          path,
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
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) return [];
      const findings = [];
      const keyPatterns = /^(answer[_-]?keys?|solutions?|correct[_-]?answers?)$/i;
      for (const [prop, val] of Object.entries(obj)) {
        if (keyPatterns.test(prop) && val && typeof val === "object") {
          if (Array.isArray(val)) {
            val.forEach((ans, idx) => {
              findings.push({
                category: ExposureCategory.ANSWER_KEY,
                questionId: idx + 1,
                questionText: null,
                answerValue: ans,
                answerIndex: typeof ans === "number" ? ans : parseOptionIndex(String(ans)),
                source,
                path: `${path}.${prop}[${idx}]`,
                evidence: `Answer list "${prop}[${idx}]": ${ans}`,
                structural: false
              });
            });
          } else {
            for (const [qId, ans] of Object.entries(val)) {
              findings.push({
                category: ExposureCategory.ANSWER_KEY,
                questionId: qId,
                questionText: null,
                answerValue: ans,
                answerIndex: typeof ans === "number" ? ans : parseOptionIndex(String(ans)),
                source,
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
  };

  // src/analysis/script-analyzer.js
  var ScriptAnalyzer = class {
    /**
     * Analyzes an array of script elements or raw script strings
     * @param {Array<HTMLScriptElement|string>} scripts 
     * @returns {Array<Object>} List of candidate findings
     */
    static analyzeScripts(scripts) {
      const allFindings = [];
      for (const item of scripts) {
        let scriptContent = "";
        let scriptType = "text/javascript";
        let scriptId = "";
        if (typeof item === "string") {
          scriptContent = item;
        } else if (item && typeof item === "object") {
          scriptContent = item.textContent || item.innerText || "";
          scriptType = (item.getAttribute("type") || "text/javascript").toLowerCase();
          scriptId = item.id || item.className || "";
        }
        if (!scriptContent || scriptContent.trim().length === 0) {
          continue;
        }
        if (scriptType.includes("json") || scriptId.includes("data") || scriptId.includes("state")) {
          const parsed = EncodingAnalyzer.parseJsonSafe(scriptContent);
          if (parsed.success) {
            const findings = JsonAnalyzer.analyze(parsed.data, `Embedded Script JSON (<script id="${scriptId}">)`);
            allFindings.push(...findings);
            continue;
          }
        }
        const jsFindings = this.analyzeScriptText(scriptContent, scriptId ? `Inline Script (#${scriptId})` : "Inline Script");
        allFindings.push(...jsFindings);
      }
      return allFindings;
    }
    /**
     * Safely analyzes a raw JavaScript string for assessment structures
     * @param {string} code 
     * @param {string} sourceName 
     * @returns {Array<Object>}
     */
    static analyzeScriptText(code, sourceName = "Inline Script") {
      const findings = [];
      const jsonParseRegex = /JSON\.parse\s*\(\s*(['"`])((?:\\.|(?!\1).)*)\1\s*\)/g;
      let match;
      while ((match = jsonParseRegex.exec(code)) !== null) {
        try {
          const rawJsonString = match[2].replace(/\\'/g, "'").replace(/\\"/g, '"');
          const parsed = EncodingAnalyzer.parseJsonSafe(rawJsonString);
          if (parsed.success) {
            const res = JsonAnalyzer.analyze(parsed.data, `${sourceName} [JSON.parse]`);
            findings.push(...res);
          }
        } catch {
        }
      }
      const b64Regex = /['"](eyJ[A-Za-z0-9+/=]{10,})['"]/g;
      while ((match = b64Regex.exec(code)) !== null) {
        const decoded = EncodingAnalyzer.decodeBase64(match[1]);
        if (decoded.success && decoded.isJson) {
          const res = JsonAnalyzer.analyze(decoded.parsedJson, `${sourceName} [Decoded Base64]`);
          findings.push(...res);
        }
      }
      const extractedObjects = this.extractObjectLiterals(code);
      for (const obj of extractedObjects) {
        const res = JsonAnalyzer.analyze(obj, sourceName);
        findings.push(...res);
      }
      return findings;
    }
    /**
     * Safely extracts and converts JS object/array literals into JSON structures without eval
     * Works against readable, minified, and bundled code using balanced bracket parsing.
     * 
     * @param {string} code 
     * @returns {Array<Object>}
     */
    static extractObjectLiterals(code) {
      const results = [];
      if (typeof code !== "string") return results;
      const hasKeyword = /(?:correct|solution|answer|isCorrect|score|points|weight)/i.test(code);
      if (!hasKeyword) {
        return results;
      }
      const assignmentRegex = /=\s*([{\[])/g;
      let match;
      while ((match = assignmentRegex.exec(code)) !== null) {
        const startIndex = match.index + match[0].length - 1;
        const literalStr = this.extractBalancedLiteral(code, startIndex);
        if (literalStr) {
          const parsed = this.safeParseJsLiteral(literalStr);
          if (parsed && typeof parsed === "object") {
            results.push(parsed);
          }
        }
      }
      return results;
    }
    /**
     * Extracts a balanced JS object/array literal starting at startIndex
     * Tracks string literals, escapes, and comments safely.
     * 
     * @param {string} code 
     * @param {number} startIndex 
     * @returns {string|null}
     */
    static extractBalancedLiteral(code, startIndex) {
      const startChar = code[startIndex];
      if (startChar !== "{" && startChar !== "[") return null;
      let depth = 0;
      let inString = false;
      let stringQuote = "";
      let inLineComment = false;
      let inBlockComment = false;
      for (let i = startIndex; i < code.length; i++) {
        const ch = code[i];
        const prev = i > 0 ? code[i - 1] : "";
        if (inLineComment) {
          if (ch === "\n" || ch === "\r") {
            inLineComment = false;
          }
          continue;
        }
        if (inBlockComment) {
          if (ch === "/" && prev === "*") {
            inBlockComment = false;
          }
          continue;
        }
        if (inString) {
          if (ch === stringQuote && prev !== "\\") {
            inString = false;
          }
          continue;
        }
        if (ch === "/" && code[i + 1] === "/") {
          inLineComment = true;
          i++;
          continue;
        }
        if (ch === "/" && code[i + 1] === "*") {
          inBlockComment = true;
          i++;
          continue;
        }
        if (ch === '"' || ch === "'" || ch === "`") {
          inString = true;
          stringQuote = ch;
          continue;
        }
        if (ch === "{" || ch === "[") {
          depth++;
        } else if (ch === "}" || ch === "]") {
          depth--;
          if (depth === 0) {
            return code.slice(startIndex, i + 1);
          }
        }
      }
      return null;
    }
    /**
     * Safely transforms a JavaScript object/array literal string into a parsed JSON object
     * without using eval() or Function().
     * 
     * Converts unquoted keys, single quotes, trailing commas into valid JSON.
     * 
     * @param {string} literalStr 
     * @returns {any|null}
     */
    static safeParseJsLiteral(literalStr) {
      if (!literalStr || typeof literalStr !== "string") return null;
      try {
        return JSON.parse(literalStr);
      } catch {
      }
      try {
        let cleaned = literalStr.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*/g, "").replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, (m, content) => {
          return `"${content.replace(/"/g, '\\"')}"`;
        }).replace(/([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g, '$1"$2":').replace(/,\s*([}\]])/g, "$1").trim();
        return JSON.parse(cleaned);
      } catch {
        return null;
      }
    }
  };

  // src/analysis/storage-analyzer.js
  var StorageAnalyzer = class {
    /**
     * Scans localStorage and sessionStorage
     * @param {Window} [win=window]
     * @returns {Array<Object>}
     */
    static analyzeStorage(win = typeof window !== "undefined" ? window : null) {
      if (!win) return [];
      const findings = [];
      try {
        if (win.localStorage && win.localStorage.length > 0) {
          for (let i = 0; i < win.localStorage.length; i++) {
            const key = win.localStorage.key(i);
            if (!key) continue;
            const val = win.localStorage.getItem(key);
            const res = this.analyzeStorageItem(key, val, "localStorage");
            findings.push(...res);
          }
        }
      } catch {
      }
      try {
        if (win.sessionStorage && win.sessionStorage.length > 0) {
          for (let i = 0; i < win.sessionStorage.length; i++) {
            const key = win.sessionStorage.key(i);
            if (!key) continue;
            const val = win.sessionStorage.getItem(key);
            const res = this.analyzeStorageItem(key, val, "sessionStorage");
            findings.push(...res);
          }
        }
      } catch {
      }
      return findings;
    }
    /**
     * Analyzes an individual storage key/value pair
     * @param {string} key 
     * @param {string} val 
     * @param {string} storageType 
     * @returns {Array<Object>}
     */
    static analyzeStorageItem(key, val, storageType) {
      if (!val || typeof val !== "string") return [];
      const findings = [];
      const source = `${storageType}['${key}']`;
      const jsonParsed = EncodingAnalyzer.parseJsonSafe(val);
      if (jsonParsed.success) {
        const res = JsonAnalyzer.analyze(jsonParsed.data, source);
        findings.push(...res);
      }
      const b64 = EncodingAnalyzer.decodeBase64(val);
      if (b64.success) {
        if (b64.isJson) {
          const res = JsonAnalyzer.analyze(b64.parsedJson, `${source} (Base64)`);
          findings.push(...res);
        } else if (this.isKeyNameSuspicious(key)) {
          findings.push({
            category: ExposureCategory.BROWSER_STORAGE,
            questionId: null,
            questionText: null,
            answerValue: b64.decoded,
            answerIndex: null,
            source,
            evidence: `Suspicious storage key "${key}" contains Base64 decoded value: "${b64.decoded}"`,
            structural: false
          });
        }
      }
      if (this.isKeyNameSuspicious(key) && findings.length === 0) {
        findings.push({
          category: ExposureCategory.BROWSER_STORAGE,
          questionId: this.extractIdFromKey(key),
          questionText: null,
          answerValue: val,
          answerIndex: null,
          source,
          evidence: `Direct answer key stored under "${key}": "${val}"`,
          structural: false
        });
      }
      return findings;
    }
    /**
     * Helper to determine if a storage key name indicates answer data
     * @param {string} key 
     * @returns {boolean}
     */
    static isKeyNameSuspicious(key) {
      return /^(?:quiz|exam|test|assessment)?[_-]?(?:answers?|answer[_-]?key|correct|solution)[_-]?\d*$/i.test(key);
    }
    /**
     * Attempts to extract a question ID or number from a key name (e.g. "answer_q1" -> "q1")
     * @param {string} key 
     * @returns {string|null}
     */
    static extractIdFromKey(key) {
      const match = key.match(/(?:q(?:uestion)?[_-]?(\d+)|(\d+))/i);
      return match ? match[1] || match[2] : null;
    }
    /**
     * Asynchronously inspects accessible IndexedDB databases where supported
     * @returns {Promise<Array<Object>>}
     */
    static async analyzeIndexedDB() {
      if (typeof indexedDB === "undefined" || !indexedDB.databases) {
        return [];
      }
      const findings = [];
      try {
        const dbs = await indexedDB.databases();
        for (const dbInfo of dbs) {
          if (!dbInfo.name) continue;
          const lowerName = dbInfo.name.toLowerCase();
          if (lowerName.includes("quiz") || lowerName.includes("assessment") || lowerName.includes("exam") || lowerName.includes("test")) {
            try {
              const openReq = indexedDB.open(dbInfo.name);
              await new Promise((resolve) => {
                openReq.onsuccess = (e) => {
                  const db = e.target.result;
                  const storeNames = Array.from(db.objectStoreNames);
                  for (const storeName of storeNames) {
                    try {
                      const tx = db.transaction(storeName, "readonly");
                      const store = tx.objectStore(storeName);
                      const getAllReq = store.getAll();
                      getAllReq.onsuccess = () => {
                        if (Array.isArray(getAllReq.result)) {
                          for (const item of getAllReq.result) {
                            const res = JsonAnalyzer.analyze(item, `IndexedDB [${dbInfo.name}/${storeName}]`);
                            findings.push(...res);
                          }
                        }
                        resolve();
                      };
                      getAllReq.onerror = () => resolve();
                    } catch {
                      resolve();
                    }
                  }
                };
                openReq.onerror = () => resolve();
              });
            } catch {
            }
          }
        }
      } catch {
      }
      return findings;
    }
  };

  // src/analysis/confidence.js
  var ConfidenceEngine = class {
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
        reasons.push("Direct DOM attribute on option element (score +95)");
      }
      if (signals.exactQuestionIdMatch && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
        score = Math.max(score, 100);
        reasons.push("Exact question ID match with correlated option (score: 100)");
      } else if (signals.exactQuestionIdMatch) {
        score = Math.max(score, 75);
        reasons.push("Question ID match (score: 75)");
      }
      if (signals.exactQuestionTextMatch && signals.answerIndexMatchesOption) {
        score = Math.max(score, 90);
        reasons.push("Exact question text match with answer index (score: 90)");
      } else if (signals.exactQuestionTextMatch && (signals.answerMatchesOptionValue || signals.idMatchOnOption)) {
        score = Math.max(score, 85);
        reasons.push("Exact question text match with answer value (score: 85)");
      } else if (signals.normalizedQuestionTextMatch && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
        score = Math.max(score, 80);
        reasons.push("Normalized question text match with answer (score: 80)");
      }
      if (signals.exactOptionListMatch && (signals.answerIndexMatchesOption || signals.answerMatchesOptionValue)) {
        score = Math.max(score, 85);
        reasons.push("Full option list match with answer (score: 85)");
      }
      if (signals.structuralQuizRelationship && (signals.answerMatchesOptionValue || signals.answerIndexMatchesOption || signals.idMatchOnOption)) {
        score = Math.max(score, 80);
        reasons.push("Structured assessment payload containing question, options, and grading key");
      }
      if (signals.scoringRule) {
        if (signals.exactQuestionIdMatch || signals.exactQuestionTextMatch) {
          score = Math.max(score, 85);
          reasons.push("Author response scoring metadata correlated with question (score: 85)");
        } else {
          score = Math.max(score, 65);
          reasons.push("Author response scoring metadata detected without exact question match (score: 65)");
        }
      }
      if (signals.isInstructionOrPrompt) {
        score = Math.min(score, 20);
        reasons.push("Demoted: text appears to be general instruction/prompt, not answer key");
      }
      if (signals.keywordOnly) {
        score = Math.max(score, 30);
        reasons.push("Keyword match without structural relationship (score: 30)");
      }
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
      if (!text || typeof text !== "string") return false;
      const lower = text.toLowerCase();
      const benignPatterns = [
        /select the correct answer/i,
        /choose the correct/i,
        /which of the following is correct/i,
        /indicate the correct option/i,
        /mark the correct/i,
        /all of the above are correct/i,
        // benign if in option text
        /none of the above is correct/i
      ];
      if (/^(please\s+)?(select|choose|pick|find|identify|mark)\s+the\s+correct/i.test(lower)) {
        return true;
      }
      return false;
    }
  };

  // src/analysis/correlator.js
  var Correlator = class {
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
        if (q.domFindings && q.domFindings.length > 0) {
          for (const df of q.domFindings) {
            const correlated = this.correlateSingle(q, df, qIdx);
            if (correlated && correlated.score > highestScore) {
              highestScore = correlated.score;
              bestMatch = correlated;
            }
          }
        }
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
      if (q.questionId && finding.questionId) {
        const qIdStr = String(q.questionId).trim();
        const findIdStr = String(finding.questionId).trim();
        if (qIdStr === findIdStr || qIdStr === `q${findIdStr}` || findIdStr === `q${qIdStr}`) {
          signals.exactQuestionIdMatch = true;
        }
      } else if (finding.questionId !== null && Number(finding.questionId) === qIdx + 1) {
        signals.exactQuestionIdMatch = true;
      }
      if (finding.questionText && q.questionText) {
        if (finding.questionText.trim() === q.questionText.trim()) {
          signals.exactQuestionTextMatch = true;
        } else {
          const similarity = calculateTextSimilarity(q.questionText, finding.questionText);
          if (similarity >= 0.85) {
            signals.normalizedQuestionTextMatch = true;
          } else if (similarity < 0.3 && !signals.exactQuestionIdMatch) {
            return null;
          }
        }
      }
      if (ConfidenceEngine.isFalsePositiveText(finding.questionText || q.questionText)) {
        signals.isInstructionOrPrompt = true;
      }
      if (finding.options && Array.isArray(finding.options) && finding.options.length > 0) {
        let matchedCount = 0;
        for (const optText of finding.options) {
          const normOpt = normalizeText(String(optText));
          if (q.options.some((o) => o.normalizedText === normOpt || (o.rawText || o.text || "").toLowerCase().includes(normOpt))) {
            matchedCount++;
          }
        }
        if (matchedCount >= 2 && matchedCount === finding.options.length) {
          signals.exactOptionListMatch = true;
        }
      }
      let matchedOption = null;
      let targetIndex = null;
      const targetIds = [finding.correctOptionId, finding.correctResponseId].filter(Boolean).map(String);
      if (targetIds.length > 0) {
        for (const opt of q.options) {
          const optIds = [
            opt.optionId,
            opt.value,
            opt.element?.getAttribute ? opt.element.getAttribute("data-option-id") : null,
            opt.element?.getAttribute ? opt.element.getAttribute("data-response-id") : null,
            opt.element?.id,
            opt.inputElement?.value
          ].filter(Boolean).map(String);
          if (targetIds.some((tid) => optIds.includes(tid))) {
            matchedOption = opt;
            targetIndex = opt.index;
            signals.answerMatchesOptionValue = true;
            signals.idMatchOnOption = true;
            break;
          }
        }
      }
      const authorList = finding.authorOptions || finding.options;
      if (!matchedOption && authorList && Array.isArray(authorList) && finding.answerIndex !== null && finding.answerIndex !== void 0) {
        const authorItem = authorList[finding.answerIndex];
        if (authorItem !== void 0) {
          const authorTargetText = typeof authorItem === "object" && authorItem !== null ? authorItem.text || authorItem.value || authorItem.label || authorItem.content : String(authorItem);
          const authorTargetId = typeof authorItem === "object" && authorItem !== null ? authorItem.id || authorItem.optionId || authorItem.responseId : null;
          if (authorTargetId) {
            const authorTargetIdStr = String(authorTargetId);
            for (const opt of q.options) {
              const optIds = [
                opt.optionId,
                opt.value,
                opt.element?.getAttribute ? opt.element.getAttribute("data-option-id") : null,
                opt.element?.getAttribute ? opt.element.getAttribute("data-response-id") : null,
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
          if (!matchedOption && authorTargetText) {
            const normTarget = normalizeText(String(authorTargetText));
            for (const opt of q.options) {
              if (opt.normalizedText === normTarget || opt.text && opt.text.trim().toLowerCase() === String(authorTargetText).trim().toLowerCase() || opt.value === String(authorTargetText) || opt.rawText && opt.rawText.toLowerCase().includes(normTarget)) {
                matchedOption = opt;
                targetIndex = opt.index;
                signals.answerMatchesOptionValue = true;
                break;
              }
            }
          }
        }
      }
      if (!matchedOption && finding.answerValue !== null && finding.answerValue !== void 0) {
        const valStr = String(finding.answerValue).trim();
        const normVal = normalizeText(valStr);
        if (valStr.length === 1 && /^[A-H]$/i.test(valStr)) {
          const letterIdx = parseOptionIndex(valStr);
          if (letterIdx !== null && letterIdx >= 0 && letterIdx < q.options.length) {
            targetIndex = letterIdx;
            matchedOption = q.options[letterIdx];
            signals.answerIndexMatchesOption = true;
          }
        }
        if (!matchedOption) {
          for (const opt of q.options) {
            if (opt.normalizedText === normVal || opt.text && opt.text.trim().toLowerCase() === valStr.toLowerCase() || opt.value === valStr) {
              matchedOption = opt;
              targetIndex = opt.index;
              signals.answerMatchesOptionValue = true;
              break;
            }
          }
        }
        if (!matchedOption) {
          for (const opt of q.options) {
            const optIds = [
              opt.optionId,
              opt.value,
              opt.element?.getAttribute ? opt.element.getAttribute("data-option-id") : null,
              opt.element?.getAttribute ? opt.element.getAttribute("data-response-id") : null,
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
      if (!matchedOption && finding.answerIndex !== null && finding.answerIndex !== void 0) {
        const idx = Number(finding.answerIndex);
        if (idx >= 0 && idx < q.options.length) {
          targetIndex = idx;
          matchedOption = q.options[idx];
          signals.answerIndexMatchesOption = true;
        }
      }
      if (!signals.exactQuestionIdMatch && !signals.exactQuestionTextMatch && !signals.normalizedQuestionTextMatch && !signals.domDirectAttribute) {
        return null;
      }
      const evalResult = ConfidenceEngine.evaluateSignals(signals);
      let displayAnswer = "";
      if (matchedOption) {
        displayAnswer = `Option ${matchedOption.index + 1} \u2014 ${matchedOption.text}`;
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
        matchedOption,
        answerValue: finding.answerValue,
        answerIndex: targetIndex,
        displayAnswer,
        source: finding.source || "Client-side application data",
        evidence: finding.evidence || "Discovered in browser state",
        confidence: evalResult.level,
        score: evalResult.score,
        reasons: evalResult.reasons
      };
    }
  };

  // src/content/detector.js
  var Detector = class {
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
    scan(doc = typeof document !== "undefined" ? document : null, win = typeof window !== "undefined" ? window : null) {
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
            statusText: "NO QUESTIONS DETECTED"
          }
        };
      }
      const domQuestions = DomAnalyzer.extractQuestions(doc);
      const scriptTags = Array.from(doc.querySelectorAll("script"));
      const scriptFindings = ScriptAnalyzer.analyzeScripts(scriptTags);
      const storageFindings = StorageAnalyzer.analyzeStorage(win);
      const allRawFindings = [
        ...scriptFindings,
        ...storageFindings,
        ...this.networkFindings
      ];
      const correlatedFindings = Correlator.correlate(domQuestions, allRawFindings);
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      for (const f of correlatedFindings) {
        if (f.confidence === ConfidenceLevel.HIGH) highCount++;
        else if (f.confidence === ConfidenceLevel.MEDIUM) mediumCount++;
        else if (f.confidence === ConfidenceLevel.LOW) lowCount++;
      }
      const hasExposure = highCount > 0 || mediumCount > 0;
      let statusText = "NO QUESTIONS DETECTED";
      if (domQuestions.length > 0) {
        statusText = hasExposure ? "CLIENT-SIDE ANSWER KEY DETECTED" : "NO CLIENT-SIDE ANSWER KEY DETECTED";
      }
      const results = {
        domQuestions,
        rawFindingsCount: allRawFindings.length,
        findings: correlatedFindings,
        metrics: {
          questionsDetected: domQuestions.length,
          answerMappingsCount: correlatedFindings.length,
          highCount,
          mediumCount,
          lowCount,
          hasExposure,
          statusText
        },
        timestamp: Date.now()
      };
      this.cachedResults = results;
      this.lastScanTime = Date.now();
      return results;
    }
  };

  // src/content/renderer.js
  var Renderer = class {
    /**
     * Renders security findings onto the inspected page
     * @param {Array<Object>} findings 
     * @param {boolean} [isAuthorized=true]
     */
    static render(findings, isAuthorized = true) {
      this.clear();
      if (!isAuthorized || !Array.isArray(findings)) return;
      for (const finding of findings) {
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
      if (q.element.querySelector(".quizkey-inspector-overlay")) return;
      if (finding.matchedOption && finding.matchedOption.element) {
        finding.matchedOption.element.classList.add("quizkey-highlighted-option");
        finding.matchedOption.element.setAttribute("data-quizkey-highlighted", "true");
      }
      const overlay = createElement("div", {
        className: `quizkey-inspector-overlay quizkey-confidence-${finding.confidence.toLowerCase()}`,
        role: "region",
        "aria-label": "QuizKey Inspector Audit Result",
        "data-quizkey-overlay": "true"
      });
      const header = createElement("div", { className: "quizkey-overlay-header" }, [
        createElement("span", { className: "quizkey-overlay-icon" }, "\u{1F50E}"),
        createElement("strong", { className: "quizkey-overlay-title" }, " QUIZKEY INSPECTOR")
      ]);
      const subtitle = createElement("div", { className: "quizkey-overlay-subtitle" }, "AUTHOR ANSWER KEY EXPOSED");
      const body = createElement("div", { className: "quizkey-overlay-body" });
      const correctOptRow = createElement("div", { className: "quizkey-overlay-row" }, [
        createElement("span", { className: "quizkey-overlay-label" }, "Correct option: "),
        createElement("strong", { className: "quizkey-overlay-answer" }, finding.displayAnswer || String(finding.answerValue))
      ]);
      body.appendChild(correctOptRow);
      const confidenceBadge = createElement("span", {
        className: `quizkey-badge quizkey-badge-${finding.confidence.toLowerCase()}`
      }, finding.confidence);
      const confidenceRow = createElement("div", { className: "quizkey-overlay-row" }, [
        createElement("span", { className: "quizkey-overlay-label" }, "Confidence: "),
        confidenceBadge
      ]);
      body.appendChild(confidenceRow);
      const evidenceText = finding.evidence || finding.source || "Client payload";
      const evidenceRow = createElement("div", { className: "quizkey-overlay-row" }, [
        createElement("span", { className: "quizkey-overlay-label" }, "Evidence: "),
        createElement("span", { className: "quizkey-overlay-evidence" }, evidenceText)
      ]);
      body.appendChild(evidenceRow);
      if (finding.questionId) {
        const qIdRow = createElement("div", { className: "quizkey-overlay-row quizkey-overlay-meta" }, [
          createElement("span", { className: "quizkey-overlay-label" }, "Question ID: "),
          createElement("span", {}, String(finding.questionId))
        ]);
        body.appendChild(qIdRow);
      }
      overlay.appendChild(header);
      overlay.appendChild(subtitle);
      overlay.appendChild(body);
      const lastOption = q.options && q.options.length > 0 ? q.options[q.options.length - 1].element : null;
      if (lastOption && lastOption.parentElement && lastOption.parentElement !== q.element) {
        lastOption.parentElement.insertAdjacentElement("afterend", overlay);
      } else {
        q.element.appendChild(overlay);
      }
    }
    /**
     * Removes all injected overlays and option highlights from the DOM
     */
    static clear() {
      const overlays = document.querySelectorAll('[data-quizkey-overlay="true"], .quizkey-inspector-overlay');
      overlays.forEach((o) => o.remove());
      const highlighted = document.querySelectorAll('[data-quizkey-highlighted="true"], .quizkey-highlighted-option');
      highlighted.forEach((el) => {
        el.classList.remove("quizkey-highlighted-option");
        el.removeAttribute("data-quizkey-highlighted");
      });
    }
  };

  // src/content/observers.js
  var DomObserver = class {
    /**
     * @param {function(): void} onTriggerCallback 
     * @param {number} [debounceMs=250] 
     */
    constructor(onTriggerCallback, debounceMs = 250) {
      this.callback = onTriggerCallback;
      this.debounceMs = debounceMs;
      this.timer = null;
      this.observer = null;
      this.isObserving = false;
    }
    /**
     * Starts observing the DOM
     * @param {Node} [target=document.body] 
     */
    start(target = typeof document !== "undefined" ? document.body : null) {
      if (!target || typeof MutationObserver === "undefined") return;
      if (this.isObserving) return;
      this.observer = new MutationObserver((mutations) => {
        let isRelevant = false;
        for (const m of mutations) {
          if (m.type === "childList" && m.addedNodes.length > 0) {
            for (let i = 0; i < m.addedNodes.length; i++) {
              const node = m.addedNodes[i];
              if (node.nodeType === Node.ELEMENT_NODE) {
                const el = (
                  /** @type {HTMLElement} */
                  node
                );
                if (el.classList && (el.classList.contains("ass-scanner-panel") || el.hasAttribute("data-ass-scanner-panel"))) {
                  continue;
                }
                if (el.querySelector && (el.querySelector("input, fieldset, [data-question-id], .question, .option") || el.tagName === "INPUT" || el.tagName === "SCRIPT")) {
                  isRelevant = true;
                  break;
                }
              }
            }
          }
          if (isRelevant) break;
        }
        if (isRelevant) {
          this.debouncedTrigger();
        }
      });
      this.observer.observe(target, {
        childList: true,
        subtree: true
      });
      this.isObserving = true;
    }
    /**
     * Debounced callback trigger
     */
    debouncedTrigger() {
      if (this.timer) {
        clearTimeout(this.timer);
      }
      this.timer = setTimeout(() => {
        if (typeof this.callback === "function") {
          this.callback();
        }
      }, this.debounceMs);
    }
    /**
     * Stops observing
     */
    stop() {
      if (this.observer) {
        this.observer.disconnect();
        this.observer = null;
      }
      if (this.timer) {
        clearTimeout(this.timer);
        this.timer = null;
      }
      this.isObserving = false;
    }
  };

  // src/analysis/network-analyzer.js
  var NetworkAnalyzer = class {
    /**
     * Analyzes an intercepted network payload
     * @param {{ url: string, method: string, data: any }} payload 
     * @returns {Array<Object>} List of candidate findings
     */
    static analyzeResponse(payload) {
      if (!payload || !payload.data) return [];
      const url = payload.url || "API Endpoint";
      const source = `API Response: ${url}`;
      const findings = JsonAnalyzer.analyze(payload.data, source);
      return findings.map((f) => ({
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
            if (findings.length > 0 && typeof onFindingsCallback === "function") {
              onFindingsCallback(findings);
            }
          }
        } catch {
        }
      };
      document.addEventListener("__quizkey_network_data__", handler);
      return () => {
        document.removeEventListener("__quizkey_network_data__", handler);
      };
    }
  };

  // src/content/content.js
  var QuizKeyContentController = class {
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
      await this.checkAuthorization();
      this.cleanupNetwork = NetworkAnalyzer.listenForNetworkEvents((networkFindings) => {
        this.detector.addNetworkFindings(networkFindings);
        if (this.isAuthorized) {
          this.runScan();
        }
      });
      this.observer = new DomObserver(() => {
        if (this.isAuthorized) {
          this.runScan();
        }
      }, 250);
      this.observer.start(document.body);
      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
          this.handleMessage(request, sendResponse);
          return true;
        });
      }
      if (this.isAuthorized) {
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", () => this.runScan());
        } else {
          this.runScan();
        }
      }
    }
    /**
     * Checks authorization status for the current domain
     */
    async checkAuthorization() {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        try {
          const data = await chrome.storage.local.get(["authorizedDomains"]);
          const domains = data.authorizedDomains || [];
          this.isAuthorized = isDomainAuthorized(this.currentDomain, domains);
        } catch {
          this.isAuthorized = false;
        }
      } else {
        this.isAuthorized = false;
      }
      return this.isAuthorized;
    }
    /**
     * Authorizes the current domain and starts scanning
     */
    async authorizeCurrentSite() {
      this.isAuthorized = true;
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        try {
          const data = await chrome.storage.local.get(["authorizedDomains"]);
          const domains = data.authorizedDomains || [];
          if (!isDomainAuthorized(this.currentDomain, domains)) {
            domains.push(this.currentDomain);
            await chrome.storage.local.set({ authorizedDomains: domains });
          }
        } catch {
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
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        try {
          const data = await chrome.storage.local.get(["authorizedDomains"]);
          const domains = (data.authorizedDomains || []).filter(
            (d) => (d || "").toLowerCase() !== this.currentDomain.toLowerCase()
          );
          await chrome.storage.local.set({ authorizedDomains: domains });
        } catch {
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
        case "GET_STATUS":
        case "GET_SCAN_STATUS": {
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
        case "AUTHORIZE_SITE": {
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
        case "DISABLE_SITE": {
          await this.disableCurrentSite();
          sendResponse({
            success: true,
            isAuthorized: false,
            currentDomain: this.currentDomain
          });
          break;
        }
        case "SCAN_PAGE":
        case "RESCAN": {
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
        case "CLEAR_FINDINGS": {
          this.detector.clear();
          Renderer.clear();
          sendResponse({ success: true });
          break;
        }
        default:
          sendResponse({ success: false, error: "Unknown action" });
      }
    }
    /**
     * Serializes findings safely without DOM node handles
     */
    serializeFindings(findings) {
      if (!Array.isArray(findings)) return [];
      return findings.map((f) => ({
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
      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        try {
          chrome.runtime.sendMessage({
            action: "UPDATE_SCAN_METRICS",
            isAuthorized: this.isAuthorized,
            metrics
          }).catch(() => {
          });
        } catch {
        }
      }
    }
  };
  var quizKeyContent = new QuizKeyContentController();
  quizKeyContent.init();
})();
