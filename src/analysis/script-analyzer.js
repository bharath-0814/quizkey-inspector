/**
 * Assessment Security Scanner - Script Analyzer
 * 
 * Safely analyzes inline scripts and accessible JavaScript resources
 * without executing arbitrary code (NO eval, NO new Function).
 * 
 * Extracts structured data literals representing quiz items and answers.
 */

import { JsonAnalyzer } from './json-analyzer.js';
import { EncodingAnalyzer } from './encoding-analyzer.js';

export class ScriptAnalyzer {
  /**
   * Analyzes an array of script elements or raw script strings
   * @param {Array<HTMLScriptElement|string>} scripts 
   * @returns {Array<Object>} List of candidate findings
   */
  static analyzeScripts(scripts) {
    const allFindings = [];

    for (const item of scripts) {
      let scriptContent = '';
      let scriptType = 'text/javascript';
      let scriptId = '';

      if (typeof item === 'string') {
        scriptContent = item;
      } else if (item && typeof item === 'object') {
        scriptContent = item.textContent || item.innerText || '';
        scriptType = (item.getAttribute('type') || 'text/javascript').toLowerCase();
        scriptId = item.id || item.className || '';
      }

      if (!scriptContent || scriptContent.trim().length === 0) {
        continue;
      }

      // 1. If script is application/json or similar data script
      if (scriptType.includes('json') || scriptId.includes('data') || scriptId.includes('state')) {
        const parsed = EncodingAnalyzer.parseJsonSafe(scriptContent);
        if (parsed.success) {
          const findings = JsonAnalyzer.analyze(parsed.data, `Embedded Script JSON (<script id="${scriptId}">)`);
          allFindings.push(...findings);
          continue;
        }
      }

      // 2. Parse inline JavaScript for structured objects
      const jsFindings = this.analyzeScriptText(scriptContent, scriptId ? `Inline Script (#${scriptId})` : 'Inline Script');
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
  static analyzeScriptText(code, sourceName = 'Inline Script') {
    const findings = [];

    // 1. Look for embedded JSON strings: JSON.parse('...') or JSON.parse("...")
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
        // ignore
      }
    }

    // 2. Look for Base64 strings in script that decode to JSON or assessment data
    const b64Regex = /['"](eyJ[A-Za-z0-9+/=]{10,})['"]/g;
    while ((match = b64Regex.exec(code)) !== null) {
      const decoded = EncodingAnalyzer.decodeBase64(match[1]);
      if (decoded.success && decoded.isJson) {
        const res = JsonAnalyzer.analyze(decoded.parsedJson, `${sourceName} [Decoded Base64]`);
        findings.push(...res);
      }
    }

    // 3. Extract array or object literals containing quiz indicators
    // Detect patterns like `const questions = [ ... ]` or `{ question: "...", options: [...], correctAnswer: "..." }`
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
    if (typeof code !== 'string') return results;

    // Check if the script contains assessment or answer-related keywords before parsing
    const hasKeyword = /(?:correct|solution|answer|isCorrect|score|points|weight)/i.test(code);
    if (!hasKeyword) {
      return results;
    }

    // Find assignments: `= \s* [ { or [ ]`
    const assignmentRegex = /=\s*([{\[])/g;
    let match;

    while ((match = assignmentRegex.exec(code)) !== null) {
      const startIndex = match.index + match[0].length - 1; // index of '{' or '['
      const literalStr = this.extractBalancedLiteral(code, startIndex);
      if (literalStr) {
        const parsed = this.safeParseJsLiteral(literalStr);
        if (parsed && typeof parsed === 'object') {
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
    if (startChar !== '{' && startChar !== '[') return null;

    let depth = 0;
    let inString = false;
    let stringQuote = '';
    let inLineComment = false;
    let inBlockComment = false;

    for (let i = startIndex; i < code.length; i++) {
      const ch = code[i];
      const prev = i > 0 ? code[i - 1] : '';

      // Line comments
      if (inLineComment) {
        if (ch === '\n' || ch === '\r') {
          inLineComment = false;
        }
        continue;
      }

      // Block comments
      if (inBlockComment) {
        if (ch === '/' && prev === '*') {
          inBlockComment = false;
        }
        continue;
      }

      // Strings
      if (inString) {
        if (ch === stringQuote && prev !== '\\') {
          inString = false;
        }
        continue;
      }

      // Check comments start
      if (ch === '/' && code[i + 1] === '/') {
        inLineComment = true;
        i++;
        continue;
      }
      if (ch === '/' && code[i + 1] === '*') {
        inBlockComment = true;
        i++;
        continue;
      }

      // Check string start
      if (ch === '"' || ch === "'" || ch === '`') {
        inString = true;
        stringQuote = ch;
        continue;
      }

      // Brackets depth
      if (ch === '{' || ch === '[') {
        depth++;
      } else if (ch === '}' || ch === ']') {
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
    if (!literalStr || typeof literalStr !== 'string') return null;

    try {
      // 1. Try direct JSON parse first
      return JSON.parse(literalStr);
    } catch {
      // Continue to sanitizer
    }

    try {
      // 2. Clean and convert to JSON format safely
      let cleaned = literalStr
        // Remove comments
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*/g, '')
        // Replace single quotes with double quotes (handling escaped quotes)
        .replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, (m, content) => {
          return `"${content.replace(/"/g, '\\"')}"`;
        })
        // Wrap unquoted object keys in double quotes
        // Matches word followed by colon: `id:` -> `"id":`
        .replace(/([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:/g, '$1"$2":')
        // Remove trailing commas before } or ]
        .replace(/,\s*([}\]])/g, '$1')
        .trim();

      return JSON.parse(cleaned);
    } catch {
      return null;
    }
  }
}
