/**
 * Assessment Security Scanner - Storage Analyzer
 * 
 * Inspects client-accessible browser storage:
 * - localStorage
 * - sessionStorage
 * - IndexedDB
 * 
 * Safely decodes stored strings and identifies leaked assessment answers.
 */

import { JsonAnalyzer } from './json-analyzer.js';
import { EncodingAnalyzer } from './encoding-analyzer.js';
import { ExposureCategory } from '../shared/types.js';

export class StorageAnalyzer {
  /**
   * Scans localStorage and sessionStorage
   * @param {Window} [win=window]
   * @returns {Array<Object>}
   */
  static analyzeStorage(win = typeof window !== 'undefined' ? window : null) {
    if (!win) return [];
    const findings = [];

    // Analyze localStorage
    try {
      if (win.localStorage && win.localStorage.length > 0) {
        for (let i = 0; i < win.localStorage.length; i++) {
          const key = win.localStorage.key(i);
          if (!key) continue;
          const val = win.localStorage.getItem(key);
          const res = this.analyzeStorageItem(key, val, 'localStorage');
          findings.push(...res);
        }
      }
    } catch {
      // Storage access may be restricted by permissions/origin
    }

    // Analyze sessionStorage
    try {
      if (win.sessionStorage && win.sessionStorage.length > 0) {
        for (let i = 0; i < win.sessionStorage.length; i++) {
          const key = win.sessionStorage.key(i);
          if (!key) continue;
          const val = win.sessionStorage.getItem(key);
          const res = this.analyzeStorageItem(key, val, 'sessionStorage');
          findings.push(...res);
        }
      }
    } catch {
      // ignore
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
    if (!val || typeof val !== 'string') return [];
    const findings = [];
    const source = `${storageType}['${key}']`;

    // 1. Direct JSON parse
    const jsonParsed = EncodingAnalyzer.parseJsonSafe(val);
    if (jsonParsed.success) {
      const res = JsonAnalyzer.analyze(jsonParsed.data, source);
      findings.push(...res);
    }

    // 2. Base64 decoded check
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
          source: source,
          evidence: `Suspicious storage key "${key}" contains Base64 decoded value: "${b64.decoded}"`,
          structural: false
        });
      }
    }

    // 3. Direct suspicious key check (e.g. key is "quiz_answer_1" and value is "B")
    if (this.isKeyNameSuspicious(key) && findings.length === 0) {
      findings.push({
        category: ExposureCategory.BROWSER_STORAGE,
        questionId: this.extractIdFromKey(key),
        questionText: null,
        answerValue: val,
        answerIndex: null,
        source: source,
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
    return match ? (match[1] || match[2]) : null;
  }

  /**
   * Asynchronously inspects accessible IndexedDB databases where supported
   * @returns {Promise<Array<Object>>}
   */
  static async analyzeIndexedDB() {
    if (typeof indexedDB === 'undefined' || !indexedDB.databases) {
      return [];
    }

    const findings = [];
    try {
      const dbs = await indexedDB.databases();
      for (const dbInfo of dbs) {
        if (!dbInfo.name) continue;
        const lowerName = dbInfo.name.toLowerCase();
        // Only inspect assessment-related databases
        if (lowerName.includes('quiz') || lowerName.includes('assessment') || lowerName.includes('exam') || lowerName.includes('test')) {
          // Open database safely in read-only mode
          try {
            const openReq = indexedDB.open(dbInfo.name);
            await new Promise((resolve) => {
              openReq.onsuccess = (e) => {
                const db = e.target.result;
                const storeNames = Array.from(db.objectStoreNames);
                for (const storeName of storeNames) {
                  try {
                    const tx = db.transaction(storeName, 'readonly');
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
            // ignore
          }
        }
      }
    } catch {
      // ignore
    }

    return findings;
  }
}
