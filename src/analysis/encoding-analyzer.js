/**
 * Assessment Security Scanner - Encoding Analyzer
 * 
 * Safely recognizes and decodes common client-side encoding schemes:
 * - Base64
 * - URL encoding
 * - Escaped / double-serialized JSON
 * - Unicode escape sequences
 * 
 * Note: Never executes decoded content. Decoding is strictly for inspection.
 */

export class EncodingAnalyzer {
  /**
   * Attempts to safely decode Base64 strings
   * @param {string} str 
   * @returns {{ success: boolean, decoded: string|null, isJson: boolean, parsedJson: any }}
   */
  static decodeBase64(str) {
    if (typeof str !== 'string' || str.length < 4) {
      return { success: false, decoded: null, isJson: false, parsedJson: null };
    }

    // Quick regex check for Base64 characters and padding
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    const cleanStr = str.trim();
    if (!base64Regex.test(cleanStr)) {
      return { success: false, decoded: null, isJson: false, parsedJson: null };
    }

    try {
      let decodedStr;
      if (typeof atob === 'function') {
        decodedStr = atob(cleanStr);
      } else if (typeof Buffer !== 'undefined') {
        decodedStr = Buffer.from(cleanStr, 'base64').toString('utf-8');
      } else {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }

      // Ensure decoded string doesn't contain unprintable garbage
      // Check if it's mostly printable ASCII or valid UTF-8
      const isPrintable = /^[\x20-\x7E\s\u00A0-\uFFFF]*$/.test(decodedStr);
      if (!isPrintable || decodedStr.length === 0) {
        return { success: false, decoded: null, isJson: false, parsedJson: null };
      }

      // Check if decoded string is JSON
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
    if (typeof str !== 'string' || !str.includes('%')) {
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
    if (typeof str !== 'string') {
      return { success: false, data: null };
    }
    const trimmed = str.trim();
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      // Check if it is a quoted JSON string: "{\"a\": 1}"
      if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length > 4) {
        try {
          const unescaped = JSON.parse(trimmed);
          if (typeof unescaped === 'string') {
            return this.parseJsonSafe(unescaped);
          }
        } catch {
          // ignore
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
    if (typeof value !== 'string') return [];
    const results = [];

    // Check direct JSON
    const directJson = this.parseJsonSafe(value);
    if (directJson.success) {
      results.push({
        type: 'json',
        raw: value,
        decoded: directJson.data,
        isJson: true
      });
    }

    // Check Base64
    const b64 = this.decodeBase64(value);
    if (b64.success) {
      results.push({
        type: 'base64',
        raw: value,
        decoded: b64.isJson ? b64.parsedJson : b64.decoded,
        isJson: b64.isJson
      });
    }

    // Check URL encoding
    const url = this.decodeUrl(value);
    if (url.success) {
      results.push({
        type: 'url',
        raw: value,
        decoded: url.isJson ? url.parsedJson : url.decoded,
        isJson: url.isJson
      });
    }

    return results;
  }
}
