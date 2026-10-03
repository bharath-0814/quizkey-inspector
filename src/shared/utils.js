/**
 * QuizKey Inspector - Shared Utilities
 * 
 * Safe text normalization, sanitization, and helper functions.
 * All operations treat page content as untrusted input.
 */

/**
 * Extracts a normalized domain identifier from a URL string
 * @param {string} urlString 
 * @returns {string}
 */
export function getDomainFromUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') return 'unknown';
  if (urlString.startsWith('file://')) return 'local-files (file://)';
  try {
    const parsed = new URL(urlString);
    return parsed.hostname || 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Checks whether a given domain is in the authorized audit list
 * @param {string} domain 
 * @param {Array<string>} authorizedList 
 * @returns {boolean}
 */
export function isDomainAuthorized(domain, authorizedList) {
  if (!Array.isArray(authorizedList)) return false;
  const cleanDomain = (domain || '').trim().toLowerCase();
  return authorizedList.some(d => (d || '').trim().toLowerCase() === cleanDomain);
}

/**
 * Normalizes question or option text for accurate comparison:
 * - Trims whitespace
 * - Collapses repeated whitespace
 * - Removes leading numbering/letters like "1.", "Q1:", "A)", "a."
 * - Lowercases for case-insensitive matching
 * 
 * @param {string} text 
 * @returns {string}
 */
export function normalizeText(text) {
  if (typeof text !== 'string') return '';
  return text
    .trim()
    .replace(/^([qQ]\d+[:.)-]?|\d+[:.)-]|[a-zA-Z][:.)-])\s*/, '')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

/**
 * Strips formatting punctuation for fuzzy comparison
 * @param {string} text 
 * @returns {string}
 */
export function cleanPunctuation(text) {
  if (typeof text !== 'string') return '';
  return text.replace(/[?.,!;:()'"[\]{}]/g, '').trim().toLowerCase();
}

/**
 * Calculates simple similarity between two strings (0.0 to 1.0)
 * Uses Jaccard word-set similarity for robust sentence matching
 * @param {string} a 
 * @param {string} b 
 * @returns {number}
 */
export function calculateTextSimilarity(a, b) {
  const normA = cleanPunctuation(normalizeText(a));
  const normB = cleanPunctuation(normalizeText(b));

  if (!normA || !normB) return 0;
  if (normA === normB) return 1.0;
  if (normA.includes(normB) || normB.includes(normA)) {
    const ratio = Math.min(normA.length, normB.length) / Math.max(normA.length, normB.length);
    return Math.max(0.8, ratio);
  }

  const wordsA = new Set(normA.split(/\s+/).filter(w => w.length > 2));
  const wordsB = new Set(normB.split(/\s+/).filter(w => w.length > 2));

  if (wordsA.size === 0 || wordsB.size === 0) return 0;

  let intersection = 0;
  for (const word of wordsA) {
    if (wordsB.has(word)) intersection++;
  }

  const union = new Set([...wordsA, ...wordsB]).size;
  return union > 0 ? intersection / union : 0;
}

/**
 * Safely creates an element with text content and attributes
 * Avoids any innerHTML XSS vulnerabilities.
 * 
 * @param {string} tag 
 * @param {Object} [attributes] 
 * @param {string|Array<Node|string>} [children] 
 * @returns {HTMLElement}
 */
export function createElement(tag, attributes = {}, children = []) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key === 'className') {
      el.className = value;
    } else if (key === 'style' && typeof value === 'object') {
      Object.assign(el.style, value);
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value !== null && value !== undefined) {
      el.setAttribute(key, String(value));
    }
  }

  const childList = Array.isArray(children) ? children : [children];
  for (const child of childList) {
    if (child instanceof Node) {
      el.appendChild(child);
    } else if (child !== null && child !== undefined) {
      el.appendChild(document.createTextNode(String(child)));
    }
  }

  return el;
}

/**
 * Safely extracts visible text from an element
 * @param {Element} element 
 * @returns {string}
 */
export function extractTextContent(element) {
  if (!element) return '';
  return (element.textContent || '').trim();
}

/**
 * Generates a stable hash or identifier for a question
 * @param {string} text 
 * @param {string|number} [id] 
 * @returns {string}
 */
export function generateQuestionKey(text, id) {
  if (id !== undefined && id !== null && String(id).trim() !== '') {
    return `qid_${String(id).trim()}`;
  }
  const normalized = normalizeText(text);
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    hash = (hash << 5) - hash + normalized.charCodeAt(i);
    hash |= 0;
  }
  return `qhash_${Math.abs(hash)}`;
}

/**
 * Check if a string looks like a common option label ('A', 'B', '1', '2', etc.)
 * @param {string} val 
 * @returns {number|null} 0-based index or null
 */
export function parseOptionIndex(val) {
  if (typeof val === 'number') {
    return val;
  }
  if (typeof val !== 'string') return null;
  const trimmed = val.trim().toUpperCase();

  // Check numeric index (e.g. "0", "1", "2")
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }

  // Check single letter ("A" -> 0, "B" -> 1, "C" -> 2, "D" -> 3)
  if (/^[A-H]$/.test(trimmed)) {
    return trimmed.charCodeAt(0) - 65;
  }

  // Check "Option 1" or "Choice A"
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
