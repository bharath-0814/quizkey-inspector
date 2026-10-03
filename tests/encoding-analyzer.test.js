/**
 * Automated Tests: Encoding Analyzer
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { EncodingAnalyzer } from '../src/analysis/encoding-analyzer.js';

test('EncodingAnalyzer - decode Base64 encoded JSON', () => {
  // eyJjb3JyZWN0SW5kZXgiOjEsImFuc3dlciI6IlVEUCJ9 -> {"correctIndex":1,"answer":"UDP"}
  const raw = 'eyJjb3JyZWN0SW5kZXgiOjEsImFuc3dlciI6IlVEUCJ9';
  const res = EncodingAnalyzer.decodeBase64(raw);

  assert.strictEqual(res.success, true);
  assert.strictEqual(res.isJson, true);
  assert.strictEqual(res.parsedJson.correctIndex, 1);
  assert.strictEqual(res.parsedJson.answer, 'UDP');
});

test('EncodingAnalyzer - decode Base64 encoded plaintext answer', () => {
  // "Option B" -> T3B0aW9uIEI=
  const raw = 'T3B0aW9uIEI=';
  const res = EncodingAnalyzer.decodeBase64(raw);

  assert.strictEqual(res.success, true);
  assert.strictEqual(res.decoded, 'Option B');
});

test('EncodingAnalyzer - decode URL-encoded JSON payload', () => {
  const urlEncoded = '%7B%22correct%22%3A%22B%22%7D';
  const res = EncodingAnalyzer.decodeUrl(urlEncoded);

  assert.strictEqual(res.success, true);
  assert.strictEqual(res.isJson, true);
  assert.strictEqual(res.parsedJson.correct, 'B');
});

test('EncodingAnalyzer - safely parse escaped JSON string', () => {
  const escaped = '"{\\"correctIndex\\": 2, \\"answer\\": \\"4\\"} "';
  const res = EncodingAnalyzer.parseJsonSafe(escaped);

  assert.strictEqual(res.success, true);
  assert.strictEqual(res.data.correctIndex, 2);
  assert.strictEqual(res.data.answer, '4');
});

test('EncodingAnalyzer - invalid base64 or garbage handled safely without crash', () => {
  const garbage = 'not-a-valid-base64-string!!@@';
  const res = EncodingAnalyzer.decodeBase64(garbage);
  assert.strictEqual(res.success, false);
});

test('EncodingAnalyzer - non-string or null input handled gracefully', () => {
  assert.strictEqual(EncodingAnalyzer.decodeBase64(null).success, false);
  assert.strictEqual(EncodingAnalyzer.decodeBase64(undefined).success, false);
  assert.strictEqual(EncodingAnalyzer.decodeBase64(12345).success, false);
  assert.strictEqual(EncodingAnalyzer.decodeUrl(null).success, false);
});
