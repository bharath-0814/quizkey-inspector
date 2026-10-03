/**
 * Automated Tests: Storage Analyzer
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { StorageAnalyzer } from '../src/analysis/storage-analyzer.js';

test('StorageAnalyzer - detects JSON quiz data in storage item', () => {
  const jsonVal = JSON.stringify({
    questions: [
      {
        id: 20,
        question: "Which symmetric encryption algorithm uses 256-bit keys?",
        options: ["DES", "RSA", "AES-256", "MD5"],
        correctAnswer: "AES-256"
      }
    ]
  });

  const findings = StorageAnalyzer.analyzeStorageItem('quiz_state', jsonVal, 'localStorage');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].questionId, "20");
  assert.strictEqual(findings[0].answerValue, "AES-256");
});

test('StorageAnalyzer - detects direct suspicious key name with answer', () => {
  const findings = StorageAnalyzer.analyzeStorageItem('assessment_answer_1', 'B', 'localStorage');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].answerValue, 'B');
  assert.strictEqual(findings[0].questionId, '1');
});

test('StorageAnalyzer - SECURE CASE: benign storage items produce 0 findings', () => {
  assert.strictEqual(StorageAnalyzer.analyzeStorageItem('theme', 'dark', 'localStorage').length, 0);
  assert.strictEqual(StorageAnalyzer.analyzeStorageItem('user_session', 'token_xyz123', 'sessionStorage').length, 0);
  assert.strictEqual(StorageAnalyzer.analyzeStorageItem('font_size', '14px', 'localStorage').length, 0);
});
