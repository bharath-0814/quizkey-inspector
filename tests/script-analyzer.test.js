/**
 * Automated Tests: Script Analyzer
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { ScriptAnalyzer } from '../src/analysis/script-analyzer.js';

test('ScriptAnalyzer - extracts questions array with correctAnswer from JavaScript code', () => {
  const code = `
    const questions = [
      {
        id: 1,
        question: "What is 2 + 2?",
        options: ["3", "4", "5", "6"],
        correctAnswer: "4"
      }
    ];
  `;

  const findings = ScriptAnalyzer.analyzeScriptText(code, 'Test Script');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].questionId, "1");
  assert.strictEqual(findings[0].answerValue, "4");
});

test('ScriptAnalyzer - handles unquoted keys and single quotes safely without eval', () => {
  const code = `
    var quiz = [
      {
        id: 'q42',
        question: 'Which protocol is connectionless?',
        options: ['TCP', 'UDP', 'FTP', 'SSH'],
        correctIndex: 1
      }
    ];
  `;

  const findings = ScriptAnalyzer.analyzeScriptText(code, 'Unquoted Script');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].questionId, "q42");
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].answerValue, "UDP");
});

test('ScriptAnalyzer - parses JSON.parse strings inside script', () => {
  const code = `
    const state = JSON.parse('{"id": 5, "question": "Capital of France?", "options": ["Paris", "Rome"], "correctAnswer": "Paris"}');
  `;

  const findings = ScriptAnalyzer.analyzeScriptText(code, 'JSON.parse Script');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].answerValue, "Paris");
});

test('ScriptAnalyzer - SECURE CASE: script without answer properties produces 0 findings', () => {
  const secureCode = `
    const secureQuestions = [
      {
        id: 101,
        question: "What is 2 + 2?",
        options: ["3", "4", "5", "6"]
      }
    ];
    function onSelect(idx) { console.log("selected", idx); }
  `;

  const findings = ScriptAnalyzer.analyzeScriptText(secureCode, 'Secure Script');
  assert.strictEqual(findings.length, 0, 'Secure script must produce 0 findings');
});

test('ScriptAnalyzer - benign script mentioning "correct" in comment or logic without answer data', () => {
  const benignCode = `
    // Check if the user selected something
    function validateForm() {
      const isInputCorrectFormat = true;
      if (!isInputCorrectFormat) return false;
      return true;
    }
  `;

  const findings = ScriptAnalyzer.analyzeScriptText(benignCode, 'Benign Script');
  assert.strictEqual(findings.length, 0, 'Benign code must produce 0 findings');
});
