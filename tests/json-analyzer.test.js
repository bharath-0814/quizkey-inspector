/**
 * Automated Tests: JSON & Application State Analyzer
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { JsonAnalyzer } from '../src/analysis/json-analyzer.js';
import { ExposureCategory } from '../src/shared/types.js';

test('JsonAnalyzer - detects exact correctAnswer property', () => {
  const payload = {
    id: 1,
    question: "What is 2 + 2?",
    options: ["3", "4", "5", "6"],
    correctAnswer: "4"
  };

  const findings = JsonAnalyzer.analyze(payload, 'Test Source');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].category, ExposureCategory.ANSWER_KEY);
  assert.strictEqual(findings[0].questionId, "1");
  assert.strictEqual(findings[0].answerValue, "4");
  assert.strictEqual(findings[0].answerIndex, 1); // 4 is index 1
});

test('JsonAnalyzer - detects numeric correctIndex property', () => {
  const payload = {
    id: 42,
    question: "Which protocol is connectionless?",
    options: ["TCP", "UDP", "FTP", "SSH"],
    correctIndex: 1
  };

  const findings = JsonAnalyzer.analyze(payload, 'API Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].questionId, "42");
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].answerValue, "UDP");
});

test('JsonAnalyzer - detects deeply nested questions array in assessment tree', () => {
  const deepState = {
    exam: {
      sections: [
        {
          title: "Math",
          questions: [
            {
              id: "m1",
              prompt: "What is 10 * 10?",
              choices: ["10", "50", "100", "200"],
              solutionIndex: 2
            }
          ]
        }
      ]
    }
  };

  const findings = JsonAnalyzer.analyze(deepState, 'Nested State');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].questionId, "m1");
  assert.strictEqual(findings[0].answerIndex, 2);
  assert.strictEqual(findings[0].answerValue, "100");
});

test('JsonAnalyzer - detects options with embedded isCorrect: true flags', () => {
  const payload = {
    id: "q99",
    question: "Select the primary color",
    options: [
      { text: "Green", isCorrect: false },
      { text: "Blue", isCorrect: true },
      { text: "Purple", isCorrect: false }
    ]
  };

  const findings = JsonAnalyzer.analyze(payload, 'Option Flags');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].answerValue, "Blue");
});

test('JsonAnalyzer - detects answerKey dictionary mapping', () => {
  const payload = {
    quizTitle: "Final Exam",
    answerKey: {
      "1": "B",
      "2": "UDP",
      "3": 0
    }
  };

  const findings = JsonAnalyzer.analyze(payload, 'Answer Dictionary');
  assert.strictEqual(findings.length, 3);
  assert.strictEqual(findings[0].answerValue, "B");
  assert.strictEqual(findings[1].answerValue, "UDP");
  assert.strictEqual(findings[2].answerValue, 0);
});

test('JsonAnalyzer - detects solutions array', () => {
  const payload = {
    solutions: [1, 3, 0]
  };

  const findings = JsonAnalyzer.analyze(payload, 'Solutions Array');
  assert.strictEqual(findings.length, 3);
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[1].answerIndex, 3);
  assert.strictEqual(findings[2].answerIndex, 0);
});

test('JsonAnalyzer - SECURE CASE: question without answers produces 0 findings', () => {
  const securePayload = {
    id: 101,
    question: "What is 2 + 2?",
    options: ["3", "4", "5", "6"]
  };

  const findings = JsonAnalyzer.analyze(securePayload, 'Secure Server Payload');
  assert.strictEqual(findings.length, 0, 'Secure payload must produce zero findings');
});

test('JsonAnalyzer - SECURE CASE: question list without answers produces 0 findings', () => {
  const securePayload = {
    assessment: "Midterm",
    questions: [
      { id: 1, text: "Question 1", options: ["A", "B", "C"] },
      { id: 2, text: "Question 2", options: ["X", "Y", "Z"] }
    ]
  };

  const findings = JsonAnalyzer.analyze(securePayload, 'Secure Exam Payload');
  assert.strictEqual(findings.length, 0, 'Secure questions must produce zero findings');
});

test('JsonAnalyzer - detects correctOptionId matching an option in choices', () => {
  const payload = {
    id: "q-101",
    question: "Which protocol is connectionless?",
    choices: [
      { id: "opt_tcp", text: "TCP" },
      { id: "opt_udp", text: "UDP" },
      { id: "opt_ftp", text: "FTP" }
    ],
    correctOptionId: "opt_udp"
  };

  const findings = JsonAnalyzer.analyze(payload, 'Author Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].correctOptionId, "opt_udp");
  assert.strictEqual(findings[0].answerValue, "UDP");
  assert.strictEqual(findings[0].answerIndex, 1);
});

test('JsonAnalyzer - detects correctResponseId matching an option in responses', () => {
  const payload = {
    id: "q-202",
    question: "Which protocol is connectionless?",
    responses: [
      { responseId: "resp_1", text: "TCP" },
      { responseId: "resp_2", text: "UDP" }
    ],
    correctResponseId: "resp_2"
  };

  const findings = JsonAnalyzer.analyze(payload, 'Author Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].correctResponseId, "resp_2");
  assert.strictEqual(findings[0].answerValue, "UDP");
  assert.strictEqual(findings[0].answerIndex, 1);
});

test('JsonAnalyzer - detects author response scoring (score > 0 indicates correct answer)', () => {
  const payload = {
    id: "q-303",
    question: "Which protocol is connectionless?",
    options: [
      { id: "c1", text: "TCP", score: 0 },
      { id: "c2", text: "UDP", score: 1 },
      { id: "c3", text: "FTP", score: 0 }
    ]
  };

  const findings = JsonAnalyzer.analyze(payload, 'Scoring Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].isScoringRule, true);
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].answerValue, "UDP");
  assert.strictEqual(findings[0].correctOptionId, "c2");
});

test('JsonAnalyzer - detects author points weighting (points > 0 indicates correct answer)', () => {
  const payload = {
    id: "q-404",
    question: "What is 2 + 2?",
    choices: [
      { text: "3", points: 0 },
      { text: "4", points: 10 },
      { text: "5", points: 0 }
    ]
  };

  const findings = JsonAnalyzer.analyze(payload, 'Points Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].isScoringRule, true);
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].answerValue, "4");
});

test('JsonAnalyzer - detects correctResponse object with id and text', () => {
  const payload = {
    id: "q-505",
    question: "Which protocol is connectionless?",
    options: ["TCP", "UDP", "FTP"],
    correctResponse: { id: "opt-udp", text: "UDP" }
  };

  const findings = JsonAnalyzer.analyze(payload, 'Object Response Payload');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].answerValue, "UDP");
  assert.strictEqual(findings[0].answerIndex, 1);
  assert.strictEqual(findings[0].correctOptionId, "opt-udp");
});
