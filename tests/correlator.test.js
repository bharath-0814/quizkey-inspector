/**
 * Automated Tests: Correlator & Confidence Engine
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { Correlator } from '../src/analysis/correlator.js';
import { ConfidenceLevel } from '../src/shared/types.js';

test('Correlator - exact question ID and answer value produces HIGH confidence', () => {
  const domQuestions = [
    {
      questionId: "1",
      questionText: "What is 2 + 2?",
      normalizedText: "what is 2 + 2",
      options: [
        { index: 0, letter: 'A', text: '3', normalizedText: '3' },
        { index: 1, letter: 'B', text: '4', normalizedText: '4' },
        { index: 2, letter: 'C', text: '5', normalizedText: '5' },
        { index: 3, letter: 'D', text: '6', normalizedText: '6' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "1",
      questionText: "What is 2 + 2?",
      answerValue: "4",
      answerIndex: 1,
      source: "API Payload",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.text, '4');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].displayAnswer, 'B. 4');
});

test('Correlator - exact question text and answerIndex produces HIGH confidence', () => {
  const domQuestions = [
    {
      questionId: "42",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', normalizedText: 'udp' },
        { index: 2, letter: 'C', text: 'FTP', normalizedText: 'ftp' },
        { index: 3, letter: 'D', text: 'SSH', normalizedText: 'ssh' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: null, // ID missing, but exact question text matches!
      questionText: "Which protocol is connectionless?",
      answerValue: "UDP",
      answerIndex: 1,
      source: "Inline Script",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
});

test('Correlator - letter answer mapping ("B" maps to 2nd option)', () => {
  const domQuestions = [
    {
      questionId: "q5",
      questionText: "Capital of Germany?",
      normalizedText: "capital of germany",
      options: [
        { index: 0, letter: 'A', text: 'Munich', normalizedText: 'munich' },
        { index: 1, letter: 'B', text: 'Berlin', normalizedText: 'berlin' },
        { index: 2, letter: 'C', text: 'Hamburg', normalizedText: 'hamburg' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "q5",
      questionText: null,
      answerValue: "B", // Letter "B"
      source: "Storage",
      structural: false
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].matchedOption.text, 'Berlin');
  assert.strictEqual(correlated[0].matchedOption.index, 1);
});

test('Correlator - false positive prevention for benign instruction texts', () => {
  const domQuestions = [
    {
      questionId: "inst_1",
      questionText: "Please select the correct answer below",
      normalizedText: "please select the correct answer below",
      options: [
        { index: 0, letter: 'A', text: 'Choice 1', normalizedText: 'choice 1' },
        { index: 1, letter: 'B', text: 'Choice 2', normalizedText: 'choice 2' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "inst_1",
      questionText: "Please select the correct answer below",
      answerValue: "Choice 1",
      answerIndex: 0,
      keywordOnly: true,
      structural: false
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  // Instruction texts are demoted so they don't produce HIGH or false alarm findings
  assert.strictEqual(correlated.length === 0 || correlated[0].confidence === ConfidenceLevel.LOW || correlated[0].confidence === ConfidenceLevel.NONE, true);
});

test('Correlator - SECURE CASE: when rawFindings is empty, returns empty array', () => {
  const domQuestions = [
    {
      questionId: "101",
      questionText: "What is 2 + 2?",
      options: [
        { index: 0, letter: 'A', text: '3' },
        { index: 1, letter: 'B', text: '4' }
      ]
    }
  ];

  const correlated = Correlator.correlate(domQuestions, []);
  assert.strictEqual(correlated.length, 0, 'No findings should be correlated when no answers exist');
});

test('Correlator - RANDOMIZED OPTION ORDER: correctly correlates answer text when DOM options are shuffled', () => {
  // Author defined options: ["TCP", "UDP", "FTP", "SSH"] with correctIndex: 1 ("UDP")
  // Webpage rendered them in shuffled/randomized order:
  // A. FTP (idx 0), B. SSH (idx 1), C. UDP (idx 2), D. TCP (idx 3)
  const domQuestions = [
    {
      questionId: "42",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'FTP', normalizedText: 'ftp' },
        { index: 1, letter: 'B', text: 'SSH', normalizedText: 'ssh' },
        { index: 2, letter: 'C', text: 'UDP', normalizedText: 'udp' },
        { index: 3, letter: 'D', text: 'TCP', normalizedText: 'tcp' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "42",
      questionText: "Which protocol is connectionless?",
      options: ["TCP", "UDP", "FTP", "SSH"], // Author original options list
      answerIndex: 1, // Author index 1 -> UDP
      answerValue: "UDP",
      source: "API Payload",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  // Crucial assertion: Correlator must resolve to C. UDP (index 2 in DOM), NOT index 1 (B. SSH)
  assert.strictEqual(correlated[0].matchedOption.index, 2);
  assert.strictEqual(correlated[0].matchedOption.letter, 'C');
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
  assert.strictEqual(correlated[0].displayAnswer, 'C. UDP');
});

test('Correlator - correctOptionId matching against DOM optionId / data-option-id', () => {
  const domQuestions = [
    {
      questionId: "q10",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', optionId: 'opt-tcp', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', optionId: 'opt-udp', normalizedText: 'udp' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "q10",
      questionText: "Which protocol is connectionless?",
      correctOptionId: "opt-udp",
      answerValue: "UDP",
      source: "API Payload",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.optionId, 'opt-udp');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
});

test('Correlator - correctResponseId matching against DOM option value', () => {
  const domQuestions = [
    {
      questionId: "q20",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', value: 'resp_1', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', value: 'resp_2', normalizedText: 'udp' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "q20",
      questionText: "Which protocol is connectionless?",
      correctResponseId: "resp_2",
      answerValue: "UDP",
      source: "State",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.value, 'resp_2');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
});

test('Correlator - author response scoring produces HIGH confidence when matched with question ID', () => {
  const domQuestions = [
    {
      questionId: "q30",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', normalizedText: 'udp' }
      ]
    }
  ];

  const rawFindings = [
    {
      questionId: "q30",
      questionText: "Which protocol is connectionless?",
      answerValue: "UDP",
      answerIndex: 1,
      isScoringRule: true,
      source: "Scored Choice State",
      structural: true
    }
  ];

  const correlated = Correlator.correlate(domQuestions, rawFindings);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
});
