/**
 * Automated Tests: End-to-End Inspection Workflows
 * 
 * Verifies that QuizKey Inspector accurately identifies client-side
 * answer key exposure across real-world assessment structures and
 * correctly reports NO CLIENT-SIDE ANSWER KEY DETECTED for secure architectures.
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { Detector } from '../src/content/detector.js';
import { ConfidenceLevel } from '../src/shared/types.js';
import { ScriptAnalyzer } from '../src/analysis/script-analyzer.js';
import { JsonAnalyzer } from '../src/analysis/json-analyzer.js';
import { EncodingAnalyzer } from '../src/analysis/encoding-analyzer.js';
import { NetworkAnalyzer } from '../src/analysis/network-analyzer.js';
import { Correlator } from '../src/analysis/correlator.js';

function createMockDoc(scripts = []) {
  return {
    querySelectorAll: (selector) => {
      if (selector === 'script') {
        return scripts.map(s => ({
          textContent: typeof s === 'string' ? s : s.content,
          getAttribute: (attr) => (attr === 'type' ? (s.type || 'text/javascript') : null),
          id: s.id || ''
        }));
      }
      return [];
    }
  };
}

test('Integration 1 - Test Page: exposed-js.html (Inline JavaScript Answer Key)', () => {
  const scriptContent = `
    const questions = [
      {
        id: 1,
        question: "What is 2 + 2?",
        options: ["3", "4", "5", "6"],
        correctAnswer: "4",
        correctIndex: 1
      }
    ];
  `;

  const mockDomQuestions = [
    {
      questionId: "1",
      questionText: "What is 2 + 2?",
      normalizedText: "what is 2 + 2",
      options: [
        { index: 0, letter: 'A', text: '3', normalizedText: '3' },
        { index: 1, letter: 'B', text: '4', normalizedText: '4' },
        { index: 2, letter: 'C', text: '5', normalizedText: '5' },
        { index: 3, letter: 'D', text: '6', normalizedText: '6' }
      ],
      domFindings: []
    }
  ];

  const doc = createMockDoc([scriptContent]);
  const scriptFindings = ScriptAnalyzer.analyzeScripts(doc.querySelectorAll('script'));
  const correlated = Correlator.correlate(mockDomQuestions, scriptFindings);

  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
  assert.strictEqual(correlated[0].matchedOption.text, '4');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].displayAnswer, 'B. 4');
});

test('Integration 2 - Test Page: exposed-json.html (Embedded JSON State)', () => {
  const jsonContent = JSON.stringify({
    items: [
      {
        id: 10,
        question: "Which data structure operates on a FIFO basis?",
        options: ["Stack", "Queue", "Tree"],
        correctOption: "Queue",
        correctIndex: 1
      }
    ]
  });

  const mockDomQuestions = [
    {
      questionId: "10",
      questionText: "Which data structure operates on a FIFO basis?",
      normalizedText: "which data structure operates on a fifo basis",
      options: [
        { index: 0, letter: 'A', text: 'Stack', normalizedText: 'stack' },
        { index: 1, letter: 'B', text: 'Queue', normalizedText: 'queue' },
        { index: 2, letter: 'C', text: 'Tree', normalizedText: 'tree' }
      ],
      domFindings: []
    }
  ];

  const doc = createMockDoc([{ content: jsonContent, type: 'application/json', id: '__PAGE_STATE__' }]);
  const scriptFindings = ScriptAnalyzer.analyzeScripts(doc.querySelectorAll('script'));
  const correlated = Correlator.correlate(mockDomQuestions, scriptFindings);

  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].matchedOption.text, 'Queue');
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
});

test('Integration 3 - Test Page: exposed-api.html (Network API Response)', () => {
  const detector = new Detector();

  const networkFindings = NetworkAnalyzer.analyzeResponse({
    url: '/api/v1/assessment/questions',
    method: 'GET',
    data: {
      questions: [
        {
          id: 42,
          question: "Which protocol is connectionless?",
          options: ["TCP", "UDP", "FTP", "SSH"],
          correctIndex: 1
        }
      ]
    }
  });

  detector.addNetworkFindings(networkFindings);

  const mockDomQuestions = [
    {
      questionId: "42",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', normalizedText: 'udp' },
        { index: 2, letter: 'C', text: 'FTP', normalizedText: 'ftp' },
        { index: 3, letter: 'D', text: 'SSH', normalizedText: 'ssh' }
      ],
      domFindings: []
    }
  ];

  const correlated = Correlator.correlate(mockDomQuestions, detector.networkFindings);

  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
});

test('Integration 4 - Test Page: exposed-encoded.html (Base64 Encoded Attribute)', () => {
  // eyJjb3JyZWN0SW5kZXgiOjEsImFuc3dlciI6IlVEUCJ9 -> {"correctIndex":1,"answer":"UDP"}
  const encodedStr = 'eyJjb3JyZWN0SW5kZXgiOjEsImFuc3dlciI6IlVEUCJ9';
  const decoded = EncodingAnalyzer.decodeBase64(encodedStr);
  assert.strictEqual(decoded.success, true);
  assert.strictEqual(decoded.isJson, true);

  const mockDomFinding = {
    category: 'Hidden DOM metadata',
    questionId: "50",
    questionText: "Which protocol is connectionless?",
    answerValue: decoded.parsedJson.answer,
    answerIndex: decoded.parsedJson.correctIndex,
    source: 'Question attribute [data-correct-answer]',
    evidence: `Decoded Base64 JSON: ${JSON.stringify(decoded.parsedJson)}`,
    domDirectAttribute: true
  };

  const mockDomQuestions = [
    {
      questionId: "50",
      questionText: "Which protocol is connectionless?",
      normalizedText: "which protocol is connectionless",
      options: [
        { index: 0, letter: 'A', text: 'TCP', normalizedText: 'tcp' },
        { index: 1, letter: 'B', text: 'UDP', normalizedText: 'udp' },
        { index: 2, letter: 'C', text: 'FTP', normalizedText: 'ftp' },
        { index: 3, letter: 'D', text: 'SSH', normalizedText: 'ssh' }
      ],
      domFindings: [mockDomFinding]
    }
  ];

  const correlated = Correlator.correlate(mockDomQuestions, []);
  assert.strictEqual(correlated.length, 1);
  assert.strictEqual(correlated[0].matchedOption.text, 'UDP');
  assert.strictEqual(correlated[0].matchedOption.letter, 'B');
  assert.strictEqual(correlated[0].confidence, ConfidenceLevel.HIGH);
});

test('Integration 5 - Test Page: secure.html (Server-Side Grading, NO CLIENT-SIDE EXPOSURE)', () => {
  const secureScript = `
    const secureQuestions = [
      { id: 101, question: "What is 2 + 2?", options: ["3", "4", "5", "6"] },
      { id: 102, question: "Which protocol is connectionless?", options: ["TCP", "UDP", "FTP", "SSH"] }
    ];
  `;

  const doc = createMockDoc([secureScript]);
  const scriptFindings = ScriptAnalyzer.analyzeScripts(doc.querySelectorAll('script'));
  assert.strictEqual(scriptFindings.length, 0, 'No raw findings should exist on secure page');

  const mockDomQuestions = [
    {
      questionId: "101",
      questionText: "What is 2 + 2?",
      normalizedText: "what is 2 + 2",
      options: [
        { index: 0, letter: 'A', text: '3', normalizedText: '3' },
        { index: 1, letter: 'B', text: '4', normalizedText: '4' }
      ],
      domFindings: []
    }
  ];

  const correlated = Correlator.correlate(mockDomQuestions, scriptFindings);
  assert.strictEqual(correlated.length, 0, 'No correlated findings should be detected');

  let statusText = 'NO QUESTIONS DETECTED';
  if (mockDomQuestions.length > 0) {
    statusText = correlated.length > 0
      ? 'CLIENT-SIDE ANSWER KEY DETECTED'
      : 'NO CLIENT-SIDE ANSWER KEY DETECTED';
  }

  assert.strictEqual(statusText, 'NO CLIENT-SIDE ANSWER KEY DETECTED');
});
