/**
 * Automated Tests: Authorized Audit Mode Logic
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { getDomainFromUrl, isDomainAuthorized } from '../src/shared/utils.js';

test('Authorization - extract normalized domain from URLs', () => {
  assert.strictEqual(getDomainFromUrl('https://assessment.university.edu/exam/123'), 'assessment.university.edu');
  assert.strictEqual(getDomainFromUrl('http://localhost:3000/quiz'), 'localhost');
  assert.strictEqual(getDomainFromUrl('http://127.0.0.1:8080/'), '127.0.0.1');
  assert.strictEqual(getDomainFromUrl('file:///d:/OptionsFinder/test-pages/secure.html'), 'local-files (file://)');
  assert.strictEqual(getDomainFromUrl('invalid-url'), 'unknown');
  assert.strictEqual(getDomainFromUrl(null), 'unknown');
});

test('Authorization - verify domain authorization check', () => {
  const authorized = ['example.edu', 'localhost', '127.0.0.1', 'local-files (file://)'];

  assert.strictEqual(isDomainAuthorized('example.edu', authorized), true);
  assert.strictEqual(isDomainAuthorized('EXAMPLE.EDU', authorized), true); // case-insensitive
  assert.strictEqual(isDomainAuthorized('localhost', authorized), true);
  assert.strictEqual(isDomainAuthorized('local-files (file://)', authorized), true);

  // Unauthorized domains
  assert.strictEqual(isDomainAuthorized('unauthorized-site.com', authorized), false);
  assert.strictEqual(isDomainAuthorized('subdomain.example.edu', authorized), false);
  assert.strictEqual(isDomainAuthorized('', authorized), false);
  assert.strictEqual(isDomainAuthorized('random', null), false);
});
