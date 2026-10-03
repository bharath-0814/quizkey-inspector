/**
 * QuizKey Inspector - Shared Types & Constants
 * 
 * Defines standard data models, confidence thresholds, and categories
 * for client-side assessment security auditing.
 */

export const ConfidenceLevel = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE'
};

export const ExposureCategory = {
  ANSWER_KEY: 'Assessment answer key',
  HIDDEN_DOM_DATA: 'Hidden DOM metadata',
  EMBEDDED_JSON: 'Embedded application state',
  BROWSER_STORAGE: 'Client browser storage',
  API_RESPONSE: 'Client-side API response',
  ENCODED_DATA: 'Encoded client-side data'
};

export const ScoreThresholds = {
  HIGH: 80,
  MEDIUM: 60,
  LOW: 40
};

export const AuditStatus = {
  AUTHORIZED: 'AUTHORIZED',
  NOT_AUTHORIZED: 'NOT AUTHORIZED'
};
