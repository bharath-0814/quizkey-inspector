/**
 * Assessment Security Scanner - Live Observers
 * 
 * Uses MutationObserver to passively detect dynamically rendered questions
 * (e.g. single-page apps, paginated assessments).
 * 
 * Features:
 * - Debounced execution (250ms) to ensure lightweight, non-blocking performance.
 * - Mutation filtering to avoid unnecessary work when non-assessment nodes change.
 */

export class DomObserver {
  /**
   * @param {function(): void} onTriggerCallback 
   * @param {number} [debounceMs=250] 
   */
  constructor(onTriggerCallback, debounceMs = 250) {
    this.callback = onTriggerCallback;
    this.debounceMs = debounceMs;
    this.timer = null;
    this.observer = null;
    this.isObserving = false;
  }

  /**
   * Starts observing the DOM
   * @param {Node} [target=document.body] 
   */
  start(target = typeof document !== 'undefined' ? document.body : null) {
    if (!target || typeof MutationObserver === 'undefined') return;
    if (this.isObserving) return;

    this.observer = new MutationObserver((mutations) => {
      // Filter mutations: only trigger if added nodes might contain inputs, questions, or scripts
      let isRelevant = false;
      for (const m of mutations) {
        if (m.type === 'childList' && m.addedNodes.length > 0) {
          for (let i = 0; i < m.addedNodes.length; i++) {
            const node = m.addedNodes[i];
            if (node.nodeType === Node.ELEMENT_NODE) {
              const el = /** @type {HTMLElement} */ (node);
              // Ignore our own injected audit panels
              if (el.classList && (el.classList.contains('ass-scanner-panel') || el.hasAttribute('data-ass-scanner-panel'))) {
                continue;
              }
              // Check if relevant assessment elements were added
              if (el.querySelector && (
                el.querySelector('input, fieldset, [data-question-id], .question, .option') ||
                el.tagName === 'INPUT' ||
                el.tagName === 'SCRIPT'
              )) {
                isRelevant = true;
                break;
              }
            }
          }
        }
        if (isRelevant) break;
      }

      if (isRelevant) {
        this.debouncedTrigger();
      }
    });

    this.observer.observe(target, {
      childList: true,
      subtree: true
    });

    this.isObserving = true;
  }

  /**
   * Debounced callback trigger
   */
  debouncedTrigger() {
    if (this.timer) {
      clearTimeout(this.timer);
    }
    this.timer = setTimeout(() => {
      if (typeof this.callback === 'function') {
        this.callback();
      }
    }, this.debounceMs);
  }

  /**
   * Stops observing
   */
  stop() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.isObserving = false;
  }
}
