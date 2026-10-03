# QuizKey Inspector 🔎

**Client-Side Code Inspection Tool for Authorized Assessment Auditing**  
*Chromium Manifest V3 Browser Extension (Version 1.0.0 Prototype)*

---

## 🎯 Purpose & Scope

**QuizKey Inspector** is a browser extension and client-side code auditing tool designed for educators, developers, and security auditors to test **existing** online MCQ and assessment web pages that they own or are explicitly authorized to audit.

### Core Concept: The Extension is NOT a Quiz
* **The extension does NOT create, host, submit, or grade quizzes.**
* **The existing website supplies the questions.**
* **The extension attaches to an existing webpage and inspects data that the page has already delivered to the browser.**

If the target webpage accidentally exposes its grading key or correct answer choices in client-side HTML, JavaScript, application state, browser storage, or network API responses, QuizKey Inspector identifies that exposure, correlates it with the displayed question, and presents an educational security audit finding.

If the assessment uses a secure architecture where grading data remains exclusively on the server, QuizKey Inspector reports:
> **🟢 NO CLIENT-SIDE ANSWER KEY DETECTED**  
> *(Confirming that no answer key was discovered in browser-visible client data; this does not evaluate backend server security).*

---

## 🛡️ Authorized Audit Mode

To ensure safe, ethical operation, QuizKey Inspector implements **Authorized Audit Mode**:
1. **Auditing is disabled by default:** On any new website, the extension remains passive.
2. **Per-domain authorization:** The auditor must explicitly click **"Authorize Audit For This Site"** in the popup to enable inspection on that domain.
3. **No automatic attacks:** The tool never bypasses authentication, never probes unauthorized endpoints, never steals credentials, and never automates assessment submission or cheating.
4. **100% Local execution:** All inspection occurs locally within the browser session. Zero telemetry, zero analytics, zero external network requests.

---

## 🏗️ Architecture

```
quizkey-inspector/
├── manifest.json                  # Manifest V3 (least-privilege permissions)
├── package.json                   # Build and test scripts
├── build.js                       # Bundles content script using esbuild
├── README.md                      # Documentation
├── icons/                         # Extension icons (16px, 48px, 128px)
├── src/
│   ├── background/
│   │   └── service-worker.js      # Service worker managing toolbar badge & domain state
│   ├── content/
│   │   ├── content.js             # Content script coordinator & Authorization controller
│   │   ├── content.bundle.js      # Bundled production script
│   │   ├── renderer.js            # Non-destructive overlay injector & option highlighter
│   │   ├── observers.js           # Debounced MutationObserver for dynamic question rendering
│   │   └── styles.css             # Scoped overlay and option highlight CSS
│   ├── network/
│   │   └── network-monitor.js     # MAIN-world passive fetch/XHR observer (zero extra requests)
│   ├── analysis/
│   │   ├── dom-analyzer.js        # Inspects hidden inputs, data-* attributes, ARIA flags
│   │   ├── script-analyzer.js     # Safe JavaScript parser without eval() or new Function()
│   │   ├── json-analyzer.js       # Recursive JSON structure & property scanner
│   │   ├── network-analyzer.js    # Evaluates payloads intercepted by network-monitor
│   │   ├── storage-analyzer.js    # Inspects localStorage and sessionStorage
│   │   ├── encoding-analyzer.js   # Safe Base64, URL-encoding & escaped JSON decoder
│   │   ├── correlator.js          # Multi-signal correlation engine
│   │   └── confidence.js          # Scoring engine & false-positive filters
│   ├── popup/
│   │   ├── popup.html             # Audit dashboard UI
│   │   ├── popup.js               # Authorization toggle, scan triggers & findings viewer
│   │   └── popup.css              # Dark/light compatible responsive styling
│   └── shared/
│       ├── types.js               # Normalized finding models & thresholds
│       └── utils.js               # Domain extraction, text normalization & safe DOM helpers
├── test-pages/                    # Minimal static test fixtures (NOT a quiz platform)
│   ├── index.html                 # Test fixture hub and directory
│   ├── exposed-randomized.html    # Fixture 1: Randomized option order resolution
│   ├── exposed-response-ids.html  # Fixture 2: Author correctOptionId / correctResponseId
│   ├── exposed-scoring.html       # Fixture 3: Author response scoring metadata
│   ├── exposed-choices-flags.html # Fixture 4: Choices with embedded isCorrect: true flags
│   ├── exposed-answer-key-map.html# Fixture 5: External answerKey dictionary mapping
│   ├── exposed-js.html            # Fixture 6: Inline JavaScript array answer key
│   ├── exposed-json.html          # Fixture 7: Embedded JSON state tag
│   ├── exposed-storage.html       # Fixture 8: localStorage quiz answer leak
│   ├── exposed-api.html           # Fixture 9: API response containing correctIndex
│   ├── exposed-encoded.html       # Fixture 10: Base64 encoded answer in data attribute
│   └── secure.html                # Fixture 11: Server-side grading (no client-side answer key)
└── tests/                         # Automated test suite (48 tests)
    ├── authorization.test.js
    ├── encoding-analyzer.test.js
    ├── json-analyzer.test.js
    ├── script-analyzer.test.js
    ├── storage-analyzer.test.js
    ├── correlator.test.js
    └── integration.test.js
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Build Extension
```bash
npm run build
```
*Compiles the modular content script into `src/content/content.bundle.js`.*

### 3. Run Automated Tests
```bash
npm test
```
*Executes all 48 unit and end-to-end integration tests using Node.js's native test runner.*

---

## Load the Extension Locally

Follow these steps to load QuizKey Inspector into Chromium, Google Chrome, Brave, or Microsoft Edge:

1. **Build the project:** Run `npm run build` in the repository root (`quizkey-inspector`) to generate `src/content/content.bundle.js`.
2. **Open chrome://extensions:** Navigate to `chrome://extensions` in your Chromium-based browser.
3. **Enable Developer mode:** Toggle the **Developer mode** switch in the top-right corner.
4. **Click Load unpacked:** Click the **Load unpacked** button in the top-left toolbar.
5. **Select the correct extension directory:** Select the `quizkey-inspector` directory:
   `D:\OptionsFinder\quizkey-inspector`
6. The extension **QuizKey Inspector** will now appear in your browser toolbar with a magnifying glass icon 🔎.

---

## 🔍 How to Use QuizKey Inspector

1. Open an existing MCQ or assessment page in your browser (or open one of the static fixtures in `test-pages/`).
2. Click the **QuizKey Inspector** icon in the extensions toolbar.
3. Notice the **Current site** and **Audit** status:
   * If the site is **NOT AUTHORIZED**, click **"🛡️ Authorize Audit For This Site"**.
4. The extension immediately scans the page:
   * **If a client-side answer key is exposed:** A non-destructive security overlay is injected directly beneath each vulnerable question:
     ```
     ┌─────────────────────────────────┐
     │ 🔎 QUIZKEY INSPECTOR            │
     │                                 │
     │ AUTHOR ANSWER KEY EXPOSED       │
     │                                 │
     │ Correct option: B. UDP          │
     │ Confidence: HIGH                │
     │                                 │
     │ Evidence: API response          │
     └─────────────────────────────────┘
     ```
     The exposed option is visually outlined with a subtle red border.
   * **If no answer key is delivered to the browser:** The popup reports:
     `🟢 NO CLIENT-SIDE ANSWER KEY DETECTED`.
5. Click **"View Evidence"** in the popup to review exact property names, DOM attributes, or API response snippets.
6. When your security review is complete, click **"⚠️ Disable Audit For This Site"** to revoke authorization.

---

## 🧪 Testing with Included Static Fixtures

The repository includes static test fixtures in `test-pages/` (accessible via `test-pages/index.html`) specifically designed to verify analyzer behavior without hosting any quiz platform:

| Test Fixture | Exposure Method Tested | Expected Inspector Result |
|---|---|---|
| `test-pages/exposed-randomized.html` | Shuffled DOM order (`author index 1 = UDP`, DOM order is C. UDP) | **C. UDP** accurately correlated (HIGH confidence) |
| `test-pages/exposed-response-ids.html` | Author grading via `correctOptionId: "opt_udp"` | **B. UDP** correlated via option ID (HIGH confidence) |
| `test-pages/exposed-scoring.html` | Choices scoring metadata (`score: 1` vs `score: 0`) | **B. UDP** correlated via score (HIGH confidence) |
| `test-pages/exposed-choices-flags.html` | Embedded choice boolean (`isCorrect: true`) | **B. UDP** correlated via flag (HIGH confidence) |
| `test-pages/exposed-answer-key-map.html` | External dictionary mapping (`answerKey: { "1": "B" }`) | **B. UDP** correlated via map (HIGH confidence) |
| `test-pages/exposed-js.html` | Inline JavaScript variable (`questions = [{ correctAnswer: "4" }]`) | **B. 4** detected (HIGH confidence) |
| `test-pages/exposed-json.html` | `<script type="application/json">` hydration state | **B. Queue** detected (HIGH confidence) |
| `test-pages/exposed-storage.html` | `localStorage` item with answer payload | **C. AES-256** detected (HIGH confidence) |
| `test-pages/exposed-api.html` | Network API response with `correctIndex: 1` | **B. UDP** detected (HIGH confidence) |
| `test-pages/exposed-encoded.html` | Base64 encoded JSON in `data-correct-answer` | **B. UDP** detected (HIGH confidence) |
| `test-pages/secure.html` | Server-side grading (client receives questions only) | **🟢 NO CLIENT-SIDE ANSWER KEY DETECTED** |

You can open these directly in Chrome via `file:///` or via any local static web server.

---

## 🔒 Security Architecture Principles

### Why Client-Side Answers Leak:
1. **CSS Hiding (`display: none`) is Not Security:** Elements remain part of the DOM tree and are trivially readable.
2. **Minification is Not Security:** Variable renaming does not alter object structure or array ordering.
3. **Base64 is Not Encryption:** Base64 is an encoding format easily decoded by any client script.
4. **Hydration Overexposure:** Modern frameworks frequently bundle complete server models into `__NEXT_DATA__` or hydration tags, inadvertently leaking fields.

### Recommended Defensive Architecture:
```
CLIENT BROWSER                                            SERVER
      │                                                     │
      │   1. Requests Question                              │
      ├────────────────────────────────────────────────────>│
      │   2. Returns Question & Options ONLY                │
      │<────────────────────────────────────────────────────┤ (Retains private answer key)
      │                                                     │
      │   3. Submits Selected Option Index                  │
      ├────────────────────────────────────────────────────>│
      │                                                     │ 4. Server compares submission
      │   5. Returns Result ONLY (isCorrect / score)        │    against private answer key
      │<────────────────────────────────────────────────────┤
```

---

## ⚠️ Known Limitations

1. **Browser-Visible Scope:** QuizKey Inspector inspects information delivered to the browser session. If an assessment keeps grading keys server-side, the tool reports `NO CLIENT-SIDE ANSWER KEY DETECTED`, but cannot evaluate server-side vulnerabilities (e.g. SQLi or broken access controls).
2. **Canvas / WebGL Renders:** Questions rendered strictly into HTML5 `<canvas>` pixels without corresponding DOM accessibility nodes or parseable JSON streams cannot be mapped to DOM elements.
3. **Decryption Boundaries:** If a page performs client-side asymmetric decryption using ephemeral session keys via Web Crypto API, inspection prior to decryption is limited.

---

## 📜 License
Apache-2.0. Built for defensive assessment security auditing on authorized applications.
