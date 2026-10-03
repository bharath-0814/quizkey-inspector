/**
 * QuizKey Inspector - Build Script
 * 
 * Bundles modular content script into standalone Manifest V3 bundle
 * and verifies required assets.
 */

import esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function build() {
  console.log('[Build] Starting QuizKey Inspector build...');

  const iconsDir = path.join(__dirname, 'icons');
  if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
  }

  // Bundle content script
  console.log('[Build] Bundling content script...');
  await esbuild.build({
    entryPoints: [path.join(__dirname, 'src/content/content.js')],
    bundle: true,
    outfile: path.join(__dirname, 'src/content/content.bundle.js'),
    format: 'iife',
    platform: 'browser',
    target: ['chrome110'],
    minify: false, // Keep readable for security audit review
    logLevel: 'info'
  });

  console.log('[Build] QuizKey Inspector build completed successfully.');
}

build().catch(err => {
  console.error('[Build Error]:', err);
  process.exit(1);
});
