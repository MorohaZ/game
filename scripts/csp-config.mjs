/**
 * NetSec: Zero-Day Protocol - Centralized Content Security Policy (CSP) Configuration
 * Single Source of Truth for Development (Vite Dev), Preview (Vite Preview),
 * Headless Browser Testing, and Production Hosting (Netlify, Cloudflare Pages, S3).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'wasm-unsafe-eval'"],
  'worker-src': ["'self'", "blob:"],
  'connect-src': ["'self'"],
  'style-src': ["'self'", "'unsafe-inline'"],
};

export const WORKER_CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'wasm-unsafe-eval'"],
  'connect-src': ["'self'"],
};

export const CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline';";

export const WORKER_CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self';";

export const X_CONTENT_TYPE_OPTIONS = "nosniff";

export const MINIMUM_BROWSER_SUPPORT = {
  chromium: {
    engine: 'Chromium (Chrome / Edge / Brave / Opera)',
    minVersion: '95+',
    releaseDate: 'October 2021',
    status: 'Verified (Passed in CI & Local)',
    notes: "Separates 'wasm-unsafe-eval' from 'unsafe-eval', enabling WebAssembly execution without JavaScript eval()",
  },
  firefox: {
    engine: 'Gecko (Firefox / Floorp / LibreWolf)',
    minVersion: '102+',
    releaseDate: 'June 2022',
    status: 'Verified (Passed in CI & Local)',
    notes: "Standard and ESR support for 'wasm-unsafe-eval'",
  },
  webkit: {
    engine: 'WebKit (Safari / iOS Browsers / Playwright WebKit)',
    minVersion: '16.0+',
    releaseDate: 'September 2022',
    status: 'Supported in CI via Playwright WebKit',
    notes: 'WebKit 614+ / iOS 16 / macOS 13',
  },
};

/**
 * Synchronize static hosting configuration files with the centralized CSP definition.
 * Targets: _headers, public/_headers, and netlify.toml
 */
export function syncHostingConfigs(projectRoot) {
  const root = projectRoot || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

  const headersContent = `/*
  Content-Security-Policy: ${CSP_HEADER}
  X-Content-Type-Options: ${X_CONTENT_TYPE_OPTIONS}
`;

  const netlifyContent = `[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "${CSP_HEADER}"
    X-Content-Type-Options = "${X_CONTENT_TYPE_OPTIONS}"
`;

  const vercelContent = JSON.stringify({
    headers: [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: CSP_HEADER,
          },
          {
            key: "X-Content-Type-Options",
            value: X_CONTENT_TYPE_OPTIONS,
          },
        ],
      },
    ],
  }, null, 2) + '\n';

  const targets = [
    { file: path.join(root, '_headers'), content: headersContent },
    { file: path.join(root, 'public/_headers'), content: headersContent },
    { file: path.join(root, 'netlify.toml'), content: netlifyContent },
    { file: path.join(root, 'vercel.json'), content: vercelContent },
  ];

  for (const t of targets) {
    fs.mkdirSync(path.dirname(t.file), { recursive: true });
    fs.writeFileSync(t.file, t.content, 'utf-8');
  }

  return true;
}

// Auto-sync when run directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  syncHostingConfigs();
  console.log('[csp-config] Hosting configs synchronized with centralized CSP configuration.');
}
