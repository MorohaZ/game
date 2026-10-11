/**
 * NetSec: Zero-Day Protocol - Content Security Policy (CSP) TypeScript Definitions
 * Centralized Single Source of Truth for CSP Directives & Header Strings
 */

export interface CspDirectives {
  'default-src': string[];
  'script-src': string[];
  'worker-src'?: string[];
  'connect-src': string[];
  'style-src'?: string[];
}

export interface BrowserSupportEntry {
  engine: string;
  minVersion: string;
  releaseDate: string;
  status: string;
  notes: string;
}

export const CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline';";

export const WORKER_CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self';";

export const X_CONTENT_TYPE_OPTIONS = "nosniff";

export const MINIMUM_BROWSER_SUPPORT: Record<'chromium' | 'firefox' | 'webkit', BrowserSupportEntry> = {
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
