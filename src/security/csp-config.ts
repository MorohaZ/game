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

/**
 * Asserts that Content Security Policy (CSP) is actively enforcing restriction against
 * arbitrary dynamic code generation (unsafe-eval).
 * Throws an Error if CSP is not active (new Function succeeds).
 */
export function assertCspActive(): void {
  try {
    const fn = new Function('return 1');
    fn();
    throw new Error('CRITICAL SECURITY FAILURE: CSP is not active in Worker scope (eval/Function permitted). Refusing to execute user code.');
  } catch (err: any) {
    if (err.message && err.message.includes('CRITICAL SECURITY FAILURE')) {
      throw err;
    }
    // Expected behavior under active CSP: EvalError or SecurityError blocked by CSP
  }
}

