import { defineConfig } from 'vite';
import { CSP_HEADER, X_CONTENT_TYPE_OPTIONS } from './src/security/csp-config';

export default defineConfig({
  worker: {
    format: 'es',
  },
  server: {
    port: 3000,
    headers: {
      'Content-Security-Policy': CSP_HEADER,
      'X-Content-Type-Options': X_CONTENT_TYPE_OPTIONS,
    },
  },
  preview: {
    port: 4173,
    headers: {
      'Content-Security-Policy': CSP_HEADER,
      'X-Content-Type-Options': X_CONTENT_TYPE_OPTIONS,
    },
  },
  build: {
    rollupOptions: {
      external: ['/pyodide/pyodide.mjs'],
    },
  },
  optimizeDeps: {
    exclude: ['pyodide'],
  },
});
