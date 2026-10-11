import { defineConfig } from 'vite';

export default defineConfig({
  worker: {
    format: 'es',
  },
  server: {
    port: 3000,
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline';",
      'X-Content-Type-Options': 'nosniff',
    },
  },
  preview: {
    port: 4173,
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline';",
      'X-Content-Type-Options': 'nosniff',
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
