import { getAvailableBrowsers } from '../src/test/headless-browser-runner.mjs';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const distPyodideDir = path.resolve(projectRoot, 'dist/pyodide');
const pyodideDir = path.resolve(projectRoot, 'node_modules/pyodide');
const distAssetsDir = path.resolve(projectRoot, 'dist/assets');

function runPythonUnderCSP(cspHeader, workerCspHeader) {
  return new Promise((resolve, reject) => {
    let workerCode = '';
    if (fs.existsSync(distAssetsDir)) {
      const workerFile = fs.readdirSync(distAssetsDir).find(f => f.startsWith('sim-worker-') && f.endsWith('.js'));
      if (workerFile) {
        workerCode = fs.readFileSync(path.join(distAssetsDir, workerFile), 'utf-8');
      }
    }

    let reportResolver = null;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === '/' || url.pathname === '/index.html') {
        const headers = { 'Content-Type': 'text/html; charset=utf-8' };
        if (cspHeader) headers['Content-Security-Policy'] = cspHeader;
        res.writeHead(200, headers);
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script type="module" src="/harness.js"></script></body></html>`);
        return;
      }

      if (url.pathname === '/harness.js') {
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
        res.end(`
          async function run() {
            try {
              const worker = new Worker('/worker.js', { type: 'module' });

              function waitMsg(type) {
                return new Promise((resolve) => {
                  function handler(e) {
                    if (e.data.type === type) {
                      worker.removeEventListener('message', handler);
                      resolve(e.data);
                    }
                  }
                  worker.addEventListener('message', handler);
                });
              }

              worker.postMessage({ type: 'INIT' });
              const readyMsg = await waitMsg('READY');

              // Test 1: Function eval rejection under CSP (no unsafe-eval)
              let functionEvalBlocked = false;
              let functionEvalError = '';
              try {
                const fn = new Function('return 42');
                fn();
                functionEvalBlocked = false;
              } catch (evalErr) {
                functionEvalBlocked = true;
                functionEvalError = evalErr.message || String(evalErr);
              }

              // Test 2: Python code execution with synchronous networking
              const pyCode = "import socket\\ns = socket.socket()\\ns.connect(('192.168.1.10', 80))\\ns.close()\\nprint('SOCKET_OK')";
              worker.postMessage({ type: 'RUN_CODE', payload: { code: pyCode, runId: 'r1' } });
              const runMsg = await waitMsg('CODE_RESULT');

              fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  success: runMsg.payload.success && functionEvalBlocked,
                  pyodideLoaded: Boolean(readyMsg && readyMsg.payload),
                  pyVersion: readyMsg.payload.version,
                  pyodideExecuted: runMsg.payload.success,
                  functionEvalBlocked,
                  functionEvalError,
                  stdout: runMsg.payload.stdout,
                  stderr: runMsg.payload.stderr,
                  error: runMsg.payload.error
                })
              });
            } catch (err) {
              fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ success: false, error: err.message })
              });
            }
          }
          run();
        `);
        return;
      }

      if (url.pathname === '/worker.js') {
        const headers = { 'Content-Type': 'application/javascript; charset=utf-8' };
        if (workerCspHeader) headers['Content-Security-Policy'] = workerCspHeader;
        res.writeHead(200, headers);
        res.end(workerCode);
        return;
      }

      if (url.pathname.startsWith('/assets/')) {
        const filePath = path.join(distAssetsDir, url.pathname.replace('/assets/', ''));
        if (fs.existsSync(filePath)) {
          res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
          fs.createReadStream(filePath).pipe(res);
          return;
        }
      }

      if (url.pathname.startsWith('/pyodide/')) {
        const relPath = url.pathname.replace('/pyodide/', '');
        let filePath = path.join(distPyodideDir, relPath);
        if (!fs.existsSync(filePath)) {
          filePath = path.join(pyodideDir, relPath);
        }
        if (fs.existsSync(filePath)) {
          const ext = path.extname(filePath);
          let mime = 'application/octet-stream';
          if (ext === '.js' || ext === '.mjs') mime = 'application/javascript';
          else if (ext === '.wasm') mime = 'application/wasm';
          else if (ext === '.json') mime = 'application/json';
          else if (ext === '.zip') mime = 'application/zip';

          res.writeHead(200, { 'Content-Type': mime });
          fs.createReadStream(filePath).pipe(res);
          return;
        }
      }

      if (url.pathname === '/api/report' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
            if (reportResolver) reportResolver(parsed);
          } catch (e) {
            res.writeHead(400);
            res.end('bad');
          }
        });
        return;
      }

      res.writeHead(404);
      res.end('not found');
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const testUrl = `http://127.0.0.1:${port}/index.html`;

      const browsers = getAvailableBrowsers();
      const chrome = browsers.find(b => b.id === 'chromium');

      const tmpDir = path.resolve(projectRoot, `.browser-tmp-csp-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });

      const browserProcess = spawn(chrome.path, [
        '--headless',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        `--user-data-dir=${tmpDir}`,
        testUrl,
      ]);

      const timer = setTimeout(() => {
        try { browserProcess.kill('SIGKILL'); } catch {}
        server.close();
        resolve({ success: false, error: 'Timeout after 15s' });
      }, 15000);

      reportResolver = (report) => {
        clearTimeout(timer);
        try { browserProcess.kill('SIGKILL'); } catch {}
        server.close(() => {
          try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
          resolve(report);
        });
      };
    });
  });
}

import { CSP_HEADER, WORKER_CSP_HEADER } from './csp-config.mjs';

async function main() {
  console.log('Testing full Python socket execution under CSP WITHOUT unsafe-eval...');
  const res = await runPythonUnderCSP(
    CSP_HEADER,
    WORKER_CSP_HEADER
  );
  console.log('Execution Result:', JSON.stringify(res, null, 2));
}

main().catch(console.error);
