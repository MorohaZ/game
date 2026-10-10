import http from 'http';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../');
const pyodideDir = path.resolve(projectRoot, 'node_modules/pyodide');
const shimPath = path.resolve(projectRoot, 'src/bridge/socket_shim.py');

export function getAvailableBrowsers() {
  const user = process.env.USERNAME || 'ken11';
  const candidates = [
    {
      id: 'chromium',
      name: 'Google Chrome (Chromium)',
      type: 'chromium',
      paths: [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        `C:\\Users\\${user}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe`,
      ],
    },
    {
      id: 'firefox',
      name: 'Mozilla Firefox (Gecko)',
      type: 'firefox',
      paths: [
        'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
        'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe',
        `C:\\Users\\${user}\\AppData\\Local\\Mozilla Firefox\\firefox.exe`,
      ],
    },
    {
      id: 'edge',
      name: 'Microsoft Edge (Chromium)',
      type: 'chromium',
      paths: [
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
      ],
    },
  ];

  const available = [];
  for (const c of candidates) {
    for (const p of c.paths) {
      if (fs.existsSync(p)) {
        available.push({ id: c.id, name: c.name, type: c.type, path: p });
        break;
      }
    }
  }
  return available;
}

export function createTestServer() {
  const shimCode = fs.readFileSync(shimPath, 'utf-8');
  const workerCode = fs.readFileSync(path.resolve(__dirname, 'browser-test-worker.js'), 'utf-8');

  return new Promise((resolve, reject) => {
    let reportResolver = null;
    let reportRejecter = null;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === '/' || url.pathname === '/index.html') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          // Note: NO COOP / COEP headers needed! Proves compatibility with standard static hosting.
        });
        res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Browser Web Worker E2E Test Harness</title>
</head>
<body style="font-family: monospace; background: #0f172a; color: #f8fafc; padding: 20px;">
  <h2>[Headless Browser E2E Test Harness]</h2>
  <div id="status" style="color: #38bdf8; margin-bottom: 10px;">Initializing Web Worker...</div>
  <pre id="log" style="background: #1e293b; padding: 15px; border-radius: 8px; max-height: 500px; overflow: auto;"></pre>

  <script type="module">
    const statusEl = document.getElementById('status');
    const logEl = document.getElementById('log');

    function log(msg) {
      logEl.textContent += msg + '\\n';
    }

    async function run() {
      try {
        log('Creating Web Worker (/worker.js)...');
        const worker = new Worker('/worker.js', { type: 'module' });

        worker.onmessage = async (e) => {
          const msg = e.data;
          if (msg.type === 'LOG') {
            log(msg.text);
          } else if (msg.type === 'COMPLETE') {
            statusEl.textContent = msg.report.success ? 'ALL TESTS PASSED' : 'TESTS FAILED';
            statusEl.style.color = msg.report.success ? '#4ade80' : '#f87171';
            await fetch('/api/report', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(msg.report),
            });
          }
        };

        worker.onerror = async (err) => {
          log('WORKER ERROR: ' + (err.message || String(err)));
          await fetch('/api/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              success: false,
              error: err.message || String(err),
              results: []
            }),
          });
        };

        worker.postMessage({ type: 'RUN' });
      } catch (err) {
        log('FATAL PAGE ERROR: ' + err.message);
        await fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            success: false,
            error: err.message,
            results: []
          }),
        });
      }
    }

    run();
  </script>
</body>
</html>`);
        return;
      }

      if (url.pathname === '/worker.js') {
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
        res.end(workerCode);
        return;
      }

      if (url.pathname === '/shim.py') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(shimCode);
        return;
      }

      if (url.pathname.startsWith('/pyodide/')) {
        const relPath = url.pathname.replace('/pyodide/', '');
        const filePath = path.join(pyodideDir, relPath);
        if (fs.existsSync(filePath)) {
          const ext = path.extname(filePath);
          let mime = 'application/octet-stream';
          if (ext === '.js' || ext === '.mjs') mime = 'application/javascript';
          else if (ext === '.wasm') mime = 'application/wasm';
          else if (ext === '.json') mime = 'application/json';
          else if (ext === '.zip') mime = 'application/zip';

          res.writeHead(200, {
            'Content-Type': mime,
            'Cache-Control': 'public, max-age=3600',
          });
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
            res.end('Bad Request');
            if (reportRejecter) reportRejecter(e);
          }
        });
        return;
      }

      res.writeHead(404);
      res.end('Not Found');
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        server,
        waitForReport: (timeoutMs = 35000) => {
          return new Promise((res, rej) => {
            const timer = setTimeout(() => {
              rej(new Error(`Timeout waiting for browser test report after ${timeoutMs}ms`));
            }, timeoutMs);

            reportResolver = (report) => {
              clearTimeout(timer);
              res(report);
            };
            reportRejecter = (err) => {
              clearTimeout(timer);
              rej(err);
            };
          });
        },
        close: () => new Promise(cb => server.close(cb)),
      });
    });
  });
}

export async function runBrowserTest(browserConfig) {
  const harness = await createTestServer();
  const testUrl = `http://127.0.0.1:${harness.port}/`;

  let browserProcess = null;
  const startTime = Date.now();

  try {
    const args = [];
    if (browserConfig.type === 'chromium') {
      args.push(
        '--headless=new',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-extensions',
        `--user-data-dir=${path.resolve(projectRoot, '.browser-tmp-' + browserConfig.id)}`,
        testUrl
      );
    } else if (browserConfig.type === 'firefox') {
      const profileDir = path.resolve(projectRoot, '.firefox-tmp-' + browserConfig.id);
      if (!fs.existsSync(profileDir)) {
        fs.mkdirSync(profileDir, { recursive: true });
      }
      args.push(
        '-headless',
        '-no-remote',
        '-profile',
        profileDir,
        testUrl
      );
    }

    browserProcess = spawn(browserConfig.path, args, {
      stdio: 'ignore',
      windowsHide: true,
    });

    const report = await harness.waitForReport(45000);
    const durationMs = Date.now() - startTime;

    return {
      browser: browserConfig.name,
      browserId: browserConfig.id,
      browserPath: browserConfig.path,
      success: report.success,
      total: report.total,
      passed: report.passed,
      failed: report.failed,
      results: report.results,
      error: report.error,
      durationMs,
    };

  } finally {
    if (browserProcess) {
      try {
        browserProcess.kill();
      } catch {}
      if (process.platform === 'win32' && browserProcess.pid) {
        try {
          spawn('taskkill', ['/F', '/T', '/PID', String(browserProcess.pid)], { stdio: 'ignore' });
        } catch {}
      }
    }
    await harness.close();
    // Clean up temp browser data dirs
    const tmpDir = path.resolve(projectRoot, '.browser-tmp-' + browserConfig.id);
    if (fs.existsSync(tmpDir)) {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    }
    const fxTmpDir = path.resolve(projectRoot, '.firefox-tmp-' + browserConfig.id);
    if (fs.existsSync(fxTmpDir)) {
      try {
        fs.rmSync(fxTmpDir, { recursive: true, force: true });
      } catch {}
    }
  }
}

