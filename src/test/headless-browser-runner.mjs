import http from 'http';
import fs from 'fs';
import path from 'path';
import { spawn, execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../');
const pyodideDir = path.resolve(projectRoot, 'node_modules/pyodide');
const distPyodideDir = path.resolve(projectRoot, 'dist/pyodide');
const distAssetsDir = path.resolve(projectRoot, 'dist/assets');
const shimPath = path.resolve(projectRoot, 'src/bridge/socket_shim.py');

function findPlaywrightBinaries() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const playwrightRoots = [
    process.env.PLAYWRIGHT_BROWSERS_PATH,
    path.join(home, '.cache', 'ms-playwright'),
    path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'ms-playwright'),
  ].filter(Boolean);

  const binaries = { chromium: [], firefox: [], webkit: [] };

  for (const root of playwrightRoots) {
    if (!fs.existsSync(root)) continue;
    try {
      const entries = fs.readdirSync(root);
      for (const entry of entries) {
        const fullDir = path.join(root, entry);
        if (entry.startsWith('chromium-')) {
          const candidates = [
            path.join(fullDir, 'chrome-linux', 'chrome'),
            path.join(fullDir, 'chrome-win', 'chrome.exe'),
            path.join(fullDir, 'chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium'),
          ];
          for (const c of candidates) {
            if (fs.existsSync(c)) binaries.chromium.push(c);
          }
        } else if (entry.startsWith('firefox-')) {
          const candidates = [
            path.join(fullDir, 'firefox', 'firefox'),
            path.join(fullDir, 'firefox', 'firefox.exe'),
            path.join(fullDir, 'firefox', 'Nightly.app', 'Contents', 'MacOS', 'firefox'),
          ];
          for (const c of candidates) {
            if (fs.existsSync(c)) binaries.firefox.push(c);
          }
        } else if (entry.startsWith('webkit-')) {
          const candidates = [
            path.join(fullDir, 'pw_run.sh'),
            path.join(fullDir, 'minibrowser'),
            path.join(fullDir, 'minibrowser-gtk', 'MiniBrowser'),
            path.join(fullDir, 'Playwright.exe'),
            path.join(fullDir, 'pw_run.bat'),
          ];
          for (const c of candidates) {
            if (fs.existsSync(c)) binaries.webkit.push(c);
          }
        }
      }
    } catch {}
  }
  return binaries;
}

export function getAvailableBrowsers() {
  const user = process.env.USERNAME || process.env.USER || 'ken11';
  const pwBinaries = findPlaywrightBinaries();

  const candidates = [
    {
      id: 'chromium',
      name: 'Google Chrome (Chromium)',
      type: 'chromium',
      paths: [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        `C:\\Users\\${user}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe`,
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        ...pwBinaries.chromium,
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
        '/usr/bin/firefox',
        ...pwBinaries.firefox,
      ],
    },
    {
      id: 'edge',
      name: 'Microsoft Edge (Chromium)',
      type: 'chromium',
      paths: [
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      ],
    },
    {
      id: 'webkit',
      name: 'Playwright WebKit',
      type: 'webkit',
      paths: pwBinaries.webkit,
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

export const DEFAULT_CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline';";
export const DEFAULT_WORKER_CSP_HEADER = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self';";

export function createTestServer(options = {}) {
  const effectiveCsp = options.cspHeader !== undefined ? options.cspHeader : DEFAULT_CSP_HEADER;
  const effectiveWorkerCsp = options.workerCspHeader !== undefined ? options.workerCspHeader : DEFAULT_WORKER_CSP_HEADER;
  const shimCode = fs.readFileSync(shimPath, 'utf-8');
  
  // Use production built sim-worker bundle
  let workerCode = '';
  if (fs.existsSync(distAssetsDir)) {
    const workerFile = fs.readdirSync(distAssetsDir).find(f => f.startsWith('sim-worker-') && f.endsWith('.js'));
    if (workerFile) {
      workerCode = fs.readFileSync(path.join(distAssetsDir, workerFile), 'utf-8');
    }
  }

  if (!workerCode) {
    const fallbackPath = path.resolve(__dirname, 'browser-test-worker.js');
    if (fs.existsSync(fallbackPath)) {
      workerCode = fs.readFileSync(fallbackPath, 'utf-8');
    }
  }

  return new Promise((resolve, reject) => {
    let reportResolver = null;
    let reportRejecter = null;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === '/' || url.pathname === '/index.html') {
        const headers = { 'Content-Type': 'text/html; charset=utf-8' };
        if (effectiveCsp) {
          headers['Content-Security-Policy'] = effectiveCsp;
        }
        res.writeHead(200, headers);
        res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Production Web Worker E2E Test Harness</title>
</head>
<body style="font-family: monospace; background: #0f172a; color: #f8fafc; padding: 20px;">
  <h2>[Headless Browser Production Web Worker E2E Test Harness]</h2>
  <div id="status" style="color: #38bdf8; margin-bottom: 10px;">Initializing Production Web Worker...</div>
  <pre id="log" style="background: #1e293b; padding: 15px; border-radius: 8px; max-height: 500px; overflow: auto;"></pre>
  <script type="module" src="/harness.js"></script>
</body>
</html>`);
        return;
      }

      if (url.pathname === '/harness.js') {
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
        res.end(`
    const statusEl = document.getElementById('status');
    const logEl = document.getElementById('log');
    const results = [];

    function log(msg) {
      logEl.textContent += msg + '\\n';
    }

    function recordAssert(pass, name, detail) {
      results.push({ name, pass: Boolean(pass), detail });
      if (pass) {
        log('  ✔ [PASS] ' + name);
      } else {
        log('  ✖ [FAIL] ' + name + (detail ? ' (' + detail + ')' : ''));
      }
    }

    function recordXFailAssert(pass, name, gapDetail) {
      if (pass) {
        results.push({ name, pass: true, xfail: false });
        log('  ✔ [PASS/XPASS] ' + name + ' (Gap is closed!)');
      } else {
        results.push({ name, pass: false, xfail: true, detail: gapDetail });
        log('  ⚠ [XFAIL] ' + name + ' (' + gapDetail + ')');
      }
    }

    async function run() {
      try {
        log('1. Checking Browser Hosting Isolation (Zero COOP/COEP)...');
        recordAssert(window.crossOriginIsolated === false, 'Zero COOP/COEP compliance: window.crossOriginIsolated is false');

        log('1b. Checking Content Security Policy (CSP) Enforcement...');
        let functionEvalBlocked = false;
        try {
          const fn = new Function('return 42');
          fn();
          functionEvalBlocked = false;
        } catch (evalErr) {
          functionEvalBlocked = true;
        }
        recordAssert(functionEvalBlocked, 'CSP active enforcement: Function/eval execution blocked without unsafe-eval');

        log('2. Spawning Production Web Worker (/worker.js)...');
        const worker = new Worker('/worker.js', { type: 'module' });

        function sendAndAwait(msg, expectedType, timeoutMs = 35000) {
          return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
              cleanup();
              reject(new Error('Timeout waiting for worker reply: ' + expectedType));
            }, timeoutMs);

            function onMsg(e) {
              const data = e.data;
              if (data && data.type === expectedType) {
                cleanup();
                resolve(data);
              } else if (data && data.type === 'INIT_ERROR') {
                cleanup();
                reject(new Error('Worker Init Error: ' + (data.payload?.error || JSON.stringify(data))));
              }
            }

            function onErr(err) {
              cleanup();
              reject(err);
            }

            function cleanup() {
              clearTimeout(timer);
              worker.removeEventListener('message', onMsg);
              worker.removeEventListener('error', onErr);
            }

            worker.addEventListener('message', onMsg);
            worker.addEventListener('error', onErr);
            worker.postMessage(msg);
          });
        }

        const tInitStart = performance.now();
        const initResp = await sendAndAwait({ type: 'INIT' }, 'READY', 35000);
        const initDur = (performance.now() - tInitStart).toFixed(1);
        recordAssert(true, 'Production Web Worker initialized with local Pyodide v' + (initResp.payload?.version || '0.26.4') + ' in ' + initDur + 'ms');

        // Verify Fail-Closed Worker Scope Lockdown for all 10 APIs individually
        log('2b. Verifying Worker API Scope Lockdown for all APIs individually...');
        const lockdown = initResp.payload?.lockdown || {};
        const apisToCheck = [
          'fetch',
          'XMLHttpRequest',
          'WebSocket',
          'indexedDB',
          'importScripts',
          'Worker',
          'SharedWorker',
          'BroadcastChannel',
          'openDatabase',
          'sendBeacon',
        ];
        for (const api of apisToCheck) {
          const isNeutralized = Boolean(lockdown[api]);
          recordAssert(isNeutralized, 'Worker API lockdown: self.' + api + ' is neutralized');
        }

        // Test Python synchronous networking & core functionality with individual assertions
        log('3. Running Python synchronous networking tests (per-key verification)...');
        const netTestPy = \`
import socket, json

net_res = {}

# Test 1: Open Port & HTTP Exchange
try:
    s1 = socket.socket()
    s1.connect(('192.168.1.10', 80))
    s1.sendall(b"GET / HTTP/1.1\\\\r\\\\nHost: corp.local\\\\r\\\\n\\\\r\\\\n")
    resp = s1.recv(1024)
    net_res["connect_open_http"] = (b"200 OK" in resp)
    s1.close()
except Exception:
    net_res["connect_open_http"] = False

# Test 2: Closed Port TCP RST
try:
    s2 = socket.socket()
    net_res["connect_closed_rst"] = (s2.connect_ex(('192.168.1.10', 22)) == 111)
    s2.close()
except Exception:
    net_res["connect_closed_rst"] = False

# Test 3: Filtered Port TCP Drop
try:
    s3 = socket.socket()
    net_res["connect_filtered_drop"] = (s3.connect_ex(('10.0.0.1', 80)) == 110)
    s3.close()
except Exception:
    net_res["connect_filtered_drop"] = False

# Test 4: Host Unreachable
try:
    s4 = socket.socket()
    net_res["connect_host_unreach"] = (s4.connect_ex(('172.16.50.1', 80)) == 113)
    s4.close()
except Exception:
    net_res["connect_host_unreach"] = False

# Test 5: Transparent DNS Resolution
try:
    s5 = socket.socket()
    net_res["dns_resolution"] = (s5.connect_ex(('corp.local', 80)) == 0)
    s5.close()
except Exception:
    net_res["dns_resolution"] = False

# Test 6: Memoryview buffer handling
try:
    s6 = socket.socket()
    s6.connect(('192.168.1.10', 80))
    mv = memoryview(b"GET / HTTP/1.1\\\\r\\\\nHost: corp.local\\\\r\\\\n\\\\r\\\\n")
    n = s6.send(mv)
    resp6 = s6.recv(1024)
    net_res["memoryview_send"] = (n > 0 and b"200 OK" in resp6)
    s6.close()
except Exception:
    net_res["memoryview_send"] = False

print("__NET_RESULTS__:" + json.dumps(net_res))
\`;

        const netResMsg = await sendAndAwait({
          type: 'RUN_CODE',
          payload: { code: netTestPy, runId: 'net-run-1' }
        }, 'CODE_RESULT');

        let netParsed = {};
        try {
          const m = (netResMsg.payload.stdout || '').match(/__NET_RESULTS__:(.*)/);
          if (m) netParsed = JSON.parse(m[1].trim());
        } catch {}

        recordAssert(netParsed.connect_open_http === true, 'Python socket.connect(192.168.1.10:80) and HTTP exchange completed synchronously');
        recordAssert(netParsed.connect_closed_rst === true, 'Python socket.connect_ex(192.168.1.10:22) returned 111 (ECONNREFUSED / TCP RST)');
        recordAssert(netParsed.connect_filtered_drop === true, 'Python socket.connect_ex(10.0.0.1:80) returned 110 (ETIMEDOUT / TCP Drop)');
        recordAssert(netParsed.connect_host_unreach === true, 'Python socket.connect_ex(172.16.50.1:80) returned 113 (EHOSTUNREACH)');
        recordAssert(netParsed.dns_resolution === true, 'Python DNS transparent resolution resolved "corp.local" synchronously');
        recordAssert(netParsed.memoryview_send === true, 'Python memoryview buffer transmission completed without DoS');

        // Test Attack Surface Reduction in real Production Worker
        log('4. Running Attack Surface Reduction tests (per-key verification)...');
        const advTestPy = \`
import json

adv_res = {}

# Attack 1: _pyodide._importhook & jsfinder blocked
try:
    import _pyodide._importhook
    adv_res["importhook_blocked"] = False
except (ImportError, ModuleNotFoundError):
    try:
        __import__('_pyodide._importhook')
        adv_res["importhook_blocked"] = False
    except (ImportError, ModuleNotFoundError):
        adv_res["importhook_blocked"] = True

# Attack 2: _pyodide_core and trigger_fatal_error blocked
try:
    import _pyodide_core
    adv_res["pyodide_core_blocked"] = False
except (ImportError, ModuleNotFoundError):
    adv_res["pyodide_core_blocked"] = True

# Attack 3: pyodide root package & pyodide.ffi blocked
try:
    import pyodide
    adv_res["pyodide_ffi_blocked"] = False
except (ImportError, ModuleNotFoundError):
    try:
        import pyodide.ffi
        adv_res["pyodide_ffi_blocked"] = False
    except (ImportError, ModuleNotFoundError):
        adv_res["pyodide_ffi_blocked"] = True

# Attack 4: Standard forbidden modules blocked individually
def _check_mod_blocked(name):
    try:
        __import__(name)
        return False
    except (ImportError, ModuleNotFoundError, TypeError):
        return True
    except Exception:
        return True

adv_res["ctypes_blocked"] = _check_mod_blocked('ctypes')
adv_res["pyodide_js_blocked"] = _check_mod_blocked('pyodide_js')
adv_res["js_blocked"] = _check_mod_blocked('js')
adv_res["micropip_blocked"] = _check_mod_blocked('micropip')
adv_res["posixsubprocess_blocked"] = _check_mod_blocked('_posixsubprocess')

# Attack 5: Global introspection leaks
adv_res["globals_purged"] = ('js_sim_core' not in globals() and '_sim_core' not in globals())

print("__ADV_RESULTS__:" + json.dumps(adv_res))
\`;

        const advResMsg = await sendAndAwait({
          type: 'RUN_CODE',
          payload: { code: advTestPy, runId: 'adv-run-1' }
        }, 'CODE_RESULT');

        let advParsed = {};
        try {
          const m = (advResMsg.payload.stdout || '').match(/__ADV_RESULTS__:(.*)/);
          if (m) advParsed = JSON.parse(m[1].trim());
        } catch {}

        recordAssert(advParsed.importhook_blocked === true, 'Adversarial attack surface: _pyodide._importhook & jsfinder blocked');
        recordAssert(advParsed.pyodide_core_blocked === true, 'Adversarial attack surface: _pyodide_core & trigger_fatal_error blocked');
        recordAssert(advParsed.pyodide_ffi_blocked === true, 'Adversarial attack surface: pyodide and pyodide.ffi blocked');
        recordAssert(advParsed.ctypes_blocked === true, 'Adversarial attack surface: ctypes module blocked');
        recordAssert(advParsed.pyodide_js_blocked === true, 'Adversarial attack surface: pyodide_js module blocked');
        recordAssert(advParsed.js_blocked === true, 'Adversarial attack surface: js module blocked');
        recordAssert(advParsed.micropip_blocked === true, 'Adversarial attack surface: micropip package blocked');
        recordAssert(advParsed.posixsubprocess_blocked === true, 'Adversarial attack surface: _posixsubprocess module blocked');
        recordAssert(advParsed.globals_purged === true, 'Introspection Isolation: js_sim_core and _sim_core purged from globals');

        // Test Expected-to-Fail Known Gaps
        log('5. Running Expected-to-Fail (xfail) tests for 3 Known Gaps...');
        const gapsTestPy = \`
import sys, socket, json

gap_res = {}

# Known Gap 1: Facade prototype / constructor traversal
gap1_sealed = True
try:
    s = socket.socket()
    for meth_name in ['connect_ex', 'send', 'recv', 'bind', 'listen', 'accept', 'close', '__init__']:
        fn = getattr(s, meth_name, None)
        if not fn:
            continue
        func = getattr(fn, '__func__', fn)
        for cell in (getattr(func, '__closure__', None) or ()):
            obj = getattr(cell, 'cell_contents', None)
            if obj is None:
                continue
            if hasattr(obj, 'constructor') and hasattr(obj.constructor, 'constructor'):
                if 'Function' in str(obj.constructor.constructor) or callable(obj.constructor.constructor):
                    gap1_sealed = False
                    break
            for attr in ['createSocket', 'connectSocket', 'sendSocket', 'recvSocket']:
                if hasattr(obj, attr):
                    m = getattr(obj, attr)
                    if hasattr(m, 'constructor') and ('Function' in str(m.constructor) or callable(m.constructor)):
                        gap1_sealed = False
                        break
            if not gap1_sealed:
                break
        if not gap1_sealed:
            break
    s.close()
except Exception:
    pass
gap_res["gap1_sealed"] = gap1_sealed

# Known Gap 2: Pyodide event-loop / asyncio internal JsProxy references
gap2_sealed = True
try:
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        for k, v in getattr(loop, '__dict__', {}).items():
            if 'JsProxy' in type(v).__name__ or 'JsProxy' in str(type(v)):
                gap2_sealed = False
                break
    except Exception:
        pass
    if gap2_sealed:
        for mod in list(sys.modules.values()):
            if mod is None:
                continue
            for k, v in getattr(mod, '__dict__', {}).items():
                if 'scheduleCallback' in str(k) or 'loadedPackages' in str(k) or 'JsProxy' in type(v).__name__:
                    gap2_sealed = False
                    break
            if not gap2_sealed:
                break
    if gap2_sealed:
        gap2_sealed = False
except Exception:
    gap2_sealed = False
gap_res["gap2_sealed"] = gap2_sealed

# Known Gap 3: Python garbage collection (gc) object graph traversal
gap3_sealed = True
try:
    import gc
    proxies = [o for o in gc.get_objects() if 'JsProxy' in type(o).__name__]
    if len(proxies) > 0:
        gap3_sealed = False
except Exception:
    pass
gap_res["gap3_sealed"] = gap3_sealed

print("__GAP_RESULTS__:" + json.dumps(gap_res))
\`;

        const gapsResMsg = await sendAndAwait({
          type: 'RUN_CODE',
          payload: { code: gapsTestPy, runId: 'gaps-run-1' }
        }, 'CODE_RESULT');

        let gapsParsed = {};
        try {
          const m = (gapsResMsg.payload.stdout || '').match(/__GAP_RESULTS__:(.*)/);
          if (m) gapsParsed = JSON.parse(m[1].trim());
        } catch {}

        recordXFailAssert(gapsParsed.gap1_sealed === true, 'Known Gap 1: Bridge facade prototype isolation', 'Constructor chain reaches Function (Expected gap in v1)');
        recordXFailAssert(gapsParsed.gap2_sealed === true, 'Known Gap 2: Pyodide event-loop / asyncio internal JsProxy isolation', 'Event loop / modules leak JsProxy (Expected gap in v1)');
        recordXFailAssert(gapsParsed.gap3_sealed === true, 'Known Gap 3: Garbage collection object graph traversal isolation', 'gc.get_objects() locates live JsProxy handles (Expected gap in v1)');

        // Test Deterministic Simulation Event Trace via Worker RPC
        log('6. Testing Simulation Event Trace via Worker RPC...');
        const traceRes = await sendAndAwait({ type: 'GET_TRACE' }, 'TRACE_RESULT');
        recordAssert(traceRes.payload.events && traceRes.payload.events.length >= 5, 'Production Worker recorded deterministic simulation packet trace (' + (traceRes.payload.events ? traceRes.payload.events.length : 0) + ' events)');

        // Test Simulator Snapshot and Restore via Worker RPC
        log('7. Testing Snapshot & Restore via Worker RPC...');
        const snapRes = await sendAndAwait({ type: 'GET_SNAPSHOT' }, 'SNAPSHOT_RESULT');
        recordAssert(!!snapRes.payload.snapshot && snapRes.payload.snapshot.nodes.length >= 3, 'Worker GET_SNAPSHOT returned valid topology snapshot');

        const restoreRes = await sendAndAwait({
          type: 'RESTORE_SNAPSHOT',
          payload: { snapshot: snapRes.payload.snapshot }
        }, 'RESTORE_DONE');
        recordAssert(restoreRes.type === 'RESTORE_DONE', 'Worker RESTORE_SNAPSHOT successfully restored simulator state');

        // Final Report: allPass requires every non-xfail test to pass
        const allPass = results.every(r => r.pass || r.xfail === true);
        statusEl.textContent = allPass ? 'ALL TESTS PASSED' : 'TESTS FAILED';
        statusEl.style.color = allPass ? '#4ade80' : '#f87171';

        await fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            success: allPass,
            total: results.length,
            passed: results.filter(r => r.pass).length,
            failed: results.filter(r => !r.pass && !r.xfail).length,
            xfail: results.filter(r => r.xfail).length,
            results: results
          }),
        });

      } catch (err) {
        log('FATAL TEST ERROR: ' + (err.message || String(err)));
        await fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            success: false,
            error: err.message || String(err),
            total: results.length,
            passed: results.filter(r => r.pass).length,
            failed: results.filter(r => !r.pass && !r.xfail).length + 1,
            xfail: results.filter(r => r.xfail).length,
            results: results
          }),
        });
      }
    }

    run();
`);
        return;
      }

      if (url.pathname === '/worker.js') {
        const headers = { 'Content-Type': 'application/javascript; charset=utf-8' };
        if (effectiveWorkerCsp) {
          headers['Content-Security-Policy'] = effectiveWorkerCsp;
        }
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

      if (url.pathname === '/shim.py') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(shimCode);
        return;
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
        waitForReport: (timeoutMs = 45000) => {
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
        close: () => new Promise(res => server.close(res)),
      });
    });
  });
}

export async function runBrowserTest(browserTarget, options = {}) {
  const { port, server, waitForReport, close } = await createTestServer(options);
  const testUrl = `http://127.0.0.1:${port}/index.html`;

  let browserVersion = 'unknown';
  try {
    const v = execSync(`"${browserTarget.path}" --version`, { timeout: 3000 }).toString().trim();
    if (v) browserVersion = v;
  } catch {}
  if (browserVersion === 'unknown' && process.platform === 'win32') {
    try {
      const v = execSync(`powershell -NoProfile -Command "(Get-Item '${browserTarget.path}').VersionInfo.ProductVersion"`, { timeout: 3000 }).toString().trim();
      if (v) browserVersion = `${browserTarget.name} ${v}`;
    } catch {}
  }

  let browserProcess;
  const tmpDir = path.resolve(projectRoot, `.browser-tmp-${browserTarget.id}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  const commonArgs = [
    '--headless',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-dev-shm-usage',
  ];

  if (browserTarget.type === 'chromium') {
    browserProcess = spawn(browserTarget.path, [
      ...commonArgs,
      `--user-data-dir=${tmpDir}`,
      testUrl,
    ]);
  } else if (browserTarget.type === 'firefox') {
    browserProcess = spawn(browserTarget.path, [
      '--headless',
      '--profile',
      tmpDir,
      testUrl,
    ]);
  } else if (browserTarget.type === 'webkit') {
    browserProcess = spawn(browserTarget.path, [
      '--headless',
      testUrl,
    ]);
  } else {
    browserProcess = spawn(browserTarget.path, [testUrl]);
  }

  const tBrowserStart = performance.now();
  try {
    const report = await waitForReport(45000);
    const durationMs = Math.round(performance.now() - tBrowserStart);
    return {
      browser: browserTarget.name,
      browserId: browserTarget.id,
      browserVersion,
      browserPath: browserTarget.path,
      durationMs,
      ...report,
    };
  } finally {
    try {
      if (browserProcess && !browserProcess.killed) {
        browserProcess.kill('SIGKILL');
      }
    } catch {
      // Ignore process kill errors
    }
    await close();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Non-blocking cleanup
    }
  }
}
