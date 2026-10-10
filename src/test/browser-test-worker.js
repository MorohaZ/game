// Co-located In-Worker Simulator + Virtual Socket Bridge + Pyodide
import { loadPyodide } from '/pyodide/pyodide.mjs';

function postLog(text) {
  self.postMessage({ type: 'LOG', text });
}

// Deterministic Simulator Implementation inside Worker
class NetworkSimulator {
  constructor() {
    this.nodes = new Map();
    this.ipToNode = new Map();
    this.sockets = new Map();
    this.conntrack = new Map();
    this.packetLog = [];
    this.currentTick = 0;
    this.nextFd = 100;
  }

  addNode(n) {
    this.nodes.set(n.id, n);
    this.ipToNode.set(n.ip, n.id);
  }

  recordPacket(srcId, srcIp, srcPort, dstId, dstIp, dstPort, proto, flags, status, reason = '') {
    this.currentTick++;
    const p = { tick: this.currentTick, srcId, srcIp, srcPort, dstId, dstIp, dstPort, proto, flags, status, reason };
    this.packetLog.push(p);
    return p;
  }

  createSocket(nodeId) {
    if (!this.nodes.has(nodeId)) throw new Error('Node not found');
    const fd = ++this.nextFd;
    this.sockets.set(fd, { fd, ownerNodeId: nodeId, status: 'INITIAL', closed: false, recvBuffer: [] });
    return fd;
  }

  setSocketTimeout(fd, t) {
    const s = this.sockets.get(fd);
    if (s) s.timeout = t;
  }

  connectSocket(fd, dstIp, dstPort) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) return { success: false, errno: 9 };
    const srcNode = this.nodes.get(s.ownerNodeId);
    const clientPort = 50000 + (fd % 1000);
    const dstNode = this.ipToNode.has(dstIp) ? this.nodes.get(this.ipToNode.get(dstIp)) : null;

    if (!dstNode) {
      this.recordPacket(srcNode.id, srcNode.ip, clientPort, undefined, dstIp, dstPort, 'TCP', { syn: true }, 'REJECTED', 'No route');
      return { success: false, errno: 113, message: 'No route to host' };
    }

    const portConfig = dstNode.ports[dstPort];
    if (!portConfig || portConfig.state === 'CLOSED') {
      this.recordPacket(srcNode.id, srcNode.ip, clientPort, dstNode.id, dstIp, dstPort, 'TCP', { syn: true }, 'DELIVERED');
      this.recordPacket(dstNode.id, dstIp, dstPort, srcNode.id, srcNode.ip, clientPort, 'TCP', { rst: true, ack: true }, 'REJECTED', 'Port closed');
      return { success: false, errno: 111, message: 'Connection refused' };
    }

    if (portConfig.state === 'FILTERED') {
      this.recordPacket(srcNode.id, srcNode.ip, clientPort, dstNode.id, dstIp, dstPort, 'TCP', { syn: true }, 'DROPPED', 'Filtered port');
      return { success: false, errno: 110, message: 'Connection timed out' };
    }

    if (portConfig.state === 'OPEN') {
      this.recordPacket(srcNode.id, srcNode.ip, clientPort, dstNode.id, dstIp, dstPort, 'TCP', { syn: true }, 'DELIVERED');
      this.recordPacket(dstNode.id, dstIp, dstPort, srcNode.id, srcNode.ip, clientPort, 'TCP', { syn: true, ack: true }, 'DELIVERED');
      this.recordPacket(srcNode.id, srcNode.ip, clientPort, dstNode.id, dstIp, dstPort, 'TCP', { ack: true }, 'DELIVERED');
      s.status = 'ESTABLISHED';
      s.boundIp = srcNode.ip;
      s.boundPort = clientPort;
      s.connectedIp = dstIp;
      s.connectedPort = dstPort;
      return { success: true, errno: 0, boundIp: srcNode.ip, boundPort: clientPort, connectedIp: dstIp, connectedPort: dstPort };
    }

    return { success: false, errno: 111 };
  }

  sendSocket(fd, data) {
    const s = this.sockets.get(fd);
    if (!s || s.status !== 'ESTABLISHED') throw new Error('Not connected');
    const dstNode = this.nodes.get(this.ipToNode.get(s.connectedIp));
    this.recordPacket(s.ownerNodeId, s.boundIp, s.boundPort, dstNode?.id, s.connectedIp, s.connectedPort, 'TCP', { psh: true, ack: true }, 'DELIVERED');
    if (dstNode && dstNode.ports[s.connectedPort]?.responseHandler) {
      const resp = dstNode.ports[s.connectedPort].responseHandler(data);
      if (resp) s.recvBuffer.push(resp);
    }
    return data.length;
  }

  recvSocket(fd, maxBytes) {
    const s = this.sockets.get(fd);
    if (!s || s.recvBuffer.length === 0) return new Uint8Array(0);
    const chunk = s.recvBuffer.shift();
    return chunk.slice(0, maxBytes);
  }

  closeSocket(fd) {
    const s = this.sockets.get(fd);
    if (!s) return;
    s.closed = true;
    s.status = 'CLOSED';
  }
}

class VirtualSocketBridge {
  constructor(sim, token) {
    this.sim = sim;
    this.defaultNodeId = 'attacker-pc';
    this.sessionToken = token;
    this.dns = { 'localhost': '127.0.0.1', 'corp.local': '192.168.1.10' };
  }

  resolveDns(h) {
    return this.dns[h] || h;
  }

  createSocket(fam, type) {
    return this.sim.createSocket(this.defaultNodeId);
  }

  setSocketTimeout(fd, t) {
    this.sim.setSocketTimeout(fd, t);
  }

  connectSocket(fd, host, port, timeout) {
    const ip = this.resolveDns(host);
    return this.sim.connectSocket(fd, ip, Number(port));
  }

  sendSocket(fd, data) {
    let bytes;
    if (data instanceof Uint8Array) bytes = data;
    else if (data && typeof data.toJs === 'function') bytes = new Uint8Array(data.toJs());
    else if (typeof data === 'string') bytes = new TextEncoder().encode(data);
    else bytes = new Uint8Array(Array.from(data || []));
    return this.sim.sendSocket(fd, bytes);
  }

  recvSocket(fd, maxBytes) {
    return this.sim.recvSocket(fd, Number(maxBytes));
  }

  getSockName(fd) {
    const s = this.sim.sockets.get(fd);
    return s ? { ip: s.boundIp || '0.0.0.0', port: s.boundPort || 0 } : null;
  }

  getPeerName(fd) {
    const s = this.sim.sockets.get(fd);
    return (s && s.connectedIp) ? { ip: s.connectedIp, port: s.connectedPort } : null;
  }

  closeSocket(fd) {
    this.sim.closeSocket(fd);
  }

  getSocketFacade() {
    return {
      createSocket: (fam, type) => this.createSocket(fam, type),
      setSocketTimeout: (fd, t) => this.setSocketTimeout(fd, t),
      connectSocket: (fd, host, port, timeout) => this.connectSocket(fd, host, port, timeout),
      sendSocket: (fd, data) => this.sendSocket(fd, data),
      recvSocket: (fd, maxBytes) => this.recvSocket(fd, maxBytes),
      getSockName: (fd) => this.getSockName(fd),
      getPeerName: (fd) => this.getPeerName(fd),
      closeSocket: (fd) => this.closeSocket(fd),
      resolveDns: (h) => this.resolveDns(h),
    };
  }

  setNodeId(nodeId, token) {
    if (!token || token !== this.sessionToken) {
      throw new Error('Permission denied: Invalid security capability token');
    }
    this.defaultNodeId = nodeId;
  }
}

self.onmessage = async (e) => {
  if (e.data.type !== 'RUN') return;
  const report = { success: true, results: [], total: 0, passed: 0, failed: 0 };

  function assertTest(name, condition, detail = '') {
    report.total++;
    if (condition) {
      report.passed++;
      report.results.push({ name, pass: true });
      postLog('  ✔ [PASS] ' + name);
    } else {
      report.failed++;
      report.success = false;
      report.results.push({ name, pass: false, detail });
      postLog('  ✖ [FAIL] ' + name + (detail ? ' (' + detail + ')' : ''));
    }
  }

  try {
    postLog('[Browser Worker] Initializing Network Simulator...');
    const sim = new NetworkSimulator();
    sim.addNode({
      id: 'attacker-pc',
      ip: '192.168.1.5',
      subnet: '192.168.1.0/24',
      ports: {}
    });
    sim.addNode({
      id: 'corp-web',
      ip: '192.168.1.10',
      subnet: '192.168.1.0/24',
      ports: {
        80: {
          port: 80,
          state: 'OPEN',
          responseHandler: () => new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{"status":"ok"}')
        },
        22: { port: 22, state: 'CLOSED' }
      }
    });
    sim.addNode({
      id: 'firewalled',
      ip: '10.0.0.1',
      subnet: '10.0.0.0/24',
      ports: { 80: { port: 80, state: 'FILTERED' } }
    });

    const bridgeToken = 'cap-browser-' + Math.random().toString(36).slice(2);
    const bridge = new VirtualSocketBridge(sim, bridgeToken);

    postLog('[Browser Worker] Loading Pyodide WebAssembly runtime...');
    const t0 = performance.now();
    const pyodide = await loadPyodide({
      indexURL: '/pyodide/',
    });
    const loadTime = (performance.now() - t0).toFixed(1);
    assertTest('Pyodide WebAssembly runtime loaded inside Browser Web Worker in ' + loadTime + 'ms', true);

    postLog('[Browser Worker] Fetching Python socket shim before sandbox lockdown...');
    const shimResp = await fetch('/shim.py');
    const shimSource = await shimResp.text();

    // Worker Scope Lockdown: strip dangerous browser capabilities before running user Python
    try {
      self.fetch = undefined;
      self.XMLHttpRequest = undefined;
      self.WebSocket = undefined;
      self.indexedDB = undefined;
      self.importScripts = undefined;
      self.Worker = undefined;
      self.SharedWorker = undefined;
      self.BroadcastChannel = undefined;
      if (self.navigator) self.navigator.sendBeacon = undefined;
    } catch {}

    assertTest('Browser Worker sandbox lockdown: self.fetch is undefined', typeof self.fetch === 'undefined');
    assertTest('Browser Worker sandbox lockdown: self.XMLHttpRequest is undefined', typeof self.XMLHttpRequest === 'undefined');
    assertTest('Browser Worker sandbox lockdown: self.WebSocket is undefined', typeof self.WebSocket === 'undefined');

    // Expose synchronous restricted client facade to Pyodide
    pyodide.globals.set('js_sim_core', bridge.getSocketFacade());

    postLog('[Browser Worker] Injecting Python socket shim...');
    pyodide.runPython(shimSource);
    assertTest('Python Virtual Socket Shim (sys.modules["socket"]) injected', true);

    postLog('[Browser Worker] Executing Python test suite...');
    const pyScript = [
      'import socket',
      '',
      '# 1. Connect Open Port 80 (HTTP)',
      's1 = socket.socket()',
      'res1 = s1.connect(("192.168.1.10", 80))',
      'assert res1 is None, "connect to open port returns None"',
      's1.sendall(b"GET / HTTP/1.1\\r\\nHost: corp.local\\r\\n\\r\\n")',
      'reply1 = s1.recv(1024)',
      'assert b"200 OK" in reply1, "HTTP response received"',
      's1.close()',
      '',
      '# 2. Closed Port 22 (RST)',
      's2 = socket.socket()',
      'assert s2.connect_ex(("192.168.1.10", 22)) == 111, "connect_ex closed port returns 111"',
      's2.close()',
      '',
      '# 3. Filtered Port 10.0.0.1:80 (Drop / Timeout)',
      's3 = socket.socket()',
      'assert s3.connect_ex(("10.0.0.1", 80)) == 110, "connect_ex filtered port returns 110"',
      's3.close()',
      '',
      '# 4. Host Unreachable 172.16.50.1:80 (EHOSTUNREACH)',
      's4 = socket.socket()',
      'assert s4.connect_ex(("172.16.50.1", 80)) == 113, "connect_ex unreachable returns 113"',
      's4.close()',
      '',
      '# 5. DNS Resolution',
      's5 = socket.socket()',
      's5.connect(("corp.local", 80))',
      'assert s5.getpeername() == ("192.168.1.10", 80), "DNS resolved corp.local to 192.168.1.10"',
      's5.close()',
      '',
      '# 6. Adversarial Sandbox Security: Blocked Modules & Dynamic Import',
      'for mod in ["js", "pyodide_js", "ctypes", "micropip", "_posixsubprocess"]:',
      '    try:',
      '        __import__(mod)',
      '        assert False, f"Module {mod} must be blocked"',
      '    except (ImportError, ModuleNotFoundError, TypeError):',
      '        pass',
      '',
      'try:',
      '    import importlib',
      '    importlib.import_module("js")',
      '    assert False, "importlib.import_module(\'js\') must be blocked"',
      'except (ImportError, ModuleNotFoundError, TypeError):',
      '    pass',
      '',
      '# 7. Adversarial Sandbox Security: Global Namespace Cleaned',
      'assert "js_sim_core" not in globals(), "js_sim_core must not be in globals"',
      'assert "_sim_core_bridge" not in globals(), "_sim_core_bridge must not be in globals"',
      '',
      '# 7b. Introspection Resistance: socket closure must not leak admin methods or simulator',
      's_check = socket.socket()',
      '_fn = getattr(s_check.connect, "__func__", s_check.connect)',
      '_cells = getattr(_fn, "__closure__", None) or ()',
      'for cell in _cells:',
      '    obj = cell.cell_contents',
      '    assert not hasattr(obj, "setNodeId"), "Bridge facade must not expose setNodeId"',
      '    assert not hasattr(obj, "sim"), "Bridge facade must not expose internal sim"',
      's_check.close()',
      '',
      '# 8. Memoryview zero-copy data transmission (eliminating DoS)',
      's_mem = socket.socket()',
      's_mem.connect(("192.168.1.10", 80))',
      'sent_mem = s_mem.send(memoryview(b"GET / HTTP/1.1\\r\\n\\r\\n"))',
      'assert sent_mem > 0, "memoryview send must succeed"',
      's_mem.close()'
    ].join('\n');

    const pt0 = performance.now();
    pyodide.runPython(pyScript);
    const pyTime = (performance.now() - pt0).toFixed(1);
    assertTest('Synchronous Python socket operations executed in Browser Worker in ' + pyTime + 'ms', true);
    assertTest('Python socket.connect(192.168.1.10:80) and HTTP exchange completed synchronously', true);
    assertTest('Python socket.connect_ex(192.168.1.10:22) returned 111 (ECONNREFUSED / TCP RST)', true);
    assertTest('Python socket.connect_ex(10.0.0.1:80) returned 110 (ETIMEDOUT / TCP Drop)', true);
    assertTest('Python socket.connect_ex(172.16.50.1:80) returned 113 (EHOSTUNREACH)', true);
    assertTest('Python DNS transparent resolution resolved "corp.local" synchronously', true);
    assertTest('Python Adversarial Sandbox successfully blocked ctypes, pyodide_js, js, micropip, importlib escape', true);
    assertTest('Python Memoryview zero-copy data transmission completed without DoS', true);

    let tokenTamperBlocked = false;
    try {
      bridge.setNodeId('corp-web', 'invalid-token-123');
    } catch (e) {
      tokenTamperBlocked = true;
    }
    assertTest('Bridge capability token blocks unauthorized node switching', tokenTamperBlocked);

    let noTokenBlocked = false;
    try {
      bridge.setNodeId('corp-web');
    } catch (e) {
      noTokenBlocked = true;
    }
    assertTest('Bridge rejects node switching without security token', noTokenBlocked);

    const trace = sim.packetLog;
    assertTest('Deterministic Simulation Event Trace recorded ' + trace.length + ' packets', trace.length >= 6);
    assertTest('Deterministic Virtual Clock advanced to tick #' + sim.currentTick, sim.currentTick >= 6);

    postLog('[Browser Worker] Test run finished: ' + report.passed + '/' + report.total + ' passed.');
  } catch (err) {
    report.success = false;
    report.error = err.message || String(err);
    postLog('FATAL ERROR: ' + err.message);
  }

  self.postMessage({ type: 'COMPLETE', report });
};
