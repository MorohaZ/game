# Phase 0 Proof-of-Concept Spike: Acceptance Criteria & Verification Record

**Project:** `NetSec: Zero-Day Protocol`  
**Phase:** Phase 0 (Browser-Native Python Networking & Deterministic Simulation Engine)  
**Status:** **CONDITIONAL GO → FULL GO (All 5 Conditions Verified and Passing)**  
**Verification Suite:** `npm test` (`node test-runner.mjs`)  
**Artifacts Generated:** `browser-test-results.json`  

---

## 1. Architectural Specification & Hosting Requirements

### 1.1 Real Blocking I/O Mechanism in Worker
In standard browser environments, asynchronous JavaScript APIs cannot easily satisfy synchronous Python socket calls (such as `socket.connect(('192.168.1.10', 80))` or `s.recv(1024)`) without complex mechanisms like `Atomics.wait()`, `SharedArrayBuffer`, or WebAssembly JSPI.

**The NetSec Architecture Solution:**
1. **Co-located Worker Architecture:** Pyodide (WASM) and the deterministic discrete-event `NetworkSimulator` run inside the **same Web Worker thread**.
2. **Synchronous Direct Bridge (`VirtualSocketBridge`):** When Python code invokes `socket.connect`, `socket.send`, or `socket.recv`, the call delegates synchronously across the Pyodide Foreign Function Interface (FFI) directly into JavaScript methods on `VirtualSocketBridge`.
3. **In-Memory Deterministic Dispatch:** The `NetworkSimulator` computes routes, evaluates Cisco interface ACLs, updates conntrack tables, and processes mock TCP/UDP packet logs synchronously in memory, returning immediate results (`{ success: true, errno: 0, ... }`) without yielding the JavaScript event loop.
4. **No Atomics / SharedArrayBuffer Needed:** Because execution is co-located and single-threaded within the worker, Python code blocks synchronously in standard execution order **without requiring `SharedArrayBuffer`, `Atomics.wait()`, or WebAssembly JSPI**.

### 1.2 Exact Hosting Requirements: Zero COOP/COEP
Because `SharedArrayBuffer` is completely avoided:
- **No `Cross-Origin-Opener-Policy` (COOP) header required.**
- **No `Cross-Origin-Embedder-Policy` (COEP) header required.**
- **Static Hosting Compatible:** Can be hosted on any standard static web server or CDN (GitHub Pages, Vercel, Netlify, Cloudflare Pages, AWS S3) with default headers.
- **Local Asset Serving:** Pyodide WASM binaries (`pyodide.asm.wasm`, `pyodide.mjs`, `python_stdlib.zip`) are bundled and served locally from `node_modules/pyodide`, eliminating external CDN downtime and security risks.

---

## 2. Real Headless Browser E2E Test Verification Record

Real headless browser tests were executed against both Google Chrome (Chromium) and Mozilla Firefox (Gecko) on Windows:

| Browser Engine | Binary Path | Worker Type | Pyodide Load | Tests Passed | Duration | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Chrome (Chromium)** | `C:\Program Files\Google\Chrome\Application\chrome.exe` | ES Module Worker | 2085.3 ms | **17 / 17 (100%)** | 2742 ms | **PASS** |
| **Mozilla Firefox (Gecko)** | `C:\Program Files\Mozilla Firefox\firefox.exe` | ES Module Worker | 2785.0 ms | **17 / 17 (100%)** | 5001 ms | **PASS** |

The full structured verification payload is recorded in [`browser-test-results.json`](./browser-test-results.json).

---

## 3. Adversarial Sandbox Security Specification

| Threat Vector | Mitigation Mechanism | Verification Test |
| :--- | :--- | :--- |
| **Internal Pyodide Hook Bypass** | `_pyodide._importhook` and `_pyodide_core` are completely blocked. `jsfinder.jsproxies` is purged and uninstalled; direct and indirect imports (`importlib`, `__import__`) of all `_pyodide*` and `pyodide*` packages are blocked at `sys.meta_path[0]`. | Python Test 15 & Browser Test 9, 10, 11 |
| **Worker Scope Lockdown (Fail-Closed)** | `self.fetch`, `self.XMLHttpRequest`, `self.WebSocket`, `self.indexedDB`, `self.importScripts`, `self.Worker`, `self.SharedWorker`, `self.BroadcastChannel`, and `navigator.sendBeacon` are made non-writable `undefined` with strict fail-closed assertion checks. | Browser E2E Tests & Production Worker Bundle |
| **Browser DOM / JS Escape via FFI** | `js` and `pyodide_js` modules are deleted from `sys.modules`, unregistered via `unregister_js_module`, forbidden in `sys.meta_path` `_SandboxFinder`, blocked in `importlib.import_module`, and `pyodide.code.run_js` is deleted. | Python Acceptance Test 15, 15b, 15c |
| **Low-Level Native Memory Access** | `ctypes` and `_posixsubprocess` modules are deleted from `sys.modules`, hooked in `sys.meta_path`, and blocked in `importlib`. | Node & Browser Tests (blocked) |
| **Arbitrary Package Installation** | `micropip` module is revoked, blocked in `sys.meta_path`, and forbidden in import hooks. | Python Acceptance Test 15 |
| **Global Object Introspection** | Global references (`js_sim_core`, `_sim_core_bridge`) are purged from globals immediately after bootstrapping the socket shim. | Python Acceptance Test 15 |
| **Closure & Reflection Introspection** | The object exposed to Python is a restricted `VirtualSocketFacade` containing only socket methods. Administrative methods (`setNodeId`, `setDnsProtectionEnabled`, `getSnapshot`, `restoreSnapshot`, `addDnsRecord`), security tokens, and internal simulator (`#sim`) are strictly absent. | Python Acceptance Test 15d & Browser Test 14 |
| **Cross-Node FD Tampering** | Bridge verifies active node ownership on every socket FD (`s.ownerNodeId === this.#defaultNodeId`). Scripts cannot read, send, or close sockets belonging to other nodes. | Bridge Test 2g3 |
| **Cryptographic Token Security** | `generateSecureToken()` utilizes `crypto.getRandomValues()` (20-byte random nonce) rather than pseudo-random generators. Mandatory token validation rejects calls without a valid token. | Bridge Test 2g, 2g2 & Production Worker |
| **Buffer Memory Exhaustion (DoS)** | Python `_to_bytes` replaces `list(data)` with zero-copy `memoryview(raw).tobytes()`. Node buffer capped at 8MB, socket buffer at 1MB, payload at 1MB. | Bridge Test 13 & Browser Test 8 |

---

## 4. Concurrency Model & Resource Ceilings

### 4.1 Concurrency Model
- **Worker Execution Loop:** Dedicated Web Worker running a single-threaded discrete-event simulation engine.
- **Event Dispatch:** Synchronous discrete ticks (`tick += 1`) advance virtual time deterministically.
- **Race Condition Immunity:** Single-threaded execution eliminates race conditions, thread contention, and non-deterministic packet arrivals.
- **Watchdog State Restoration & UI Queueing:** The UI client maintains a message queue during worker initialization/respawns. When the watchdog terminates a hanging worker, the latest simulation snapshot is restored automatically upon respawn.

### 4.2 Resource Ceilings

```typescript
export const RESOURCE_LIMITS = {
  MAX_SOCKETS_PER_NODE: 32,              // Enforced with EMFILE (24)
  MAX_SOCKET_BUFFER_SIZE: 1024 * 1024,   // 1MB per socket (ENOBUFS: 105)
  MAX_NODE_BUFFER_SIZE: 8 * 1024 * 1024, // 8MB per host node (ENOBUFS: 105)
  MAX_PAYLOAD_SIZE: 1024 * 1024,         // 1MB max per individual send()
};
```

---

## 5. Phase 0 Acceptance Criteria: 1:1 Test Traceability Matrix

| ID | Requirement / Feature | Implementation Location | Test Location | Result |
| :--- | :--- | :--- | :--- | :--- |
| **AC-01** | Deterministic TCP 3-Way Handshake & HTTP Transfer | `NetworkSimulator.connectSocket()`, `sendSocket()`, `recvSocket()` | Suite 1: Test 1.1, 1.2 | **PASS** |
| **AC-02** | Closed Port TCP RST (`ECONNREFUSED` 111) & State Rollback | `NetworkSimulator.connectSocket()` | Suite 1: Test 1.3, 1.3b | **PASS** |
| **AC-03** | Filtered Port Silent Drop & Timeout (`ETIMEDOUT` 110) | `NetworkSimulator.connectSocket()` | Suite 1: Test 1.4 | **PASS** |
| **AC-04** | Route Unreachable Resolution (`EHOSTUNREACH` 113) | `NetworkSimulator.connectSocket()` | Suite 1: Test 1.5 | **PASS** |
| **AC-05** | First-Match Firewall Rule Semantics | `NetworkSimulator.evaluateAcl()` | Suite 1: Test 1.6 | **PASS** |
| **AC-06** | Port Binding & Duplicate Bind (`EADDRINUSE` 98) | `NetworkSimulator.bindSocket()` | Suite 1: Test 1.7 | **PASS** |
| **AC-07** | UDP Datagram Delivery with Real Sender Preservation | `NetworkSimulator.sendToSocket()`, `recvFromSocket()` | Suite 1: Test 1.8 | **PASS** |
| **AC-08** | Dynamic Server Sockets (`listen`, `accept`, bidirectional I/O) | `NetworkSimulator.listenSocket()`, `acceptSocket()` | Suite 1: Test 1.9 | **PASS** |
| **AC-09** | **Stateful Connection Tracking (ESTABLISHED Table)** | `NetworkSimulator.isConntrackEstablished()`, `setConntrack()` | Suite 1: Test 1.10 | **PASS** |
| **AC-10** | **Cisco Interface ACL Binding (`aclsIn`/`aclsOut`) & Implicit Deny** | `NetworkSimulator.getInboundAcl()`, `evaluateAcl()` | Suite 1: Test 1.11 | **PASS** |
| **AC-11** | **Resource Quotas (32 sockets/node EMFILE, 1MB payload cap)** | `NetworkSimulator.createSocket()`, `sendSocket()` | Suite 1: Test 1.12 | **PASS** |
| **AC-12** | **Simulator Topology Snapshot & Restore** | `NetworkSimulator.getSnapshot()`, `restoreSnapshot()` | Suite 1: Test 1.13 | **PASS** |
| **AC-13** | Transparent DNS Resolution & Socket Address Inspection | `VirtualSocketBridge.resolveDns()`, `getSockName()`, `getPeerName()` | Suite 2: Test 2.1–2.4 | **PASS** |
| **AC-14** | **Capability Security Token Enforcement & Omission Rejection** | `VirtualSocketBridge.setNodeId(id, token)` | Suite 2: Test 2.7, 2.7b | **PASS** |
| **AC-14b**| **Cross-Node FD Ownership Protection** | `VirtualSocketBridge.verifySocketOwnership(fd)` | Suite 2: Test 2.7c | **PASS** |
| **AC-15** | **Mission-Configurable DNS Protection (Red Team Spoofing Mode)** | `VirtualSocketBridge.setDnsProtectionEnabled()` | Suite 2: Test 2.8 | **PASS** |
| **AC-16** | **Bridge Snapshot & Restore** | `VirtualSocketBridge.getSnapshot()`, `restoreSnapshot()` | Suite 2: Test 2.9 | **PASS** |
| **AC-17** | Synchronous Python Socket API (`connect`, `connect_ex`, `sendall`, `recv`) | `src/bridge/socket_shim.py` | Suite 3: Python Tests 1–14 | **PASS** |
| **AC-18** | **Adversarial Python Sandbox Lockdown** (`sys.meta_path`, `importlib`, `pyodide.ffi`) | `src/bridge/socket_shim.py` | Suite 3: Python Test 15, 15b, 15c | **PASS** |
| **AC-18b**| **Introspection Hardening: Facade Closure Non-Leakage** | `VirtualSocketBridge.getSocketFacade()` | Suite 3: Python Test 15d & Browser Test 7b | **PASS** |
| **AC-19** | Zero-Copy Python Buffer Handling (`memoryview`, eliminating memory DoS) | `src/bridge/socket_shim.py` (`_to_bytes`) | Suite 3: Python Test 9 & Browser Test 7 | **PASS** |
| **AC-20** | Watchdog State Snapshot Restoration & Message Queue Buffering | `SimWorkerClient.restoreSnapshot()`, `enqueue()` | Unit & Integration Verification | **PASS** |
| **AC-21** | **Headless Chromium Execution (Chrome, ES Module Worker, local Pyodide)** | `src/test/headless-browser-runner.mjs` | Suite 5: Chrome Test (17/17) | **PASS** |
| **AC-22** | **Headless Gecko Execution (Firefox, ES Module Worker, local Pyodide)** | `src/test/headless-browser-runner.mjs` | Suite 5: Firefox Test (17/17) | **PASS** |
| **AC-23** | **Zero COOP/COEP Hosting Compliance Verified** | `src/test/headless-browser-runner.mjs` | Suite 5 (default HTTP headers) | **PASS** |
| **AC-24** | Deterministic Event Trace & Auto-Grader Verification | `NetworkSimulator.getTraceLog()` | Suite 4 | **PASS** |

---

## 6. Verification Summary

Execution of `npm test` runs all 5 test suites synchronously and end-to-end:

```
================================================================
  TEST SUMMARY
================================================================

  Total Tests Run: 79
  Passed:         79
  Failed:         0

  ★★★ PHASE 0 PROOF-OF-CONCEPT SPIKE PASSED ALL ACCEPTANCE CRITERIA ★★★
```

Both real headless browsers (Google Chrome and Mozilla Firefox) successfully initialized Pyodide from local assets inside an ES Module Web Worker, enforced Worker scope lockdown and Python sandbox isolation, and passed all 17 in-worker networking and adversarial tests without requiring COOP or COEP headers. All 5 conditions of the Conditional Go are closed.
