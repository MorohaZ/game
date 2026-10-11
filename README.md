# NetSec: Zero-Day Protocol
## Phase 0: Proof-of-Concept Vertical Spike

### 1. Executive Summary & Objective

This Proof-of-Concept (Phase 0) proves the feasibility of the **Co-located Worker Architecture** for **NetSec: Zero-Day Protocol**, solving the core engineering challenge of running standard Python networking code inside Pyodide in the browser without deadlocks or thread blocking.

In standard Pyodide, Python socket operations are synchronous (e.g., `s.connect(('192.168.1.10', 80))`). If the network simulation engine runs on the main browser thread or in a separate Web Worker, synchronous Python calls cannot await asynchronous `postMessage` events without complex, fragile SharedArrayBuffer / Atomics polling mechanisms.

**The Solution:** Both Pyodide and the **Deterministic Network Simulator Core** are co-located inside the **same Web Worker**. Python socket calls translate into **direct, synchronous JavaScript function calls** across the WebAssembly boundary (`JsProxy`) with sub-millisecond execution times.

---

### 2. Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────┐
│ Browser Main Thread (Presentation Layer)                        │
│ - Vite App (index.html, src/ui/app.ts)                          │
│ - Code Editor & Presets                                         │
│ - Live Output Terminal                                          │
│ - Simulation Event Trace Inspector Table                        │
│ - Main-Thread Watchdog (Terminates hanging workers)             │
└───────────────────────────────┬─────────────────────────────────┘
                                │ postMessage (Async RPC)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ Co-located Web Worker Sandbox (Deterministic Execution)         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Pyodide Python Runtime (WASM)                             │  │
│  │ - Python Virtual Socket Shim (sys.modules['socket'])      │  │
│  │   - s.connect(('192.168.1.10', 80))                       │  │
│  │   - s.sendall(data) / s.recv(1024)                        │  │
│  │   - raises ConnectionRefusedError / TimeoutError          │  │
│  └─────────────────────────────┬─────────────────────────────┘  │
│                                │ Direct Synchronous Calls       │
│                                │ (Microsecond JsProxy)          │
│                                ▼                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ VirtualSocketBridge (js_sim_core)                         │  │
│  │ - createSocket, connectSocket, sendSocket, recvSocket     │  │
│  │ - DNS Resolver, Port State Translator                    │  │
│  └─────────────────────────────┬─────────────────────────────┘  │
│                                │ Synchronous                    │
│                                ▼                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Deterministic In-Memory Network Simulator Core            │  │
│  │ - Virtual Clock (Deterministic Ticks)                     │  │
│  │ - Nodes (Attacker, Corp-Web, Firewalled Host)             │  │
│  │ - L3 Routing & L4 Ports (Open, Closed, Filtered)          │  │
│  │ - Packet Event Trace Logger                               │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 3. Core Acceptance Criteria Verified

1. **Deterministic Network Simulator Core**:
   - Node and subnet topology with deterministic Virtual Clock ticks.
   - **Open Port (`192.168.1.10:80`)**: Completes full 3-way TCP handshake (SYN -> SYN-ACK -> ACK). Returns `errno: 0` (`success: true`).
   - **Closed Port (`192.168.1.10:22`)**: Emits TCP SYN, receives TCP RST with status `REJECTED`. Returns `errno: 111` (`ECONNREFUSED`).
   - **Filtered Port (`10.0.0.1:80`)**: Emits TCP SYN, silently dropped by firewall rule with status `DROPPED`. Returns `errno: 110` (`ETIMEDOUT`).
   - **Host Unreachable (`172.16.50.1:80`)**: Returns `errno: 113` (`EHOSTUNREACH`).

2. **Python Virtual Socket Shim (`sys.modules['socket']`)**:
   - Python code executes 100% synchronously without blocking or hanging:
     ```python
     import socket

     # Pattern A: Standard socket.connect() (raises exceptions on failure)
     # 1. Open Port: connects successfully, returns None
     s_open = socket.socket()
     s_open.connect(('192.168.1.10', 80))
     s_open.close()

     # 2. Closed Port: raises ConnectionRefusedError synchronously
     s_closed = socket.socket()
     try:
         s_closed.connect(('192.168.1.10', 22))
     except ConnectionRefusedError:
         pass  # Expected ECONNREFUSED
     s_closed.close()

     # 3. Filtered Port: raises TimeoutError synchronously
     s_filtered = socket.socket()
     try:
         s_filtered.connect(('10.0.0.1', 80))
     except TimeoutError:
         pass  # Expected ETIMEDOUT
     s_filtered.close()

     # Pattern B: Non-throwing socket.connect_ex() (returns errno integer)
     s_ex = socket.socket()
     assert s_ex.connect_ex(('192.168.1.10', 80)) == 0    # Success (errno 0)
     assert s_ex.connect_ex(('192.168.1.10', 22)) == 111  # ECONNREFUSED (errno 111)
     assert s_ex.connect_ex(('10.0.0.1', 80)) == 110      # ETIMEDOUT (errno 110)
     assert s_ex.connect_ex(('172.16.50.1', 80)) == 113   # EHOSTUNREACH (errno 113)
     s_ex.close()
     ```

3. **Simulation Event Trace Capture**:
   - Every simulated packet records:
     - Sequential `pkt-XXXX` ID
     - Deterministic Virtual Tick counter
     - Source IP:Port and Target IP:Port
     - L4 Protocol (`TCP`) and TCP Flags (`SYN`, `ACK`, `RST`, `PSH`)
     - Delivery Status (`DELIVERED`, `DROPPED`, `REJECTED`)
     - Human-readable reason / audit log

4. **Watchdog Infinite-Loop Protection**:
   - Main thread watchdog timer enforces a maximum execution window (e.g. 5.0 seconds).
   - If user script enters `while True: pass`, watchdog triggers `worker.terminate()`, re-spawns a fresh worker instance, and restores state without locking the browser UI.

---

### 4. Running the Tests & Verification

#### Option A: Run Standalone CLI Test Suite
```bash
node test-runner.mjs
# or
npm test
```
The test runner executes:
- Suite 1: Network Simulator Core Unit Tests
- Suite 2: Virtual Socket Bridge API Tests
- Suite 3: Python Socket Shim & Pyodide Synchronous Contract Tests
- Suite 4: Event Trace & Deterministic Tick Verification

#### Option B: Run Browser Interactive Spike with Vite
```bash
npm install
npm run dev
```
Open `http://localhost:3000` in your browser:
- Click **"▶ Run Python in Worker"** to execute the Python script live inside Pyodide WASM.
- Inspect real-time stdout logs and the Packet Trace inspector table.
- Test the presets: Open Port, Closed Port, Filtered Port, and Watchdog Infinite Loop recovery.

---

### 5. Repository File Structure

```
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions CI workflow (lint, test, browser E2E)
├── scripts/
│   ├── copy-pyodide.mjs            # Bundles local Pyodide runtime assets to public/dist
│   ├── csp-config.mjs              # Centralized CSP configuration & hosting sync generator
│   ├── csp-experiment.mjs          # CSP behavioral probe and header validation tool
│   ├── generate-browser-table.mjs  # Generates acceptance criteria markdown table
│   └── sync-shim.mjs               # Compiles socket_shim.py to python-socket-shim.ts
├── public/
│   └── _headers                    # Cloudflare Pages / Static hosting headers
├── _headers                        # Netlify static headers with CSP & nosniff
├── netlify.toml                    # Netlify deployment configuration
├── vercel.json                     # Vercel deployment headers configuration
├── GAME_DESIGN_DOCUMENT.md         # Original system architecture document
├── PHASE_0_ACCEPTANCE_CRITERIA.md  # Acceptance criteria & verification record matrix
├── package.json                    # Scripts and dependencies
├── package-lock.json               # Deterministic dependency lockfile
├── tsconfig.json                   # TypeScript configuration
├── vite.config.ts                  # Vite & Web Worker bundle settings
├── index.html                      # Interactive Phase 0 Spike UI
├── test-runner.mjs                 # Zero-dependency CLI & browser test harness
├── README.md                       # Phase 0 documentation & verification report
└── src/
    ├── core/
    │   ├── types.ts                # TypeScript interfaces (Node, Port, Packet, Errno)
    │   ├── NetworkSimulator.ts     # Deterministic in-memory network simulator core
    │   └── default-topology.ts     # Pre-configured topology (Attacker, Corp-Web, Firewalled)
    ├── bridge/
    │   ├── VirtualSocketBridge.ts  # Synchronous JS bridge (`js_sim_core`)
    │   ├── python-socket-shim.ts   # Auto-generated Python bootstrap injected into Pyodide
    │   └── socket_shim.py          # Master Python socket replacement module & sandbox policy
    ├── security/
    │   └── csp-config.ts           # TypeScript CSP constants and assertCspActive probe
    ├── worker/
    │   ├── sim-worker.ts           # Co-located Web Worker loading Pyodide + Simulator
    │   └── worker-protocol.ts      # Typed postMessage RPC protocol
    ├── client/
    │   └── SimWorkerClient.ts      # Main thread client with Watchdog recovery
    ├── ui/
    │   ├── app.ts                  # Browser UI controller & test presets
    │   └── styles.css              # Cyber OS terminal styling
    └── test/
        ├── NetworkSimulator.test.ts
        ├── VirtualSocketBridge.test.ts
        └── headless-browser-runner.mjs # Multi-browser headless automation engine
```

---

### 6. Project Description & Status

**NetSec: Zero-Day Protocol** is an adversarial cybersecurity simulation and educational hacking game that executes natively in the browser. Players write standard, synchronous Python socket code to discover hosts, map networks, exploit misconfigurations, and interact with virtual targets in real-time.

Phase 0 validates the **Co-located Worker Architecture**, combining Pyodide WASM and a deterministic discrete-event discrete simulation engine in the same Web Worker. This achieves synchronous Python networking without deadlocks, without requiring `SharedArrayBuffer` or COOP/COEP headers, and provides full compatibility with standard static hosting (GitHub Pages, Netlify, Vercel, Cloudflare Pages).

---

### 7. License

MIT License. Copyright (c) 2026 NetSec Protocol Contributors.

