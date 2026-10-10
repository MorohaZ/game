import { SimWorkerClient } from '../client/SimWorkerClient';
import { PacketTraceEntry } from '../core/types';

const PRESETS: Record<string, string> = {
  full: `# === NetSec Phase 0 Acceptance Criteria Test ===
import socket

print("[-] Starting Phase 0 PoC Verification...")

# 1. Open Port (80)
print("\\n[Test 1] Target 192.168.1.10:80 (HTTP Open)")
s1 = socket.socket()
code1 = s1.connect_ex(('192.168.1.10', 80))
print(f"  -> connect_ex returned: {code1} (0=OK)")
assert code1 == 0, f"Expected 0, got {code1}"

# Send data and verify round-trip
s1.sendall(b"GET / HTTP/1.1\\r\\nHost: 192.168.1.10\\r\\n\\r\\n")
reply = s1.recv(256)
print(f"  -> Received reply: {reply[:35]}...")
s1.close()

# 2. Closed Port (22 - TCP RST)
print("\\n[Test 2] Target 192.168.1.10:22 (SSH Closed / RST)")
s2 = socket.socket()
code2 = s2.connect_ex(('192.168.1.10', 22))
print(f"  -> connect_ex returned: {code2} (111=ECONNREFUSED)")
assert code2 == 111, f"Expected 111, got {code2}"

try:
    s2_throw = socket.socket()
    s2_throw.connect(('192.168.1.10', 22))
    assert False, "Should have raised ConnectionRefusedError"
except ConnectionRefusedError as e:
    print(f"  -> connect() correctly raised ConnectionRefusedError: {e}")

# 3. Filtered Port (10.0.0.1:80 - Silent Drop / Timeout)
print("\\n[Test 3] Target 10.0.0.1:80 (Filtered / Drop)")
s3 = socket.socket()
code3 = s3.connect_ex(('10.0.0.1', 80))
print(f"  -> connect_ex returned: {code3} (110=ETIMEDOUT)")
assert code3 == 110, f"Expected 110, got {code3}"

try:
    s3_throw = socket.socket()
    s3_throw.connect(('10.0.0.1', 80))
    assert False, "Should have raised TimeoutError"
except TimeoutError as e:
    print(f"  -> connect() correctly raised TimeoutError: {e}")

print("\\n[+] SUCCESS: All Phase 0 Acceptance Criteria verified synchronously!")
`,
  open: `import socket
s = socket.socket()
print("Connecting to 192.168.1.10:80...")
s.connect(('192.168.1.10', 80))
print("Handshake established!")
s.sendall(b"GET /status HTTP/1.1\\r\\n\\r\\n")
data = s.recv(512)
print("Response:", data.decode('utf-8', errors='ignore'))
s.close()
`,
  closed: `import socket
s = socket.socket()
print("Connecting to closed port 192.168.1.10:22...")
try:
    s.connect(('192.168.1.10', 22))
except ConnectionRefusedError as e:
    print("Caught expected ConnectionRefusedError:", e)
`,
  filtered: `import socket
s = socket.socket()
print("Connecting to filtered host 10.0.0.1:80...")
try:
    s.connect(('10.0.0.1', 80))
except TimeoutError as e:
    print("Caught expected TimeoutError:", e)
`,
  watchdog: `print("Simulating an infinite loop to test Main-Thread Watchdog...")
# Watchdog will terminate this worker in ~5 seconds and spawn a new one!
counter = 0
while True:
    counter += 1
`,
};

function getRequiredElement<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Required DOM element not found: #${id}`);
  }
  return el as T;
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

class AppController {
  private client: SimWorkerClient;
  private statusBadge: HTMLElement;
  private runBtn: HTMLButtonElement;
  private codeInput: HTMLTextAreaElement;
  private terminal: HTMLElement;
  private traceTableBody: HTMLElement;
  private packetCountBadge: HTMLElement;
  private totalPackets = 0;

  constructor() {
    this.statusBadge = getRequiredElement<HTMLElement>('status-badge');
    this.runBtn = getRequiredElement<HTMLButtonElement>('btn-run');
    this.codeInput = getRequiredElement<HTMLTextAreaElement>('code-input');
    this.terminal = getRequiredElement<HTMLElement>('terminal');
    this.traceTableBody = getRequiredElement<HTMLElement>('trace-body');
    this.packetCountBadge = getRequiredElement<HTMLElement>('packet-count');

    // Run button is disabled until worker is confirmed ready
    this.runBtn.disabled = true;

    this.client = new SimWorkerClient();
    this.initUI();
    this.bootstrapWorker();
  }

  private initUI(): void {
    this.codeInput.value = PRESETS['full'];

    document.querySelectorAll('[data-preset]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const presetKey = (e.currentTarget as HTMLElement).getAttribute('data-preset') || 'full';
        if (PRESETS[presetKey]) {
          this.codeInput.value = PRESETS[presetKey];
        }
      });
    });

    this.runBtn.addEventListener('click', () => this.handleRun());
    document.getElementById('btn-clear')?.addEventListener('click', () => {
      this.terminal.textContent = '';
      this.traceTableBody.innerHTML = '';
      this.totalPackets = 0;
      this.packetCountBadge.textContent = '0 packets';
    });
  }

  private async bootstrapWorker(): Promise<void> {
    this.statusBadge.className = 'badge loading';
    this.statusBadge.textContent = 'Pyodide: Loading WASM...';
    this.runBtn.disabled = true;
    this.log('Initializing Co-located Pyodide Worker sandbox...', 'info');

    try {
      await this.client.waitReady(30000);
      this.statusBadge.className = 'badge ready';
      this.statusBadge.textContent = 'Pyodide: Ready';
      this.runBtn.disabled = false;
      this.log('Pyodide Worker initialized successfully with Virtual Socket Shim injected.', 'success');
    } catch (err: unknown) {
      this.statusBadge.className = 'badge err';
      this.statusBadge.textContent = 'Pyodide: Error';
      this.runBtn.disabled = true; // Keep disabled on error
      const errMsg = err instanceof Error ? err.message : String(err);
      this.log(`Worker init failed: ${errMsg}`, 'err');
    }
  }

  private async handleRun(): Promise<void> {
    if (this.runBtn.disabled) return;
    const code = this.codeInput.value;
    this.runBtn.disabled = true;
    this.log(`--- Running Python Code (${code.split('\n').length} lines) ---`, 'info');

    try {
      const res = await this.client.runPython(code, 6000);
      if (res.stdout) {
        this.log(res.stdout);
      }
      if (res.stderr) {
        this.log(res.stderr, 'err');
      }
      if (res.error) {
        this.log(`Error: ${res.error}`, 'err');
      } else {
        this.log(`[Execution Completed in ${res.durationMs.toFixed(1)}ms]`, 'success');
      }

      if (res.newEvents && res.newEvents.length > 0) {
        this.appendTraceEvents(res.newEvents);
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.log(`Fatal execution error: ${errMsg}`, 'err');
    } finally {
      if (!this.statusBadge.className.includes('err')) {
        this.runBtn.disabled = false;
      }
    }
  }

  private log(text: string, style: 'normal' | 'info' | 'err' | 'success' = 'normal'): void {
    const span = document.createElement('div');
    if (style !== 'normal') span.className = style;
    span.textContent = text;
    this.terminal.appendChild(span);
    this.terminal.scrollTop = this.terminal.scrollHeight;
  }

  private appendTraceEvents(events: PacketTraceEntry[]): void {
    this.totalPackets += events.length;
    this.packetCountBadge.textContent = `${this.totalPackets} packets`;

    for (const evt of events) {
      const row = document.createElement('tr');
      const flagStr = evt.tcpFlags
        ? Object.entries(evt.tcpFlags)
            .filter(([_, v]) => v)
            .map(([k]) => k.toUpperCase())
            .join(' ')
        : '-';

      const tagClass =
        evt.status === 'DELIVERED'
          ? 'tag-delivered'
          : evt.status === 'REJECTED'
          ? 'tag-rejected'
          : 'tag-dropped';

      const srcPortStr = evt.sourcePort !== undefined ? `:${evt.sourcePort}` : '';
      const tgtPortStr = evt.targetPort !== undefined ? `:${evt.targetPort}` : '';

      row.innerHTML = `
        <td>${escapeHtml(evt.id)}</td>
        <td>Tick #${evt.tick}</td>
        <td>${escapeHtml(evt.sourceIp)}${srcPortStr}</td>
        <td>${escapeHtml(evt.targetIp)}${tgtPortStr}</td>
        <td>${escapeHtml(evt.protocol)} [${escapeHtml(flagStr)}]</td>
        <td class="${tagClass}">${escapeHtml(evt.status)}</td>
        <td>${escapeHtml(evt.reason || '-')}</td>
      `;
      this.traceTableBody.appendChild(row);
    }

    const wrapper = this.traceTableBody.parentElement?.parentElement;
    if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
  }
}

// Instantiate on page load with safe readyState check
function initApp(): void {
  try {
    new AppController();
  } catch (err: unknown) {
    console.error('[AppController] Startup error:', err);
  }
}

if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
