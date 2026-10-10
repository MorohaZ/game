import { NetworkSimulator } from '../core/NetworkSimulator';
import { createDefaultTopology } from '../core/default-topology';
import { VirtualSocketBridge } from '../bridge/VirtualSocketBridge';
import { PYTHON_SOCKET_SHIM_CODE } from '../bridge/python-socket-shim';
import { generateSecureToken } from '../core/types';
import {
  WorkerInMessage,
  WorkerOutMessage,
  isValidWorkerInMessage,
} from './worker-protocol';

declare function importScripts(...urls: string[]): void;

let sim: NetworkSimulator | null = null;
let bridge: VirtualSocketBridge | null = null;
let pyodide: any = null;
let isReady = false;
let initPromise: Promise<void> | null = null;
const workerSessionToken = generateSecureToken();

function postMsg(msg: WorkerOutMessage): void {
  self.postMessage(msg);
}

function enforceWorkerScopeLockdown(): void {
  const g = self as any;
  const dangerousAPIs = [
    'fetch',
    'XMLHttpRequest',
    'WebSocket',
    'indexedDB',
    'importScripts',
    'Worker',
    'SharedWorker',
    'BroadcastChannel',
    'openDatabase',
  ];

  for (const api of dangerousAPIs) {
    try {
      delete g[api];
      Object.defineProperty(g, api, {
        value: undefined,
        writable: false,
        configurable: false,
      });
    } catch {
      try {
        g[api] = undefined;
      } catch (err) {
        throw new Error(`CRITICAL SECURITY FAILURE: Failed to neutralize Worker API '${api}': ${err}`);
      }
    }

    // Strict fail-closed verification
    if (typeof g[api] !== 'undefined') {
      throw new Error(`CRITICAL SECURITY FAILURE: Worker API '${api}' remained accessible after lockdown.`);
    }
  }

  if (g.navigator && 'sendBeacon' in g.navigator) {
    try {
      delete g.navigator.sendBeacon;
      g.navigator.sendBeacon = undefined;
    } catch {
      // Non-fatal if navigator is read-only in some runtimes, but ensure undefined
    }
  }
}

async function loadPyodideRuntime(): Promise<any> {
  if (pyodide) return pyodide;

  let localIndexURL = '/pyodide/';
  if (typeof self !== 'undefined' && self.location && self.location.origin) {
    localIndexURL = `${self.location.origin}/pyodide/`;
  }

  // 1. Pre-loaded on global scope (if any)
  if (typeof (self as any).loadPyodide === 'function') {
    return await (self as any).loadPyodide({
      indexURL: localIndexURL,
    });
  }

  // 2. ESM dynamic import of local Pyodide bundle
  try {
    const pyodideUrl = `${localIndexURL}pyodide.mjs`;
    const pyodideModule = await import(/* @vite-ignore */ pyodideUrl);
    if (typeof pyodideModule.loadPyodide === 'function') {
      return await pyodideModule.loadPyodide({
        indexURL: localIndexURL,
      });
    }
  } catch {
    // Continue to package import
  }

  // 3. Bundled npm package fallback
  try {
    const pyodideModule = await import('pyodide');
    if (typeof pyodideModule.loadPyodide === 'function') {
      return await pyodideModule.loadPyodide({
        indexURL: localIndexURL,
      });
    }
  } catch (e: any) {
    throw new Error(`Failed to load local Pyodide WebAssembly runtime from '${localIndexURL}': ${e?.message || e}`);
  }

  throw new Error(`Unable to initialize Pyodide runtime from local assets.`);
}

async function doInitialize(): Promise<void> {
  try {
    sim = new NetworkSimulator();
    createDefaultTopology(sim);
    bridge = new VirtualSocketBridge(sim, 'attacker-pc', workerSessionToken);

    pyodide = await loadPyodideRuntime();

    // Expose synchronous restricted client facade to Pyodide Worker execution scope
    pyodide.globals.set('js_sim_core', bridge.getSocketFacade());

    // Inject Python Virtual Socket Shim
    pyodide.runPython(PYTHON_SOCKET_SHIM_CODE);

    // Remove direct bridge from Pyodide globals to prevent sandbox escape
    try {
      pyodide.globals.delete('js_sim_core');
    } catch {
      // If delete is not supported on globals map, fallback
    }

    // Fail-Closed Worker Scope Hardening: strip dangerous capabilities before user code runs
    enforceWorkerScopeLockdown();

    isReady = true;
    postMsg({
      type: 'READY',
      payload: { version: pyodide.version || '0.26.4' },
    });
  } catch (error: any) {
    isReady = false;
    postMsg({
      type: 'INIT_ERROR',
      payload: { error: error?.message || String(error) },
    });
    throw error;
  }
}

async function initialize(): Promise<void> {
  if (isReady && pyodide) {
    postMsg({
      type: 'READY',
      payload: { version: pyodide.version || '0.26.4' },
    });
    return;
  }

  if (initPromise) {
    return initPromise;
  }

  initPromise = doInitialize().finally(() => {
    initPromise = null;
  });

  return initPromise;
}

function handleRunCode(code: string, runId: string): void {
  if (!isReady || !pyodide || !sim) {
    postMsg({
      type: 'CODE_RESULT',
      payload: {
        runId,
        success: false,
        stdout: '',
        stderr: 'Pyodide runtime is not ready.',
        error: 'Pyodide not ready',
        durationMs: 0,
        newEvents: [],
      },
    });
    return;
  }

  let stdoutBuf = '';
  let stderrBuf = '';

  pyodide.setStdout({
    batched: (str: string) => {
      stdoutBuf += str + '\n';
    },
  });

  pyodide.setStderr({
    batched: (str: string) => {
      stderrBuf += str + '\n';
    },
  });

  const traceBeforeCount = sim.getTraceLog().length;
  const startTime = performance.now();

  try {
    pyodide.runPython(code);
    const duration = performance.now() - startTime;
    const newEvents = sim.getTraceLog().slice(traceBeforeCount);

    postMsg({
      type: 'CODE_RESULT',
      payload: {
        runId,
        success: true,
        stdout: stdoutBuf,
        stderr: stderrBuf,
        durationMs: duration,
        newEvents,
      },
    });
  } catch (err: any) {
    const duration = performance.now() - startTime;
    const newEvents = sim.getTraceLog().slice(traceBeforeCount);

    postMsg({
      type: 'CODE_RESULT',
      payload: {
        runId,
        success: false,
        stdout: stdoutBuf,
        stderr: stderrBuf,
        error: err?.message || String(err),
        durationMs: duration,
        newEvents,
      },
    });
  } finally {
    // State isolation cleanup: reset stdout/stderr callbacks
    pyodide.setStdout({});
    pyodide.setStderr({});
  }
}

self.onmessage = async (e: MessageEvent<unknown>) => {
  if (!isValidWorkerInMessage(e.data)) {
    console.warn('[sim-worker] Invalid WorkerInMessage received:', e.data);
    return;
  }

  const msg: WorkerInMessage = e.data;
  switch (msg.type) {
    case 'INIT':
      await initialize();
      break;

    case 'RUN_CODE':
      handleRunCode(msg.payload.code, msg.payload.runId);
      break;

    case 'GET_TRACE':
      postMsg({
        type: 'TRACE_RESULT',
        payload: { events: sim ? sim.getTraceLog() : [] },
      });
      break;

    case 'RESET_SIM':
      if (sim && bridge) {
        sim.reset();
        createDefaultTopology(sim);
        bridge.setNodeId('attacker-pc', workerSessionToken);
      }
      postMsg({ type: 'RESET_DONE' });
      break;

    case 'GET_SNAPSHOT':
      postMsg({
        type: 'SNAPSHOT_RESULT',
        payload: {
          snapshot: bridge
            ? bridge.getSnapshot()
            : { nodes: [], dnsTable: {}, currentTick: 0 },
        },
      });
      break;

    case 'RESTORE_SNAPSHOT':
      if (bridge && msg.payload.snapshot) {
        bridge.restoreSnapshot(msg.payload.snapshot);
      }
      postMsg({ type: 'RESTORE_DONE' });
      break;

    case 'SET_MISSION_CONFIG':
      if (bridge) {
        bridge.setDnsProtectionEnabled(msg.payload.dnsProtectionEnabled);
      }
      postMsg({ type: 'CONFIG_DONE' });
      break;

    case 'PING':
      postMsg({ type: 'PONG' });
      break;
  }
};

// Start initialization automatically upon worker load
initialize();
