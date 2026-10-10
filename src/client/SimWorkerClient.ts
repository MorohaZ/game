import {
  WorkerInMessage,
  WorkerOutMessage,
  isValidWorkerOutMessage,
} from '../worker/worker-protocol';
import { PacketTraceEntry, SimulatorSnapshot } from '../core/types';

export interface RunResult {
  runId: string;
  success: true | false;
  stdout: string;
  stderr: string;
  error?: string;
  durationMs: number;
  newEvents: PacketTraceEntry[];
}

export class SimWorkerClient {
  private worker: Worker | null = null;
  private isReady = false;
  private isSpawning = false;
  private lastKnownSnapshot: SimulatorSnapshot | null = null;
  private messageQueue: WorkerInMessage[] = [];
  private pendingInitResolvers: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];
  private pendingRuns = new Map<
    string,
    {
      resolve: (res: RunResult) => void;
      reject: (err: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private runSeq = 0;
  private static readonly MAX_CODE_LENGTH = 1024 * 1024; // 1MB code limit

  constructor() {
    this.spawnWorker();
  }

  private extractErrorMessage(err: unknown): string {
    if (err instanceof Error) {
      return err.message;
    }
    if (err && typeof err === 'object') {
      if ('message' in err && typeof (err as any).message === 'string') {
        return (err as any).message;
      }
      if ('error' in err && (err as any).error) {
        return String((err as any).error);
      }
    }
    return String(err || 'Unknown worker error');
  }

  private spawnWorker(): void {
    if (this.isSpawning) return;
    this.isSpawning = true;

    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      for (const [_, item] of this.pendingRuns.entries()) {
        clearTimeout(item.timer);
        item.reject(new Error('Worker respawned: previous worker was terminated'));
      }
      this.pendingRuns.clear();
    }
    this.isReady = false;

    try {
      this.worker = new Worker(
        new URL('../worker/sim-worker.ts', import.meta.url),
        { type: 'module' }
      );

      this.worker.onmessage = (e: MessageEvent<unknown>) => {
        if (!isValidWorkerOutMessage(e.data)) {
          console.warn('[SimWorkerClient] Invalid WorkerOutMessage received:', e.data);
          return;
        }
        this.handleWorkerMessage(e.data);
      };

      this.worker.onerror = (err: unknown) => {
        const errMsg = this.extractErrorMessage(err);
        console.error('[SimWorkerClient] Worker error:', errMsg);

        // Reject pending init resolvers
        for (const p of this.pendingInitResolvers) {
          clearTimeout(p.timer);
          p.reject(new Error(`Worker error: ${errMsg}`));
        }
        this.pendingInitResolvers = [];

        // Reject and clear pending runs immediately
        for (const [_, item] of this.pendingRuns.entries()) {
          clearTimeout(item.timer);
          item.reject(new Error(`Worker error: ${errMsg}`));
        }
        this.pendingRuns.clear();
      };

      // Always post INIT to ensure worker starts cleanly
      const initMsg: WorkerInMessage = { type: 'INIT' };
      this.worker.postMessage(initMsg);
    } finally {
      this.isSpawning = false;
    }
  }

  private handleWorkerMessage(msg: WorkerOutMessage): void {
    switch (msg.type) {
      case 'READY':
        this.isReady = true;
        // Restore previous snapshot if worker respawned after watchdog or crash
        if (this.lastKnownSnapshot && this.worker) {
          this.worker.postMessage({
            type: 'RESTORE_SNAPSHOT',
            payload: { snapshot: this.lastKnownSnapshot },
          });
        }
        for (const p of this.pendingInitResolvers) {
          clearTimeout(p.timer);
          p.resolve();
        }
        this.pendingInitResolvers = [];
        this.flushMessageQueue();
        break;

      case 'INIT_ERROR':
        this.isReady = false;
        const initErr = new Error(`Worker initialization failed: ${msg.payload.error}`);
        for (const p of this.pendingInitResolvers) {
          clearTimeout(p.timer);
          p.reject(initErr);
        }
        this.pendingInitResolvers = [];
        break;

      case 'SNAPSHOT_RESULT':
        this.lastKnownSnapshot = msg.payload.snapshot;
        break;

      case 'CODE_RESULT': {
        const item = this.pendingRuns.get(msg.payload.runId);
        if (item) {
          clearTimeout(item.timer);
          this.pendingRuns.delete(msg.payload.runId);
          item.resolve(msg.payload);
        }
        // Keep simulator snapshot updated after script execution
        this.postWorkerMessage({ type: 'GET_SNAPSHOT' });
        break;
      }

      default:
        break;
    }
  }

  public postWorkerMessage(msg: WorkerInMessage): void {
    if (!this.worker || !this.isReady) {
      this.messageQueue.push(msg);
      return;
    }
    this.worker.postMessage(msg);
  }

  private flushMessageQueue(): void {
    if (!this.worker || !this.isReady) return;
    while (this.messageQueue.length > 0) {
      const msg = this.messageQueue.shift();
      if (msg) {
        this.worker.postMessage(msg);
      }
    }
  }

  public getLastKnownSnapshot(): SimulatorSnapshot | null {
    return this.lastKnownSnapshot;
  }

  public setLastKnownSnapshot(snapshot: SimulatorSnapshot): void {
    this.lastKnownSnapshot = snapshot;
    if (this.worker && this.isReady) {
      this.worker.postMessage({
        type: 'RESTORE_SNAPSHOT',
        payload: { snapshot },
      });
    }
  }

  public async waitReady(timeoutMs: number = 20000): Promise<void> {
    if (!this.worker) {
      this.spawnWorker();
    }
    if (this.isReady) return;

    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timeout waiting for Pyodide worker initialization (${timeoutMs}ms)`));
      }, timeoutMs);

      this.pendingInitResolvers.push({
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
        reject: (err: Error) => {
          clearTimeout(timer);
          reject(err);
        },
        timer,
      });
    });
  }

  public async runPython(code: string, timeoutMs: number = 8000): Promise<RunResult> {
    if (!code || typeof code !== 'string') {
      throw new Error('Code must be a non-empty string');
    }

    if (code.length > SimWorkerClient.MAX_CODE_LENGTH) {
      throw new Error(`Code length exceeds maximum allowed limit (${SimWorkerClient.MAX_CODE_LENGTH} bytes)`);
    }

    if (!this.worker) {
      this.spawnWorker();
    }
    await this.waitReady();

    if (!this.worker) {
      throw new Error('Worker is not running or has been terminated');
    }
    const currentWorker = this.worker;

    const runId = `run-${++this.runSeq}-${Date.now()}`;

    return new Promise<RunResult>((resolve, reject) => {
      // Main Thread Watchdog Timer
      const watchdogTimer = setTimeout(() => {
        this.pendingRuns.delete(runId);
        console.warn(`[Watchdog] Execution timed out (${timeoutMs}ms). Terminating hanging worker.`);

        // Force terminate stuck worker and respawn cleanly
        this.spawnWorker();

        resolve({
          runId,
          success: false,
          stdout: '',
          stderr: `Execution timed out after ${timeoutMs}ms. Worker terminated by Watchdog.`,
          error: 'WatchdogTimeoutError: Worker terminated due to execution timeout.',
          durationMs: timeoutMs,
          newEvents: [],
        });
      }, timeoutMs);

      this.pendingRuns.set(runId, {
        resolve,
        reject,
        timer: watchdogTimer,
      });

      const msg: WorkerInMessage = {
        type: 'RUN_CODE',
        payload: { code, runId },
      };

      try {
        currentWorker.postMessage(msg);
      } catch (err: unknown) {
        clearTimeout(watchdogTimer);
        this.pendingRuns.delete(runId);
        reject(new Error(`Failed to post message to worker: ${this.extractErrorMessage(err)}`));
      }
    });
  }

  public terminate(): void {
    for (const [_, item] of this.pendingRuns.entries()) {
      clearTimeout(item.timer);
      item.reject(new Error('SimWorkerClient terminated'));
    }
    this.pendingRuns.clear();

    for (const p of this.pendingInitResolvers) {
      clearTimeout(p.timer);
      p.reject(new Error('SimWorkerClient terminated'));
    }
    this.pendingInitResolvers = [];

    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.isReady = false;
  }
}
