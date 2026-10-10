import { PacketTraceEntry, SimulatorSnapshot } from '../core/types';

export type WorkerInMessage =
  | { type: 'INIT' }
  | { type: 'RUN_CODE'; payload: { code: string; runId: string } }
  | { type: 'GET_TRACE' }
  | { type: 'RESET_SIM' }
  | { type: 'GET_SNAPSHOT' }
  | { type: 'RESTORE_SNAPSHOT'; payload: { snapshot: SimulatorSnapshot } }
  | { type: 'SET_MISSION_CONFIG'; payload: { dnsProtectionEnabled: boolean } }
  | { type: 'PING' };

export interface CodeResultSuccess {
  runId: string;
  success: true;
  stdout: string;
  stderr: string;
  durationMs: number;
  newEvents: PacketTraceEntry[];
}

export interface CodeResultFailure {
  runId: string;
  success: false;
  stdout: string;
  stderr: string;
  error: string;
  durationMs: number;
  newEvents: PacketTraceEntry[];
}

export type CodeResultPayload = CodeResultSuccess | CodeResultFailure;

export type WorkerOutMessage =
  | { type: 'READY'; payload: { version: string } }
  | { type: 'INIT_ERROR'; payload: { error: string } }
  | { type: 'CODE_RESULT'; payload: CodeResultPayload }
  | { type: 'TRACE_RESULT'; payload: { events: PacketTraceEntry[] } }
  | { type: 'SNAPSHOT_RESULT'; payload: { snapshot: SimulatorSnapshot } }
  | { type: 'RESTORE_DONE' }
  | { type: 'CONFIG_DONE' }
  | { type: 'RESET_DONE' }
  | { type: 'PONG' };

export function isValidWorkerInMessage(msg: unknown): msg is WorkerInMessage {
  if (!msg || typeof msg !== 'object') return false;
  const m = msg as Record<string, unknown>;
  if (typeof m.type !== 'string') return false;

  switch (m.type) {
    case 'INIT':
    case 'GET_TRACE':
    case 'RESET_SIM':
    case 'GET_SNAPSHOT':
    case 'PING':
      return true;
    case 'RUN_CODE':
      if (!m.payload || typeof m.payload !== 'object') return false;
      const p = m.payload as Record<string, unknown>;
      return typeof p.code === 'string' && typeof p.runId === 'string';
    case 'RESTORE_SNAPSHOT':
      if (!m.payload || typeof m.payload !== 'object') return false;
      return Boolean((m.payload as any).snapshot && typeof (m.payload as any).snapshot === 'object');
    case 'SET_MISSION_CONFIG':
      if (!m.payload || typeof m.payload !== 'object') return false;
      return typeof (m.payload as any).dnsProtectionEnabled === 'boolean';
    default:
      return false;
  }
}

export function isValidWorkerOutMessage(msg: unknown): msg is WorkerOutMessage {
  if (!msg || typeof msg !== 'object') return false;
  const m = msg as Record<string, unknown>;
  if (typeof m.type !== 'string') return false;

  switch (m.type) {
    case 'READY':
      return Boolean(m.payload && typeof (m.payload as any).version === 'string');
    case 'INIT_ERROR':
      return Boolean(m.payload && typeof (m.payload as any).error === 'string');
    case 'CODE_RESULT':
      if (!m.payload || typeof m.payload !== 'object') return false;
      const cp = m.payload as Record<string, unknown>;
      return (
        typeof cp.runId === 'string' &&
        typeof cp.success === 'boolean' &&
        typeof cp.stdout === 'string' &&
        typeof cp.stderr === 'string' &&
        typeof cp.durationMs === 'number' &&
        Array.isArray(cp.newEvents)
      );
    case 'TRACE_RESULT':
      return Boolean(m.payload && Array.isArray((m.payload as any).events));
    case 'SNAPSHOT_RESULT':
      return Boolean(m.payload && typeof (m.payload as any).snapshot === 'object');
    case 'RESTORE_DONE':
    case 'CONFIG_DONE':
    case 'RESET_DONE':
    case 'PONG':
      return true;
    default:
      return false;
  }
}
