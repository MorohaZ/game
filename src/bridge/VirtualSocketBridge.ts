import { NetworkSimulator, isValidIPv4 } from '../core/NetworkSimulator';
import { ConnectResult, BindResult, AcceptResult, Errno, PacketTraceEntry, RESOURCE_LIMITS, SimulatorSnapshot, generateSecureToken } from '../core/types';

/**
 * Restricted client socket facade exposed to Python runtime.
 * Contains only safe socket operations, with zero administrative or topology control surface.
 */
export interface VirtualSocketFacade {
  createSocket(family?: number, type?: number): number;
  setSocketTimeout(fd: number, timeout: number | null): void;
  connectSocket(fd: number, ip: string, port: number | string, timeout?: number | null): ConnectResult;
  sendSocket(fd: number, data: unknown): number;
  sendToSocket(fd: number, ip: string, port: number | string, data: unknown): number;
  recvSocket(fd: number, maxBytes: number): Uint8Array;
  recvFromSocket(fd: number, maxBytes: number): { data: Uint8Array; ip: string; port: number } | null;
  bindSocket(fd: number, ip: string, port: number | string): BindResult;
  listenSocket(fd: number, backlog?: number): void;
  acceptSocket(fd: number): AcceptResult;
  closeSocket(fd: number): void;
  getSockName(fd: number): { ip: string; port: number } | null;
  getPeerName(fd: number): { ip: string; port: number } | null;
  resolveDns(host: string): string;
}

/**
 * Direct Synchronous Bridge for Worker execution.
 * Backed by private ECMAScript fields so internal simulator and tokens cannot be accessed via reflection.
 */
export class VirtualSocketBridge implements VirtualSocketFacade {
  #sim: NetworkSimulator;
  #defaultNodeId: string;
  #sessionToken: string;
  #dnsProtectionEnabled: boolean = true;
  #dnsTable: Record<string, string>;
  #sessionFds: Set<number> = new Set<number>();

  private static readonly SYSTEM_DNS_RECORDS = new Set<string>([
    'localhost',
    'corp.local',
    'web.corp.local',
    'perimeter.sec',
  ]);

  private static readonly MAX_PAYLOAD_SIZE = RESOURCE_LIMITS.MAX_PAYLOAD_SIZE_BYTES; // 1MB limit

  constructor(sim: NetworkSimulator, defaultNodeId: string = 'attacker-pc', token?: string) {
    this.#sim = sim;
    this.#defaultNodeId = defaultNodeId;
    this.#sessionToken = token || generateSecureToken();
    this.#dnsTable = {
      'localhost': '127.0.0.1',
      'corp.local': '192.168.1.10',
      'web.corp.local': '192.168.1.10',
      'perimeter.sec': '10.0.0.1',
    };
  }

  /**
   * Generates a restricted facade containing ONLY safe socket operations.
   * Passed to untrusted Python runtime as `js_sim_core`.
   */
  public getSocketFacade(): VirtualSocketFacade {
    const facade = Object.create(null) as VirtualSocketFacade;
    Object.assign(facade, {
      createSocket: (family?: number, type?: number) => this.createSocket(family, type),
      setSocketTimeout: (fd: number, timeout: number | null) => this.setSocketTimeout(fd, timeout),
      connectSocket: (fd: number, ip: string, port: number | string, timeout?: number | null) =>
        this.connectSocket(fd, ip, port, timeout),
      sendSocket: (fd: number, data: unknown) => this.sendSocket(fd, data),
      sendToSocket: (fd: number, ip: string, port: number | string, data: unknown) =>
        this.sendToSocket(fd, ip, port, data),
      recvSocket: (fd: number, maxBytes: number) => this.recvSocket(fd, maxBytes),
      recvFromSocket: (fd: number, maxBytes: number) => this.recvFromSocket(fd, maxBytes),
      bindSocket: (fd: number, ip: string, port: number | string) => this.bindSocket(fd, ip, port),
      listenSocket: (fd: number, backlog?: number) => this.listenSocket(fd, backlog),
      acceptSocket: (fd: number) => this.acceptSocket(fd),
      closeSocket: (fd: number) => this.closeSocket(fd),
      getSockName: (fd: number) => this.getSockName(fd),
      getPeerName: (fd: number) => this.getPeerName(fd),
      resolveDns: (host: string) => this.resolveDns(host),
    });
    return Object.freeze(facade);
  }

  public getSessionToken(): string {
    return this.#sessionToken;
  }

  public setDnsProtectionEnabled(enabled: boolean): void {
    this.#dnsProtectionEnabled = Boolean(enabled);
  }

  public isDnsProtectionEnabled(): boolean {
    return this.#dnsProtectionEnabled;
  }

  public checkToken(token?: string): void {
    if (!token || token !== this.#sessionToken) {
      throw new Error(`Permission denied: Invalid security capability token '${token}'`);
    }
  }

  public setNodeId(nodeId: string, token?: string): void {
    this.checkToken(token);
    if (!this.#sim.getNode(nodeId)) {
      throw new Error(`Node '${nodeId}' not found in simulator`);
    }
    this.#defaultNodeId = nodeId;
  }

  public getNodeId(): string {
    return this.#defaultNodeId;
  }

  private verifySocketOwnership(fd: number): void {
    const s = this.#sim.getSocket(fd);
    if (!s) {
      throw new Error(`Bad file descriptor (fd=${fd})`);
    }
    if (s.ownerNodeId !== this.#defaultNodeId && !this.#sessionFds.has(fd)) {
      throw new Error(`Permission denied: Socket (fd=${fd}) does not belong to active node '${this.#defaultNodeId}'`);
    }
  }

  // --- Socket Lifecycle ---

  public createSocket(family: number = 2, type: number = 1): number {
    const fd = this.#sim.createSocket(this.#defaultNodeId, family, type);
    this.#sessionFds.add(fd);
    return fd;
  }

  public setSocketTimeout(fd: number, timeout: number | null): void {
    this.verifySocketOwnership(fd);
    this.#sim.setSocketTimeout(fd, timeout);
  }

  public connectSocket(
    fd: number,
    ip: string,
    port: number | string,
    timeout?: number | null
  ): ConnectResult {
    this.verifySocketOwnership(fd);

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      return {
        success: false,
        errno: Errno.EINVAL,
        message: `Invalid target port: ${port}`,
      };
    }

    let resolvedIp: string;
    try {
      resolvedIp = this.resolveDns(ip);
    } catch {
      return {
        success: false,
        errno: Errno.EHOSTUNREACH,
        message: `Name or service not known: ${ip}`,
      };
    }

    return this.#sim.connectSocket(fd, resolvedIp, parsedPort, timeout);
  }

  public sendSocket(fd: number, data: unknown): number {
    this.verifySocketOwnership(fd);

    let uint8: Uint8Array;

    if (data instanceof Uint8Array) {
      uint8 = data;
    } else if (data instanceof ArrayBuffer) {
      uint8 = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      uint8 = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else if (Array.isArray(data)) {
      uint8 = new Uint8Array(data);
    } else if (data && typeof (data as any).toJs === 'function') {
      const converted = (data as any).toJs();
      if (converted instanceof Uint8Array) {
        uint8 = converted;
      } else if (Array.isArray(converted)) {
        uint8 = new Uint8Array(converted);
      } else if (converted instanceof ArrayBuffer) {
        uint8 = new Uint8Array(converted);
      } else {
        uint8 = new Uint8Array(Array.from(converted || []));
      }
    } else if (typeof data === 'string') {
      uint8 = new TextEncoder().encode(data);
    } else if (data && typeof (data as any)[Symbol.iterator] === 'function') {
      uint8 = new Uint8Array(Array.from(data as Iterable<number>));
    } else {
      throw new Error(`Unsupported data format passed to sendSocket: ${typeof data}`);
    }

    if (uint8.length > VirtualSocketBridge.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size exceeds maximum allowed size (${VirtualSocketBridge.MAX_PAYLOAD_SIZE} bytes)`);
    }

    return this.#sim.sendSocket(fd, uint8);
  }

  public sendToSocket(fd: number, ip: string, port: number | string, data: unknown): number {
    this.verifySocketOwnership(fd);

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      throw new Error(`Invalid target port: ${port}`);
    }

    let resolvedIp: string;
    try {
      resolvedIp = this.resolveDns(ip);
    } catch {
      throw new Error(`Name or service not known: ${ip}`);
    }

    let uint8: Uint8Array;
    if (data instanceof Uint8Array) {
      uint8 = data;
    } else if (data instanceof ArrayBuffer) {
      uint8 = new Uint8Array(data);
    } else if (ArrayBuffer.isView(data)) {
      uint8 = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    } else if (Array.isArray(data)) {
      uint8 = new Uint8Array(data);
    } else if (data && typeof (data as any).toJs === 'function') {
      const converted = (data as any).toJs();
      if (converted instanceof Uint8Array) {
        uint8 = converted;
      } else if (Array.isArray(converted)) {
        uint8 = new Uint8Array(converted);
      } else if (converted instanceof ArrayBuffer) {
        uint8 = new Uint8Array(converted);
      } else {
        uint8 = new Uint8Array(Array.from(converted || []));
      }
    } else if (typeof data === 'string') {
      uint8 = new TextEncoder().encode(data);
    } else if (data && typeof (data as any)[Symbol.iterator] === 'function') {
      uint8 = new Uint8Array(Array.from(data as Iterable<number>));
    } else {
      throw new Error(`Unsupported data format passed to sendToSocket: ${typeof data}`);
    }

    if (uint8.length > VirtualSocketBridge.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size exceeds maximum allowed size (${VirtualSocketBridge.MAX_PAYLOAD_SIZE} bytes)`);
    }

    return this.#sim.sendToSocket(fd, resolvedIp, parsedPort, uint8);
  }

  public recvSocket(fd: number, maxBytes: number): Uint8Array {
    this.verifySocketOwnership(fd);
    const parsedMax = Number(maxBytes);
    if (isNaN(parsedMax) || parsedMax <= 0) {
      return new Uint8Array(0);
    }
    return this.#sim.recvSocket(fd, parsedMax);
  }

  public recvFromSocket(
    fd: number,
    maxBytes: number
  ): { data: Uint8Array; ip: string; port: number } | null {
    this.verifySocketOwnership(fd);
    const parsedMax = Number(maxBytes);
    if (isNaN(parsedMax) || parsedMax <= 0) {
      return null;
    }
    const res = this.#sim.recvFromSocket(fd, parsedMax);
    if (!res) return null;
    return {
      ...res,
      data: new Uint8Array(res.data),
    };
  }

  public bindSocket(fd: number, ip: string, port: number | string): BindResult {
    this.verifySocketOwnership(fd);

    let resolvedIp: string;
    if (!ip || ip.trim() === '') {
      resolvedIp = '0.0.0.0';
    } else {
      try {
        resolvedIp = this.resolveDns(ip);
      } catch {
        return {
          success: false,
          errno: Errno.EINVAL,
          message: `Cannot resolve bind host: ${ip}`,
        };
      }
    }

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 0 || parsedPort > 65535) {
      return {
        success: false,
        errno: Errno.EINVAL,
        message: `Invalid bind port: ${port}`,
      };
    }

    return this.#sim.bindSocket(fd, resolvedIp, parsedPort);
  }

  public listenSocket(fd: number, backlog: number = 5): void {
    this.verifySocketOwnership(fd);
    const parsedBacklog = Number(backlog);
    this.#sim.listenSocket(fd, isNaN(parsedBacklog) || parsedBacklog < 1 ? 5 : parsedBacklog);
  }

  public acceptSocket(fd: number): AcceptResult {
    this.verifySocketOwnership(fd);
    const res = this.#sim.acceptSocket(fd);
    if (res.clientFd) {
      this.#sessionFds.add(res.clientFd);
    }
    return res;
  }

  public closeSocket(fd: number): void {
    this.verifySocketOwnership(fd);
    this.#sessionFds.delete(fd);
    this.#sim.closeSocket(fd);
  }

  public getSockName(fd: number): { ip: string; port: number } | null {
    this.verifySocketOwnership(fd);
    const s = this.#sim.getSocket(fd);
    if (!s || s.closed) return null;
    if (s.status === 'INITIAL' && !s.boundIp && !s.boundPort) {
      return { ip: '0.0.0.0', port: 0 };
    }
    const ip = s.boundIp || '0.0.0.0';
    const port = s.boundPort ?? 0;
    return { ip, port };
  }

  public getPeerName(fd: number): { ip: string; port: number } | null {
    this.verifySocketOwnership(fd);
    const s = this.#sim.getSocket(fd);
    if (!s || s.closed || s.status !== 'ESTABLISHED') {
      return null;
    }
    if (s.connectedIp == null || s.connectedPort == null) {
      return null;
    }
    return { ip: s.connectedIp, port: s.connectedPort };
  }

  // --- DNS Helpers ---

  public resolveDns(host: string): string {
    if (!host || typeof host !== 'string') {
      throw new Error(`Invalid host: ${host}`);
    }
    const trimmed = host.trim();
    if (isValidIPv4(trimmed)) {
      return trimmed;
    }
    if (Object.prototype.hasOwnProperty.call(this.#dnsTable, trimmed)) {
      return this.#dnsTable[trimmed];
    }
    throw new Error(`getaddrinfo ENOTFOUND: Host '${trimmed}' could not be resolved`);
  }

  public addDnsRecord(host: string, ip: string, allowSystemOverride: boolean = false): void {
    if (!isValidIPv4(ip)) {
      throw new Error(`Invalid IPv4 address for DNS record: ${ip}`);
    }
    if (this.#dnsProtectionEnabled && !allowSystemOverride && VirtualSocketBridge.SYSTEM_DNS_RECORDS.has(host)) {
      throw new Error(`Permission denied: Cannot overwrite protected system DNS record '${host}'`);
    }
    this.#dnsTable[host] = ip;
  }

  // --- Snapshot & Restore ---

  public getSnapshot(): SimulatorSnapshot {
    return this.#sim.getSnapshot(this.#dnsTable, { dnsProtectionEnabled: this.#dnsProtectionEnabled });
  }

  public restoreSnapshot(snapshot: SimulatorSnapshot): void {
    this.#sim.restoreSnapshot(snapshot);
    if (snapshot.dnsTable) {
      this.#dnsTable = { ...snapshot.dnsTable };
    }
    if (snapshot.missionConfig && snapshot.missionConfig.dnsProtectionEnabled !== undefined) {
      this.#dnsProtectionEnabled = Boolean(snapshot.missionConfig.dnsProtectionEnabled);
    }
  }

  // --- Simulator Trace & Observability ---

  public getTraceLog(): PacketTraceEntry[] {
    return this.#sim.getTraceLog();
  }

  public clearTraceLog(): void {
    this.#sim.clearTraceLog();
  }

  public getTick(): number {
    return this.#sim.getTick();
  }
}
