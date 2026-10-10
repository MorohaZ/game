import {
  NetworkNode,
  PortConfig,
  PacketTraceEntry,
  VirtualSocketState,
  ConnectResult,
  BindResult,
  AcceptResult,
  Errno,
  ProtocolType,
  TcpFlags,
  PacketDeliveryStatus,
  FirewallRule,
  FirewallAction,
  ConntrackEntry,
  ConnectionState,
  RESOURCE_LIMITS,
  SimulatorSnapshot,
} from './types';

export function isValidIPv4(ip: string): boolean {
  if (typeof ip !== 'string') return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const n = parseInt(part, 10);
    if (n < 0 || n > 255) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

export function ipToUint(ip: string): number | null {
  if (!isValidIPv4(ip)) return null;
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function isInSubnet(ip: string, cidr: string): boolean {
  if (!cidr || typeof cidr !== 'string') return false;
  if (!cidr.includes('/')) {
    return isValidIPv4(ip) && isValidIPv4(cidr) && ip === cidr;
  }
  const parts = cidr.split('/');
  if (parts.length !== 2) return false;
  const [subIp, maskBitsStr] = parts;
  if (!/^\d+$/.test(maskBitsStr)) return false;
  const maskBits = parseInt(maskBitsStr, 10);
  if (maskBits < 0 || maskBits > 32) return false;

  const ipNum = ipToUint(ip);
  const subNum = ipToUint(subIp);
  if (ipNum === null || subNum === null) return false;

  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipNum & mask) === (subNum & mask);
}

export class NetworkSimulator {
  private nodes: Map<string, NetworkNode> = new Map();
  private ipToNodeMap: Map<string, string> = new Map();
  private sockets: Map<number, VirtualSocketState> = new Map();
  private packetEventLog: PacketTraceEntry[] = [];
  private conntrack: Map<string, ConntrackEntry> = new Map();
  private currentTick: number = 0;
  private nextFd: number = 100;
  private packetCounter: number = 0;
  private ephemeralPortBase: number = 49152;

  constructor() {
    this.reset();
  }

  public reset(): void {
    this.nodes.clear();
    this.ipToNodeMap.clear();
    this.sockets.clear();
    this.conntrack.clear();
    this.packetEventLog = [];
    this.currentTick = 0;
    this.nextFd = 100;
    this.packetCounter = 0;
  }

  // --- Stateful Connection Tracking ---

  private makeConntrackKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number, proto: ProtocolType): string {
    return `${srcIp}:${srcPort}->${dstIp}:${dstPort}/${proto}`;
  }

  public isConntrackEstablished(srcIp: string, srcPort: number, dstIp: string, dstPort: number, proto: ProtocolType): boolean {
    const forwardKey = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const reverseKey = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    const entry = this.conntrack.get(forwardKey) || this.conntrack.get(reverseKey);
    return Boolean(entry && entry.state === 'ESTABLISHED');
  }

  public setConntrack(srcIp: string, srcPort: number, dstIp: string, dstPort: number, proto: ProtocolType, state: ConnectionState = 'ESTABLISHED'): void {
    const forwardKey = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const reverseKey = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    const entry: ConntrackEntry = {
      id: `ct-${Date.now()}-${srcPort}-${dstPort}`,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      protocol: proto,
      state,
      createdAtTick: this.currentTick,
      lastSeenTick: this.currentTick,
    };
    this.conntrack.set(forwardKey, entry);
    this.conntrack.set(reverseKey, entry);
  }

  public removeConntrack(srcIp: string, srcPort: number, dstIp: string, dstPort: number, proto: ProtocolType): void {
    const forwardKey = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const reverseKey = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    this.conntrack.delete(forwardKey);
    this.conntrack.delete(reverseKey);
  }

  // --- ACL & Interface Evaluation ---

  public evaluateAcl(
    rules: FirewallRule[] | undefined,
    srcIp: string,
    srcPort: number | undefined,
    dstIp: string,
    dstPort: number | undefined,
    protocol: ProtocolType,
    implicitDeny: boolean = false
  ): { action: FirewallAction; ruleId?: string } {
    if (!rules || rules.length === 0) {
      return implicitDeny ? { action: 'DENY_DROP', ruleId: 'implicit-deny' } : { action: 'PERMIT' };
    }

    for (const rule of rules) {
      if (rule.sourceIp && rule.sourceIp !== 'any' && !isInSubnet(srcIp, rule.sourceIp)) continue;
      if (rule.targetIp && rule.targetIp !== 'any' && rule.targetIp !== dstIp && !isInSubnet(dstIp, rule.targetIp)) continue;
      if (rule.targetPort && rule.targetPort !== dstPort) continue;
      if (rule.protocol && rule.protocol !== 'ANY' && rule.protocol !== protocol) continue;

      return { action: rule.action, ruleId: rule.id };
    }

    if (implicitDeny) {
      return { action: 'DENY_DROP', ruleId: 'implicit-deny' };
    }

    return { action: 'PERMIT' };
  }

  public getOutboundAcl(
    node: NetworkNode,
    srcIp: string,
    dstIp: string
  ): { rules: FirewallRule[]; implicitDeny: boolean } {
    if (node.interfaces && Object.keys(node.interfaces).length > 0) {
      const ifaces = Object.values(node.interfaces);
      const matched = ifaces.find((i) => i.ip === srcIp || isInSubnet(dstIp, i.subnet)) || ifaces[0];
      if (matched) {
        return {
          rules: matched.aclsOut || [],
          implicitDeny: matched.implicitDeny !== undefined ? Boolean(matched.implicitDeny) : Boolean(node.implicitDeny),
        };
      }
    }
    return {
      rules: node.firewallRules || [],
      implicitDeny: Boolean(node.implicitDeny),
    };
  }

  public getInboundAcl(
    node: NetworkNode,
    dstIp: string,
    srcIp: string
  ): { rules: FirewallRule[]; implicitDeny: boolean } {
    if (node.interfaces && Object.keys(node.interfaces).length > 0) {
      const ifaces = Object.values(node.interfaces);
      const matched = ifaces.find((i) => i.ip === dstIp || isInSubnet(srcIp, i.subnet)) || ifaces[0];
      if (matched) {
        return {
          rules: matched.aclsIn || [],
          implicitDeny: matched.implicitDeny !== undefined ? Boolean(matched.implicitDeny) : Boolean(node.implicitDeny),
        };
      }
    }
    return {
      rules: node.firewallRules || [],
      implicitDeny: Boolean(node.implicitDeny),
    };
  }

  // --- Resource Buffer Tracking ---

  public getSocketBufferBytes(fd: number): number {
    const s = this.sockets.get(fd);
    if (!s) return 0;
    let total = 0;
    for (const chunk of s.recvBuffer) total += chunk.length;
    for (const chunk of s.sendBuffer) total += chunk.length;
    return total;
  }

  public getNodeBufferBytes(nodeId: string): number {
    let total = 0;
    for (const s of this.sockets.values()) {
      if (!s.closed && s.ownerNodeId === nodeId) {
        total += this.getSocketBufferBytes(s.fd);
      }
    }
    return total;
  }

  // --- Snapshot & Restore ---

  public getSnapshot(dnsTable?: Record<string, string>, missionConfig?: any): SimulatorSnapshot {
    const serializedNodes: NetworkNode[] = [];
    for (const node of this.nodes.values()) {
      serializedNodes.push({
        ...node,
        ports: { ...node.ports },
        firewallRules: node.firewallRules ? [...node.firewallRules] : undefined,
        interfaces: node.interfaces ? JSON.parse(JSON.stringify(node.interfaces)) : undefined,
      });
    }
    return {
      nodes: serializedNodes,
      dnsTable: dnsTable ? { ...dnsTable } : {},
      currentTick: this.currentTick,
      missionConfig: missionConfig ? { ...missionConfig } : undefined,
    };
  }

  public restoreSnapshot(snapshot: SimulatorSnapshot): void {
    this.nodes.clear();
    this.ipToNodeMap.clear();
    this.sockets.clear();
    this.conntrack.clear();
    this.packetEventLog = [];
    this.currentTick = snapshot.currentTick || 0;
    this.packetCounter = 0;

    if (snapshot.nodes) {
      for (const n of snapshot.nodes) {
        this.addNode(n);
      }
    }
  }

  public getTick(): number {
    return this.currentTick;
  }

  public tick(count: number = 1): void {
    if (count > 0) {
      this.currentTick += count;
    }
  }

  public addNode(node: NetworkNode): void {
    if (this.nodes.has(node.id)) {
      console.warn(`[NetworkSimulator] Overwriting existing node ID: ${node.id}`);
    }
    this.nodes.set(node.id, {
      ...node,
      ports: { ...node.ports },
      firewallRules: node.firewallRules ? [...node.firewallRules] : [],
      interfaces: node.interfaces ? JSON.parse(JSON.stringify(node.interfaces)) : undefined,
    });
    this.ipToNodeMap.set(node.ip, node.id);
    if (node.interfaces) {
      for (const iface of Object.values(node.interfaces)) {
        if (iface.ip) {
          this.ipToNodeMap.set(iface.ip, node.id);
        }
      }
    }
  }

  public getNode(nodeId: string): NetworkNode | undefined {
    return this.nodes.get(nodeId);
  }

  public getNodeByIp(ip: string): NetworkNode | undefined {
    const id = this.ipToNodeMap.get(ip);
    if (!id) return undefined;
    return this.nodes.get(id);
  }

  public getTraceLog(): PacketTraceEntry[] {
    return this.packetEventLog.map((p) => ({
      ...p,
      tcpFlags: p.tcpFlags ? { ...p.tcpFlags } : undefined,
    }));
  }

  public clearTraceLog(): void {
    this.packetEventLog = [];
  }

  public recordPacket(
    sourceNodeId: string,
    sourceIp: string,
    sourcePort?: number,
    targetNodeId?: string,
    targetIp: string = '0.0.0.0',
    targetPort?: number,
    protocol: ProtocolType = 'TCP',
    flags?: TcpFlags,
    status: PacketDeliveryStatus = 'DELIVERED',
    reason?: string,
    payloadSize: number = 0
  ): PacketTraceEntry {
    this.currentTick += 1;
    this.packetCounter += 1;

    const entry: PacketTraceEntry = {
      id: `pkt-${this.packetCounter.toString().padStart(4, '0')}`,
      tick: this.currentTick,
      timestamp: Date.now(),
      sourceNodeId,
      sourceIp,
      sourcePort,
      targetNodeId,
      targetIp,
      targetPort,
      protocol,
      tcpFlags: flags,
      status,
      reason,
      payloadSize,
    };

    this.packetEventLog.push(entry);
    return entry;
  }

  // ==========================================
  // Socket Management (Direct Synchronous Core)
  // ==========================================

  public createSocket(nodeId: string, family: number = 2, type: number = 1): number {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error(`Node not found: ${nodeId}`);
    }

    let activeSocketCount = 0;
    for (const s of this.sockets.values()) {
      if (!s.closed && s.ownerNodeId === nodeId) {
        activeSocketCount++;
      }
    }
    if (activeSocketCount >= RESOURCE_LIMITS.MAX_SOCKETS_PER_NODE) {
      throw new Error(`Resource limit exceeded: Maximum ${RESOURCE_LIMITS.MAX_SOCKETS_PER_NODE} sockets per node (EMFILE)`);
    }

    const fd = ++this.nextFd;
    const socket: VirtualSocketState = {
      fd,
      ownerNodeId: nodeId,
      family,
      type,
      timeout: null,
      status: 'INITIAL',
      closed: false,
      sendBuffer: [],
      recvBuffer: [],
    };

    this.sockets.set(fd, socket);
    return fd;
  }

  public setSocketTimeout(fd: number, timeout: number | null): void {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) return;
    socket.timeout = timeout;
  }

  public getSocket(fd: number): VirtualSocketState | undefined {
    return this.sockets.get(fd);
  }

  public connectSocket(
    fd: number,
    targetIp: string,
    targetPort: number,
    timeout?: number | null
  ): ConnectResult {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) {
      return { success: false, errno: Errno.EBADF, message: 'Bad file descriptor' };
    }

    if (socket.status === 'ESTABLISHED') {
      return { success: false, errno: Errno.EISCONN, message: 'Transport endpoint is already connected' };
    }

    const sourceNode = this.nodes.get(socket.ownerNodeId);
    if (!sourceNode) {
      return { success: false, errno: Errno.EBADF, message: 'Source node vanished' };
    }

    if (!isValidIPv4(targetIp)) {
      return { success: false, errno: Errno.EINVAL, message: 'Invalid target IP address' };
    }

    if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      return { success: false, errno: Errno.EINVAL, message: 'Invalid target port' };
    }

    const clientPort = socket.boundPort || (this.ephemeralPortBase + (fd % 10000));
    const candidateBoundIp = (socket.boundIp && socket.boundIp !== '0.0.0.0') ? socket.boundIp : sourceNode.ip;

    if (timeout !== undefined) {
      socket.timeout = timeout;
    }

    // 1. Check Firewall Rules on Source Node (Outbound) - Stateful Inspection & Interface ACLs
    if (!this.isConntrackEstablished(candidateBoundIp, clientPort, targetIp, targetPort, 'TCP')) {
      const outAcl = this.getOutboundAcl(sourceNode, candidateBoundIp, targetIp);
      const outDecision = this.evaluateAcl(
        outAcl.rules,
        candidateBoundIp,
        clientPort,
        targetIp,
        targetPort,
        'TCP',
        outAcl.implicitDeny
      );

      if (outDecision.action === 'DENY_DROP') {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          undefined,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DROPPED',
          `Outbound packet dropped by firewall rule [${outDecision.ruleId || 'implicit-deny'}]`
        );
        this.tick(5);
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }

      if (outDecision.action === 'DENY_RST') {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          undefined,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DELIVERED'
        );
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          undefined,
          targetIp,
          targetPort,
          'TCP',
          { rst: true, ack: true },
          'REJECTED',
          `Outbound connection rejected by firewall rule [${outDecision.ruleId || 'implicit-deny'}]`
        );
        return {
          success: false,
          errno: Errno.ECONNREFUSED,
          message: 'Connection refused',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }
    }

    // 2. Resolve Target Node & Routing
    const targetNode = this.getNodeByIp(targetIp);
    if (!targetNode) {
      const inSubnet = sourceNode.subnet ? isInSubnet(targetIp, sourceNode.subnet) : false;
      const hasValidGateway = Boolean(
        sourceNode.defaultGateway && this.getNodeByIp(sourceNode.defaultGateway)
      );

      if (!inSubnet && !hasValidGateway) {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          undefined,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'REJECTED',
          'No route to destination host'
        );
        return {
          success: false,
          errno: Errno.EHOSTUNREACH,
          message: 'No route to host',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }

      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        undefined,
        targetIp,
        targetPort,
        'TCP',
        { syn: true },
        'DROPPED',
        'Target IP not responding (Timeout)'
      );
      this.tick(5);
      return {
        success: false,
        errno: Errno.ETIMEDOUT,
        message: 'Connection timed out',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: targetPort,
      };
    }

    // 3. Check Target Node Inbound Firewall Rules - Stateful Inspection & Interface ACLs
    if (!this.isConntrackEstablished(candidateBoundIp, clientPort, targetIp, targetPort, 'TCP')) {
      const inAcl = this.getInboundAcl(targetNode, targetIp, candidateBoundIp);
      const inDecision = this.evaluateAcl(
        inAcl.rules,
        candidateBoundIp,
        clientPort,
        targetIp,
        targetPort,
        'TCP',
        inAcl.implicitDeny
      );

      if (inDecision.action === 'DENY_DROP') {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          targetNode.id,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DROPPED',
          `Inbound packet dropped by firewall rule [${inDecision.ruleId || 'implicit-deny'}]`
        );
        this.tick(5);
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }

      if (inDecision.action === 'DENY_RST') {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          targetNode.id,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DELIVERED'
        );
        this.recordPacket(
          targetNode.id,
          targetIp,
          targetPort,
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          'TCP',
          { rst: true, ack: true },
          'REJECTED',
          `Connection rejected by firewall rule [${inDecision.ruleId || 'implicit-deny'}]`
        );
        return {
          success: false,
          errno: Errno.ECONNREFUSED,
          message: 'Connection refused',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }
    }

    // 3b. Check for Listening Sockets on Target Node
    let listeningSocket: VirtualSocketState | undefined;
    for (const [_, sock] of this.sockets) {
      if (
        !sock.closed &&
        sock.ownerNodeId === targetNode.id &&
        sock.status === 'LISTENING' &&
        sock.boundPort === targetPort &&
        (sock.boundIp === targetIp || sock.boundIp === '0.0.0.0' || targetIp === '127.0.0.1' || targetIp === targetNode.ip)
      ) {
        listeningSocket = sock;
        break;
      }
    }

    if (listeningSocket) {
      const maxBacklog = listeningSocket.backlog || 5;
      if (listeningSocket.acceptQueue && listeningSocket.acceptQueue.length >= maxBacklog) {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          targetNode.id,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DROPPED',
          'TCP SYN dropped (Backlog queue full)'
        );
        this.tick(5);
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }

      let targetNodeSocketCount = 0;
      for (const s of this.sockets.values()) {
        if (!s.closed && s.ownerNodeId === targetNode.id) {
          targetNodeSocketCount++;
        }
      }
      if (targetNodeSocketCount >= RESOURCE_LIMITS.MAX_SOCKETS_PER_NODE) {
        this.recordPacket(
          sourceNode.id,
          candidateBoundIp,
          clientPort,
          targetNode.id,
          targetIp,
          targetPort,
          'TCP',
          { syn: true },
          'DROPPED',
          'TCP SYN dropped (Target node socket quota exceeded)'
        );
        this.tick(5);
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: targetPort,
        };
      }

      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { syn: true },
        'DELIVERED',
        `TCP SYN sent to ${targetIp}:${targetPort}`
      );
      this.recordPacket(
        targetNode.id,
        targetIp,
        targetPort,
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        'TCP',
        { syn: true, ack: true },
        'DELIVERED',
        `TCP SYN-ACK received from ${targetIp}:${targetPort}`
      );
      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { ack: true },
        'DELIVERED',
        `TCP ACK sent to ${targetIp}:${targetPort} (Handshake Established)`
      );

      socket.boundIp = candidateBoundIp;
      socket.boundPort = clientPort;
      socket.connectedIp = targetIp;
      socket.connectedPort = targetPort;
      socket.status = 'ESTABLISHED';
      this.setConntrack(candidateBoundIp, clientPort, targetIp, targetPort, 'TCP', 'ESTABLISHED');

      const serverClientFd = ++this.nextFd;
      const serverClientSocket: VirtualSocketState = {
        fd: serverClientFd,
        ownerNodeId: targetNode.id,
        family: socket.family,
        type: socket.type,
        boundIp: targetIp,
        boundPort: targetPort,
        connectedIp: candidateBoundIp,
        connectedPort: clientPort,
        timeout: null,
        status: 'ESTABLISHED',
        closed: false,
        sendBuffer: [],
        recvBuffer: [],
        connectedFd: socket.fd,
      };
      socket.connectedFd = serverClientFd;
      this.sockets.set(serverClientFd, serverClientSocket);

      if (!listeningSocket.acceptQueue) {
        listeningSocket.acceptQueue = [];
      }
      listeningSocket.acceptQueue.push({
        clientFd: serverClientFd,
        clientIp: candidateBoundIp,
        clientPort: clientPort,
      });

      return {
        success: true,
        errno: Errno.SUCCESS,
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: targetPort,
      };
    }

    // 4. Inspect Target Port Configuration
    const portConfig = targetNode.ports[targetPort];


    if (!portConfig || portConfig.state === 'CLOSED') {
      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { syn: true },
        'DELIVERED',
        `TCP SYN sent to ${targetIp}:${targetPort}`
      );
      this.recordPacket(
        targetNode.id,
        targetIp,
        targetPort,
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        'TCP',
        { rst: true, ack: true },
        'REJECTED',
        `TCP RST received from ${targetIp}:${targetPort} (Port Closed)`
      );
      socket.status = 'CLOSED';
      return {
        success: false,
        errno: Errno.ECONNREFUSED,
        message: 'Connection refused',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: targetPort,
      };
    }

    if (portConfig.state === 'FILTERED') {
      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { syn: true },
        'DROPPED',
        `TCP SYN dropped (Port Filtered / No response)`
      );
      this.tick(5);
      return {
        success: false,
        errno: Errno.ETIMEDOUT,
        message: 'Connection timed out',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: targetPort,
      };
    }

    if (portConfig.state === 'OPEN') {
      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { syn: true },
        'DELIVERED',
        `TCP SYN sent to ${targetIp}:${targetPort}`
      );
      this.recordPacket(
        targetNode.id,
        targetIp,
        targetPort,
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        'TCP',
        { syn: true, ack: true },
        'DELIVERED',
        `TCP SYN-ACK received from ${targetIp}:${targetPort}`
      );
      this.recordPacket(
        sourceNode.id,
        candidateBoundIp,
        clientPort,
        targetNode.id,
        targetIp,
        targetPort,
        'TCP',
        { ack: true },
        'DELIVERED',
        `TCP ACK sent to ${targetIp}:${targetPort} (Handshake Established)`
      );

      socket.boundIp = candidateBoundIp;
      socket.boundPort = clientPort;
      socket.connectedIp = targetIp;
      socket.connectedPort = targetPort;
      socket.status = 'ESTABLISHED';
      this.setConntrack(candidateBoundIp, clientPort, targetIp, targetPort, 'TCP', 'ESTABLISHED');

      if (portConfig.banner && portConfig.service !== 'http') {
        const bannerBytes = new TextEncoder().encode(portConfig.banner + '\r\n');
        socket.recvBuffer.push(bannerBytes);
      }

      return {
        success: true,
        errno: Errno.SUCCESS,
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: targetPort,
      };
    }

    return {
      success: false,
      errno: Errno.ECONNREFUSED,
      message: 'Unknown port state',
      boundIp: candidateBoundIp,
      boundPort: clientPort,
      connectedIp: targetIp,
      connectedPort: targetPort,
    };
  }

  public sendSocket(fd: number, data: Uint8Array): number {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed || socket.status !== 'ESTABLISHED') {
      throw new Error(`Socket not connected (fd=${fd})`);
    }

    if (data.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE_BYTES) {
      throw new Error(`Payload size exceeds maximum allowed limit (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE_BYTES} bytes)`);
    }

    const sourceNode = this.nodes.get(socket.ownerNodeId);
    const targetNode = socket.connectedIp ? this.getNodeByIp(socket.connectedIp) : undefined;

    this.recordPacket(
      sourceNode?.id || 'unknown',
      socket.boundIp || '0.0.0.0',
      socket.boundPort || 0,
      targetNode?.id,
      socket.connectedIp || '0.0.0.0',
      socket.connectedPort || 0,
      'TCP',
      { psh: true, ack: true },
      'DELIVERED',
      `Data sent (${data.length} bytes)`,
      data.length
    );

    // Direct peer connection forwarding if paired
    if (socket.connectedFd) {
      const peerSocket = this.sockets.get(socket.connectedFd);
      if (peerSocket && !peerSocket.closed && peerSocket.status === 'ESTABLISHED') {
        const peerBuf = this.getSocketBufferBytes(peerSocket.fd);
        if (peerBuf + data.length > RESOURCE_LIMITS.MAX_SOCKET_BUFFER_BYTES) {
          throw new Error(`Buffer limit exceeded for socket (ENOBUFS: max ${RESOURCE_LIMITS.MAX_SOCKET_BUFFER_BYTES} bytes)`);
        }
        const peerNodeBuf = this.getNodeBufferBytes(peerSocket.ownerNodeId);
        if (peerNodeBuf + data.length > RESOURCE_LIMITS.MAX_NODE_BUFFER_BYTES) {
          throw new Error(`Buffer limit exceeded for node (ENOBUFS: max ${RESOURCE_LIMITS.MAX_NODE_BUFFER_BYTES} bytes)`);
        }
        peerSocket.recvBuffer.push(data);
        return data.length;
      }
    }

    if (targetNode && socket.connectedPort) {
      const portConfig = targetNode.ports[socket.connectedPort];
      if (portConfig?.responseHandler) {
        try {
          const response = portConfig.responseHandler(data);
          if (response && response.length > 0) {
            const sockBuf = this.getSocketBufferBytes(socket.fd);
            if (sockBuf + response.length <= RESOURCE_LIMITS.MAX_SOCKET_BUFFER_BYTES) {
              socket.recvBuffer.push(response);
            }
            this.recordPacket(
              targetNode.id,
              targetNode.ip,
              socket.connectedPort,
              sourceNode?.id,
              socket.boundIp || '0.0.0.0',
              socket.boundPort || 0,
              'TCP',
              { psh: true, ack: true },
              'DELIVERED',
              `Service reply (${response.length} bytes)`,
              response.length
            );
          }
        } catch {
          // Response handler error ignored for robustness
        }
      }
    }

    return data.length;
  }

  public sendToSocket(fd: number, targetIp: string, targetPort: number, data: Uint8Array): number {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) {
      throw new Error(`Socket closed or invalid (fd=${fd})`);
    }

    if (data.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE_BYTES) {
      throw new Error(`Payload size exceeds maximum allowed limit (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE_BYTES} bytes)`);
    }

    const sourceNode = this.nodes.get(socket.ownerNodeId);
    const targetNode = this.getNodeByIp(targetIp);
    const clientPort = socket.boundPort || (this.ephemeralPortBase + (fd % 10000));
    const boundIp = (socket.boundIp && socket.boundIp !== '0.0.0.0') ? socket.boundIp : (sourceNode?.ip || '0.0.0.0');
    if (!socket.boundPort) {
      socket.boundPort = clientPort;
      socket.boundIp = boundIp;
      if (socket.status === 'INITIAL') {
        socket.status = 'BOUND';
      }
    }

    // 1. Check Outbound Firewall Rules on Source Node - Stateful & Interface ACLs
    if (!this.isConntrackEstablished(boundIp, clientPort, targetIp, targetPort, 'UDP')) {
      if (sourceNode) {
        const outAcl = this.getOutboundAcl(sourceNode, boundIp, targetIp);
        const outDecision = this.evaluateAcl(
          outAcl.rules,
          boundIp,
          clientPort,
          targetIp,
          targetPort,
          'UDP',
          outAcl.implicitDeny
        );

        if (outDecision.action === 'DENY_DROP' || outDecision.action === 'DENY_RST') {
          this.recordPacket(
            sourceNode.id,
            boundIp,
            clientPort,
            undefined,
            targetIp,
            targetPort,
            'UDP',
            undefined,
            'DROPPED',
            `Outbound UDP datagram dropped by firewall rule [${outDecision.ruleId || 'implicit-deny'}]`,
            data.length
          );
          return data.length;
        }
      }
    }

    // 2. Check Inbound Firewall Rules on Target Node - Stateful & Interface ACLs
    if (targetNode && !this.isConntrackEstablished(boundIp, clientPort, targetIp, targetPort, 'UDP')) {
      const inAcl = this.getInboundAcl(targetNode, targetIp, boundIp);
      const inDecision = this.evaluateAcl(
        inAcl.rules,
        boundIp,
        clientPort,
        targetIp,
        targetPort,
        'UDP',
        inAcl.implicitDeny
      );

      if (inDecision.action === 'DENY_DROP' || inDecision.action === 'DENY_RST') {
        this.recordPacket(
          sourceNode?.id || 'unknown',
          boundIp,
          clientPort,
          targetNode.id,
          targetIp,
          targetPort,
          'UDP',
          undefined,
          'DROPPED',
          `Inbound UDP datagram dropped by firewall rule [${inDecision.ruleId || 'implicit-deny'}]`,
          data.length
        );
        return data.length;
      }
    }

    this.recordPacket(
      sourceNode?.id || 'unknown',
      boundIp,
      clientPort,
      targetNode?.id,
      targetIp,
      targetPort,
      'UDP',
      undefined,
      'DELIVERED',
      `UDP Datagram sent (${data.length} bytes)`,
      data.length
    );

    // Track stateful connection so replies are permitted
    this.setConntrack(boundIp, clientPort, targetIp, targetPort, 'UDP', 'ESTABLISHED');

    if (targetNode) {
      for (const [_, dstSock] of this.sockets) {
        if (
          !dstSock.closed &&
          dstSock.ownerNodeId === targetNode.id &&
          dstSock.boundPort === targetPort &&
          dstSock.type === 2
        ) {
          const dstBuf = this.getSocketBufferBytes(dstSock.fd);
          if (dstBuf + data.length <= RESOURCE_LIMITS.MAX_SOCKET_BUFFER_BYTES) {
            if (!dstSock.udpRecvQueue) {
              dstSock.udpRecvQueue = [];
            }
            dstSock.udpRecvQueue.push({
              data,
              sourceIp: boundIp,
              sourcePort: clientPort,
            });
            dstSock.recvBuffer.push(data);
          }
          break;
        }
      }
    }

    return data.length;
  }

  public recvSocket(fd: number, maxBytes: number): Uint8Array {
    if (maxBytes <= 0) {
      return new Uint8Array(0);
    }
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) {
      return new Uint8Array(0);
    }

    if (socket.recvBuffer.length === 0) {
      return new Uint8Array(0);
    }

    const firstChunk = socket.recvBuffer[0];
    if (firstChunk.length <= maxBytes) {
      socket.recvBuffer.shift();
      return firstChunk;
    } else {
      const returned = firstChunk.slice(0, maxBytes);
      socket.recvBuffer[0] = firstChunk.slice(maxBytes);
      return returned;
    }
  }

  public recvFromSocket(
    fd: number,
    maxBytes: number
  ): { data: Uint8Array; ip: string; port: number } | null {
    if (maxBytes <= 0) return null;
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) return null;

    if (socket.udpRecvQueue && socket.udpRecvQueue.length > 0) {
      const queued = socket.udpRecvQueue.shift()!;
      socket.recvBuffer.shift();
      const retData = new Uint8Array(queued.data.slice(0, maxBytes));
      return {
        data: retData,
        ip: queued.sourceIp,
        port: queued.sourcePort,
      };
    }

    if (socket.recvBuffer.length === 0) return null;
    const data = this.recvSocket(fd, maxBytes);
    return {
      data,
      ip: socket.connectedIp || '0.0.0.0',
      port: socket.connectedPort || 0,
    };
  }

  public bindSocket(fd: number, ip: string, port: number): BindResult {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) {
      return { success: false, errno: Errno.EBADF, message: 'Bad file descriptor' };
    }
    if (socket.status === 'BOUND' || socket.status === 'ESTABLISHED' || socket.status === 'LISTENING') {
      return { success: false, errno: Errno.EINVAL, message: 'Socket already bound or connected' };
    }

    const node = this.nodes.get(socket.ownerNodeId);
    if (!node) {
      return { success: false, errno: Errno.EBADF, message: 'Owner node not found' };
    }

    let bindNode = node;
    if (ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== node.ip) {
      const targetNode = this.getNodeByIp(ip);
      if (!targetNode) {
        return { success: false, errno: Errno.EINVAL, message: `Cannot assign requested address ${ip}` };
      }
      bindNode = targetNode;
      socket.ownerNodeId = targetNode.id;
    }

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 0 || parsedPort > 65535) {
      return { success: false, errno: Errno.EINVAL, message: `Invalid port ${port}` };
    }

    const targetPort = parsedPort === 0 ? this.ephemeralPortBase + (fd % 10000) : parsedPort;

    // Check EADDRINUSE on the same node
    for (const [otherFd, other] of this.sockets.entries()) {
      if (otherFd === fd || other.closed || other.ownerNodeId !== socket.ownerNodeId) continue;
      if (other.boundPort === targetPort) {
        if (
          other.boundIp === ip ||
          other.boundIp === '0.0.0.0' ||
          ip === '0.0.0.0'
        ) {
          return { success: false, errno: Errno.EADDRINUSE, message: 'Address already in use' };
        }
      }
    }

    socket.boundIp = ip;
    socket.boundPort = targetPort;
    socket.status = 'BOUND';
    return { success: true, errno: Errno.SUCCESS };
  }

  public listenSocket(fd: number, backlog: number = 5): void {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) return;
    if (socket.status !== 'BOUND') {
      const node = this.nodes.get(socket.ownerNodeId);
      socket.boundIp = node?.ip || '0.0.0.0';
      socket.boundPort = this.ephemeralPortBase + (fd % 10000);
    }
    socket.status = 'LISTENING';
    socket.backlog = backlog > 0 ? backlog : 5;
    socket.acceptQueue = socket.acceptQueue || [];
  }

  public acceptSocket(fd: number): AcceptResult {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed || socket.status !== 'LISTENING') {
      return { errno: Errno.EINVAL };
    }
    if (socket.acceptQueue && socket.acceptQueue.length > 0) {
      const queued = socket.acceptQueue.shift()!;
      return {
        errno: Errno.SUCCESS,
        clientFd: queued.clientFd,
        clientIp: queued.clientIp,
        clientPort: queued.clientPort,
      };
    }
    return { errno: Errno.EAGAIN };
  }

  public closeSocket(fd: number): void {
    const socket = this.sockets.get(fd);
    if (!socket || socket.closed) return;

    if (socket.status === 'ESTABLISHED') {
      const sourceNode = this.nodes.get(socket.ownerNodeId);
      const targetNode = socket.connectedIp ? this.getNodeByIp(socket.connectedIp) : undefined;
      this.recordPacket(
        sourceNode?.id || 'unknown',
        socket.boundIp || '0.0.0.0',
        socket.boundPort || 0,
        targetNode?.id,
        socket.connectedIp || '0.0.0.0',
        socket.connectedPort || 0,
        'TCP',
        { fin: true, ack: true },
        'DELIVERED',
        'TCP FIN connection close'
      );
    }

    if (socket.connectedIp && socket.connectedPort) {
      this.removeConntrack(
        socket.boundIp || '0.0.0.0',
        socket.boundPort || 0,
        socket.connectedIp,
        socket.connectedPort,
        socket.type === 2 ? 'UDP' : 'TCP'
      );
    }

    socket.closed = true;
    socket.status = 'CLOSED';
    this.sockets.delete(fd);
  }
}
