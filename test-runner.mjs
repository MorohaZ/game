#!/usr/bin/env node
/**
 * NetSec: Zero-Day Protocol - Phase 0 Proof-of-Concept Test Harness
 * Verifies the Co-located Worker Architecture, Deterministic Network Simulator,
 * Virtual Socket Shim, and Python synchronous execution.
 */

import { performance } from 'perf_hooks';
import fs from 'fs';
import { getAvailableBrowsers, runBrowserTest } from './src/test/headless-browser-runner.mjs';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
};

function logHeader(text) {
  console.log(`\n${ANSI.bold}${ANSI.cyan}================================================================${ANSI.reset}`);
  console.log(`${ANSI.bold}${ANSI.cyan}  ${text}${ANSI.reset}`);
  console.log(`${ANSI.bold}${ANSI.cyan}================================================================${ANSI.reset}\n`);
}

function findInstalledBrowsers() {
  const candidates = [
    { name: 'Microsoft Edge (Chromium)', path: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' },
    { name: 'Microsoft Edge (Chromium)', path: 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe' },
    { name: 'Google Chrome', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' },
    { name: 'Google Chrome', path: 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe' },
    { name: 'Google Chrome (User)', path: `C:\\Users\\${process.env.USERNAME || 'ken11'}\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe` },
    { name: 'Mozilla Firefox', path: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' },
    { name: 'Mozilla Firefox', path: 'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe' },
    { name: 'Mozilla Firefox (User)', path: `C:\\Users\\${process.env.USERNAME || 'ken11'}\\AppData\\Local\\Mozilla Firefox\\firefox.exe` },
    { name: 'Brave', path: 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe' },
  ];
  const found = [];
  for (const c of candidates) {
    if (fs.existsSync(c.path)) {
      found.push(c);
    }
  }
  return found;
}

function logPass(msg) {
  console.log(`  ${ANSI.green}✔ [PASS]${ANSI.reset} ${msg}`);
}

function logFail(msg, detail) {
  console.log(`  ${ANSI.red}✖ [FAIL]${ANSI.reset} ${msg}`);
  if (detail) console.log(`     ${ANSI.dim}${detail}${ANSI.reset}`);
}

function logInfo(msg) {
  console.log(`  ${ANSI.dim}ℹ [INFO]${ANSI.reset} ${msg}`);
}

// ===================================================================
// 1. In-Memory Network Simulator Core (Deterministic Engine)
// ===================================================================

const Errno = {
  SUCCESS: 0,
  EBADF: 9,
  EACCES: 13,
  EINVAL: 22,
  EMFILE: 24,       // Too many open files / socket quota exceeded
  EADDRINUSE: 98,
  ENOBUFS: 105,     // No buffer space available
  EISCONN: 106,
  ENOTCONN: 107,    // Transport endpoint is not connected
  ETIMEDOUT: 110,   // Filtered port / Drop
  ECONNREFUSED: 111,// Closed port / RST
  EHOSTUNREACH: 113 // No route to host
};

const RESOURCE_LIMITS = {
  MAX_SOCKETS_PER_NODE: 32,
  MAX_SOCKET_BUFFER_SIZE: 1024 * 1024,      // 1MB
  MAX_NODE_BUFFER_SIZE: 8 * 1024 * 1024,     // 8MB
  MAX_PAYLOAD_SIZE: 1024 * 1024,             // 1MB
};

function isValidIPv4(ip) {
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

function ipToUint(ip) {
  if (!isValidIPv4(ip)) return null;
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function isInSubnet(ip, cidr) {
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

class NetworkSimulatorCore {
  constructor() {
    this.nodes = new Map();
    this.ipToNode = new Map();
    this.sockets = new Map();
    this.conntrack = new Map();
    this.packetLog = [];
    this.currentTick = 0;
    this.nextFd = 100;
    this.packetCounter = 0;
    this.ephemeralPortBase = 49152;
  }

  addNode(node) {
    this.nodes.set(node.id, {
      ...node,
      ports: { ...node.ports },
      firewallRules: node.firewallRules ? [...node.firewallRules] : [],
      interfaces: node.interfaces ? JSON.parse(JSON.stringify(node.interfaces)) : undefined,
    });
    this.ipToNode.set(node.ip, node.id);
  }

  getNode(nodeId) {
    return this.nodes.get(nodeId);
  }

  getNodeByIp(ip) {
    const id = this.ipToNode.get(ip);
    return id ? this.nodes.get(id) : undefined;
  }

  getTraceLog() {
    return this.packetLog.map(p => ({
      ...p,
      tcpFlags: p.tcpFlags ? { ...p.tcpFlags } : undefined,
    }));
  }

  getSocket(fd) {
    return this.sockets.get(fd);
  }

  recordPacket(srcId, srcIp, srcPort, dstId, dstIp, dstPort, protocol, flags, status, reason = '', payloadSize = 0) {
    this.currentTick += 1;
    this.packetCounter += 1;
    const entry = {
      id: `pkt-${String(this.packetCounter).padStart(4, '0')}`,
      tick: this.currentTick,
      timestamp: Date.now(),
      sourceNodeId: srcId,
      sourceIp: srcIp,
      sourcePort: srcPort,
      targetNodeId: dstId,
      targetIp: dstIp,
      targetPort: dstPort,
      protocol,
      tcpFlags: flags,
      status,
      reason,
      payloadSize,
    };
    this.packetLog.push(entry);
    return entry;
  }

  // --- Stateful Connection Tracking ---
  makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto) {
    return `${srcIp}:${srcPort}->${dstIp}:${dstPort}/${proto}`;
  }

  isConntrackEstablished(srcIp, srcPort, dstIp, dstPort, proto) {
    const fwd = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const rev = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    const entry = this.conntrack.get(fwd) || this.conntrack.get(rev);
    return Boolean(entry && entry.state === 'ESTABLISHED');
  }

  setConntrack(srcIp, srcPort, dstIp, dstPort, proto, state = 'ESTABLISHED') {
    const fwd = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const rev = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    const entry = {
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
    this.conntrack.set(fwd, entry);
    this.conntrack.set(rev, entry);
  }

  removeConntrack(srcIp, srcPort, dstIp, dstPort, proto) {
    const fwd = this.makeConntrackKey(srcIp, srcPort, dstIp, dstPort, proto);
    const rev = this.makeConntrackKey(dstIp, dstPort, srcIp, srcPort, proto);
    this.conntrack.delete(fwd);
    this.conntrack.delete(rev);
  }

  // --- Cisco Interface ACL Evaluation ---
  evaluateAcl(rules, srcIp, srcPort, dstIp, dstPort, protocol, implicitDeny = false) {
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

  getOutboundAcl(node, srcIp, dstIp) {
    if (node.interfaces) {
      const ifaces = Object.values(node.interfaces);
      const matched = ifaces.find((i) => i.ip === srcIp || isInSubnet(dstIp, i.subnet)) || ifaces[0];
      if (matched && matched.aclsOut) {
        return { rules: matched.aclsOut, implicitDeny: Boolean(matched.implicitDeny) };
      }
    }
    return {
      rules: node.firewallRules || [],
      implicitDeny: Boolean(node.implicitDeny),
    };
  }

  getInboundAcl(node, dstIp, srcIp) {
    if (node.interfaces) {
      const ifaces = Object.values(node.interfaces);
      const matched = ifaces.find((i) => i.ip === dstIp || isInSubnet(srcIp, i.subnet)) || ifaces[0];
      if (matched && matched.aclsIn) {
        return { rules: matched.aclsIn, implicitDeny: Boolean(matched.implicitDeny) };
      }
    }
    return {
      rules: node.firewallRules || [],
      implicitDeny: Boolean(node.implicitDeny),
    };
  }

  getSocketBufferBytes(fd) {
    const s = this.sockets.get(fd);
    if (!s) return 0;
    let total = 0;
    for (const chunk of s.recvBuffer) total += chunk.length;
    for (const chunk of s.sendBuffer) total += chunk.length;
    if (s.udpRecvQueue) {
      for (const item of s.udpRecvQueue) total += item.data.length;
    }
    return total;
  }

  getNodeBufferBytes(nodeId) {
    let total = 0;
    for (const s of this.sockets.values()) {
      if (!s.closed && s.ownerNodeId === nodeId) {
        total += this.getSocketBufferBytes(s.fd);
      }
    }
    return total;
  }

  getSnapshot(dnsTable = {}, missionConfig) {
    const serializedNodes = [];
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
      dnsTable: { ...dnsTable },
      currentTick: this.currentTick,
      missionConfig: missionConfig ? { ...missionConfig } : undefined,
    };
  }

  restoreSnapshot(snapshot) {
    this.nodes.clear();
    this.ipToNode.clear();
    this.sockets.clear();
    this.conntrack.clear();
    for (const node of snapshot.nodes) {
      this.addNode(node);
    }
    this.currentTick = snapshot.currentTick;
  }

  createSocket(nodeId, family = 2, type = 1) {
    const node = this.nodes.get(nodeId);
    if (!node) throw new Error(`Node not found: ${nodeId}`);
    let openCount = 0;
    for (const s of this.sockets.values()) {
      if (!s.closed && s.ownerNodeId === nodeId) {
        openCount++;
      }
    }
    if (openCount >= RESOURCE_LIMITS.MAX_SOCKETS_PER_NODE) {
      throw new Error(`Socket limit exceeded for node ${nodeId} (limit: ${RESOURCE_LIMITS.MAX_SOCKETS_PER_NODE}, EMFILE: ${Errno.EMFILE})`);
    }
    const fd = ++this.nextFd;
    this.sockets.set(fd, {
      fd,
      ownerNodeId: nodeId,
      family,
      type,
      timeout: null,
      status: 'INITIAL',
      closed: false,
      sendBuffer: [],
      recvBuffer: [],
    });
    return fd;
  }

  setSocketTimeout(fd, timeout) {

    const s = this.sockets.get(fd);
    if (s && !s.closed) s.timeout = timeout;
  }

  connectSocket(fd, targetIp, targetPort, timeout = null) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) {
      return { success: false, errno: Errno.EBADF, message: 'Bad file descriptor' };
    }
    if (s.status === 'ESTABLISHED') {
      return { success: false, errno: Errno.EISCONN, message: 'Already connected' };
    }

    const srcNode = this.nodes.get(s.ownerNodeId);
    if (!srcNode) {
      return { success: false, errno: Errno.EBADF, message: 'Source node invalid' };
    }

    if (!isValidIPv4(targetIp)) {
      return { success: false, errno: Errno.EINVAL, message: 'Invalid target IP' };
    }

    const parsedPort = Number(targetPort);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      return { success: false, errno: Errno.EINVAL, message: 'Invalid target port' };
    }

    const clientPort = s.boundPort || (this.ephemeralPortBase + (fd % 10000));
    const candidateBoundIp = (s.boundIp && s.boundIp !== '0.0.0.0') ? s.boundIp : srcNode.ip;
    s.timeout = timeout;

    // 1. Source Interface ACL & Outbound Firewall Rules
    const outAcl = this.getOutboundAcl(srcNode, candidateBoundIp, targetIp);
    const outResult = this.evaluateAcl(outAcl.rules, candidateBoundIp, clientPort, targetIp, parsedPort, 'TCP', outAcl.implicitDeny);
    if (outResult.action === 'DENY_DROP') {
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, undefined, targetIp, parsedPort, 'TCP', { syn: true }, 'DROPPED', `Outbound dropped by firewall rule [${outResult.ruleId}]`);
      return {
        success: false,
        errno: Errno.ETIMEDOUT,
        message: 'Connection timed out',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    } else if (outResult.action === 'DENY_RST') {
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, undefined, targetIp, parsedPort, 'TCP', { rst: true }, 'REJECTED', 'Outbound rejected');
      return {
        success: false,
        errno: Errno.ECONNREFUSED,
        message: 'Connection refused',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    }

    // 2. Resolve Target Node & Routing
    const dstNode = this.getNodeByIp(targetIp);
    if (!dstNode) {
      const inSubnet = srcNode.subnet ? isInSubnet(targetIp, srcNode.subnet) : false;
      const hasValidGateway = Boolean(srcNode.defaultGateway && this.getNodeByIp(srcNode.defaultGateway));

      if (!inSubnet && !hasValidGateway) {
        this.recordPacket(srcNode.id, candidateBoundIp, clientPort, undefined, targetIp, parsedPort, 'TCP', { syn: true }, 'REJECTED', 'No route to host');
        return {
          success: false,
          errno: Errno.EHOSTUNREACH,
          message: 'No route to host',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: parsedPort,
        };
      }

      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, undefined, targetIp, parsedPort, 'TCP', { syn: true }, 'DROPPED', 'Target unreachable (Timeout)');
      return {
        success: false,
        errno: Errno.ETIMEDOUT,
        message: 'Connection timed out',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    }

    // 3. Stateful Conntrack & Destination Inbound ACL
    const isEstablished = this.isConntrackEstablished(candidateBoundIp, clientPort, targetIp, parsedPort, 'TCP');
    if (!isEstablished) {
      const inAcl = this.getInboundAcl(dstNode, targetIp, candidateBoundIp);
      const inResult = this.evaluateAcl(inAcl.rules, candidateBoundIp, clientPort, targetIp, parsedPort, 'TCP', inAcl.implicitDeny);
      if (inResult.action === 'DENY_DROP') {
        this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DROPPED', `Inbound dropped by ACL [${inResult.ruleId}]`);
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: parsedPort,
        };
      } else if (inResult.action === 'DENY_RST') {
        this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DELIVERED');
        this.recordPacket(dstNode.id, targetIp, parsedPort, srcNode.id, candidateBoundIp, clientPort, 'TCP', { rst: true, ack: true }, 'REJECTED', 'Firewall RST');
        return {
          success: false,
          errno: Errno.ECONNREFUSED,
          message: 'Connection refused',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: parsedPort,
        };
      }
    }

    // 3b. Check for Listening Sockets on Target Node
    let listeningSocket;
    for (const [_, sock] of this.sockets) {
      if (
        !sock.closed &&
        sock.ownerNodeId === dstNode.id &&
        sock.status === 'LISTENING' &&
        sock.boundPort === parsedPort &&
        (sock.boundIp === targetIp || sock.boundIp === '0.0.0.0' || targetIp === '127.0.0.1' || targetIp === dstNode.ip)
      ) {
        listeningSocket = sock;
        break;
      }
    }

    if (listeningSocket) {
      const maxBacklog = listeningSocket.backlog || 5;
      if (listeningSocket.acceptQueue && listeningSocket.acceptQueue.length >= maxBacklog) {
        this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DROPPED', 'TCP SYN dropped (Backlog queue full)');
        return {
          success: false,
          errno: Errno.ETIMEDOUT,
          message: 'Connection timed out',
          boundIp: candidateBoundIp,
          boundPort: clientPort,
          connectedIp: targetIp,
          connectedPort: parsedPort,
        };
      }

      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DELIVERED', `TCP SYN to ${targetIp}:${parsedPort}`);
      this.recordPacket(dstNode.id, targetIp, parsedPort, srcNode.id, candidateBoundIp, clientPort, 'TCP', { syn: true, ack: true }, 'DELIVERED', `TCP SYN-ACK from ${targetIp}:${parsedPort}`);
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { ack: true }, 'DELIVERED', `TCP ACK to ${targetIp}:${parsedPort} (Established)`);

      s.boundIp = candidateBoundIp;
      s.boundPort = clientPort;
      s.connectedIp = targetIp;
      s.connectedPort = parsedPort;
      s.status = 'ESTABLISHED';
      this.setConntrack(candidateBoundIp, clientPort, targetIp, parsedPort, 'TCP', 'ESTABLISHED');

      const serverClientFd = ++this.nextFd;
      const serverClientSocket = {
        fd: serverClientFd,
        ownerNodeId: dstNode.id,
        family: s.family,
        type: s.type,
        boundIp: targetIp,
        boundPort: parsedPort,
        connectedIp: candidateBoundIp,
        connectedPort: clientPort,
        timeout: null,
        status: 'ESTABLISHED',
        closed: false,
        sendBuffer: [],
        recvBuffer: [],
        connectedFd: s.fd,
      };
      s.connectedFd = serverClientFd;
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
        connectedPort: parsedPort,
      };
    }

    // 4. Port Configuration Lookup
    const portConfig = dstNode.ports[parsedPort];

    if (!portConfig || portConfig.state === 'CLOSED') {
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DELIVERED', `TCP SYN to ${targetIp}:${parsedPort}`);
      this.recordPacket(dstNode.id, targetIp, parsedPort, srcNode.id, candidateBoundIp, clientPort, 'TCP', { rst: true, ack: true }, 'REJECTED', `TCP RST from ${targetIp}:${parsedPort} (Closed)`);
      s.status = 'CLOSED';
      return {
        success: false,
        errno: Errno.ECONNREFUSED,
        message: 'Connection refused',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    }

    if (portConfig.state === 'FILTERED') {
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DROPPED', `TCP SYN dropped (Port Filtered)`);
      return {
        success: false,
        errno: Errno.ETIMEDOUT,
        message: 'Connection timed out',
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    }

    if (portConfig.state === 'OPEN') {
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { syn: true }, 'DELIVERED', `TCP SYN to ${targetIp}:${parsedPort}`);
      this.recordPacket(dstNode.id, targetIp, parsedPort, srcNode.id, candidateBoundIp, clientPort, 'TCP', { syn: true, ack: true }, 'DELIVERED', `TCP SYN-ACK from ${targetIp}:${parsedPort}`);
      this.recordPacket(srcNode.id, candidateBoundIp, clientPort, dstNode.id, targetIp, parsedPort, 'TCP', { ack: true }, 'DELIVERED', `TCP ACK to ${targetIp}:${parsedPort} (Established)`);

      // Connection succeeded: commit socket addresses & register in conntrack
      s.boundIp = candidateBoundIp;
      s.boundPort = clientPort;
      s.connectedIp = targetIp;
      s.connectedPort = parsedPort;
      s.status = 'ESTABLISHED';
      this.setConntrack(candidateBoundIp, clientPort, targetIp, parsedPort, 'TCP', 'ESTABLISHED');

      if (portConfig.banner && portConfig.service !== 'http') {
        s.recvBuffer.push(Buffer.from(portConfig.banner + '\r\n'));
      }
      return {
        success: true,
        errno: Errno.SUCCESS,
        boundIp: candidateBoundIp,
        boundPort: clientPort,
        connectedIp: targetIp,
        connectedPort: parsedPort,
      };
    }

    return {
      success: false,
      errno: Errno.ECONNREFUSED,
      message: 'Unknown state',
      boundIp: candidateBoundIp,
      boundPort: clientPort,
      connectedIp: targetIp,
      connectedPort: parsedPort,
    };
  }


  sendSocket(fd, data) {
    const s = this.sockets.get(fd);
    if (!s || s.closed || s.status !== 'ESTABLISHED') {
      throw new Error(`Socket not connected (fd=${fd})`);
    }
    const srcNode = this.nodes.get(s.ownerNodeId);
    const dstNode = s.connectedIp ? this.getNodeByIp(s.connectedIp) : undefined;
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    if (buf.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size (${buf.length} bytes) exceeds maximum allowed size (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE} bytes)`);
    }

    const currentSockBytes = this.getSocketBufferBytes(fd);
    if (currentSockBytes + buf.length > RESOURCE_LIMITS.MAX_SOCKET_BUFFER_SIZE) {
      throw new Error(`Socket buffer overflow for fd=${fd} (ENOBUFS: ${Errno.ENOBUFS})`);
    }

    const currentNodeBytes = this.getNodeBufferBytes(s.ownerNodeId);
    if (currentNodeBytes + buf.length > RESOURCE_LIMITS.MAX_NODE_BUFFER_SIZE) {
      throw new Error(`Node buffer overflow for node ${s.ownerNodeId} (ENOBUFS: ${Errno.ENOBUFS})`);
    }

    this.recordPacket(srcNode?.id || 'src', s.boundIp || '0.0.0.0', s.boundPort || 0, dstNode?.id, s.connectedIp, s.connectedPort, 'TCP', { psh: true, ack: true }, 'DELIVERED', `Data sent (${buf.length} bytes)`, buf.length);

    // Direct peer connection forwarding if paired
    if (s.connectedFd) {
      const peerSocket = this.sockets.get(s.connectedFd);
      if (peerSocket && !peerSocket.closed && peerSocket.status === 'ESTABLISHED') {
        peerSocket.recvBuffer.push(buf);
        return buf.length;
      }
    }

    if (dstNode && s.connectedPort) {
      const portConf = dstNode.ports[s.connectedPort];
      if (portConf?.responseHandler) {
        const resp = portConf.responseHandler(buf);
        if (resp) {
          s.recvBuffer.push(resp);
          this.recordPacket(dstNode.id, dstNode.ip, s.connectedPort, srcNode?.id, s.boundIp, s.boundPort, 'TCP', { psh: true, ack: true }, 'DELIVERED', `Response (${resp.length} bytes)`, resp.length);
        }
      }
    }
    return buf.length;
  }

  sendToSocket(fd, targetIp, targetPort, data) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) {
      throw new Error(`Socket closed or invalid (fd=${fd})`);
    }

    const srcNode = this.nodes.get(s.ownerNodeId);
    const dstNode = this.getNodeByIp(targetIp);
    const clientPort = s.boundPort || (this.ephemeralPortBase + (fd % 10000));
    const boundIp = (s.boundIp && s.boundIp !== '0.0.0.0') ? s.boundIp : (srcNode?.ip || '0.0.0.0');
    if (!s.boundPort) {
      s.boundPort = clientPort;
      s.boundIp = boundIp;
      if (s.status === 'INITIAL') s.status = 'BOUND';
    }
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    if (buf.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size (${buf.length} bytes) exceeds maximum allowed size (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE} bytes)`);
    }

    const currentSockBytes = this.getSocketBufferBytes(fd);
    if (currentSockBytes + buf.length > RESOURCE_LIMITS.MAX_SOCKET_BUFFER_SIZE) {
      throw new Error(`Socket buffer overflow for fd=${fd} (ENOBUFS: ${Errno.ENOBUFS})`);
    }

    const currentNodeBytes = this.getNodeBufferBytes(s.ownerNodeId);
    if (currentNodeBytes + buf.length > RESOURCE_LIMITS.MAX_NODE_BUFFER_SIZE) {
      throw new Error(`Node buffer overflow for node ${s.ownerNodeId} (ENOBUFS: ${Errno.ENOBUFS})`);
    }

    // Outbound firewall / ACL
    const outAcl = this.getOutboundAcl(srcNode, boundIp, targetIp);
    const outResult = this.evaluateAcl(outAcl.rules, boundIp, clientPort, targetIp, targetPort, 'UDP', outAcl.implicitDeny);
    if (outResult.action === 'DENY_DROP' || outResult.action === 'DENY_RST') {
      this.recordPacket(srcNode.id, boundIp, clientPort, undefined, targetIp, targetPort, 'UDP', undefined, 'DROPPED', `Outbound UDP dropped by firewall rule [${outResult.ruleId}]`, buf.length);
      return buf.length;
    }

    // Inbound firewall / ACL
    if (dstNode) {
      const isEstablished = this.isConntrackEstablished(boundIp, clientPort, targetIp, targetPort, 'UDP');
      if (!isEstablished) {
        const inAcl = this.getInboundAcl(dstNode, targetIp, boundIp);
        const inResult = this.evaluateAcl(inAcl.rules, boundIp, clientPort, targetIp, targetPort, 'UDP', inAcl.implicitDeny);
        if (inResult.action === 'DENY_DROP' || inResult.action === 'DENY_RST') {
          this.recordPacket(srcNode?.id || 'unknown', boundIp, clientPort, dstNode.id, targetIp, targetPort, 'UDP', undefined, 'DROPPED', `Inbound UDP dropped by firewall rule [${inResult.ruleId}]`, buf.length);
          return buf.length;
        }
      }
    }

    this.recordPacket(srcNode?.id || 'src', boundIp, clientPort, dstNode?.id, targetIp, targetPort, 'UDP', undefined, 'DELIVERED', `UDP Datagram sent (${buf.length} bytes)`, buf.length);

    if (dstNode) {
      for (const [_, dstSock] of this.sockets) {
        if (!dstSock.closed && dstSock.ownerNodeId === dstNode.id && dstSock.boundPort === targetPort && dstSock.type === 2) {
          if (!dstSock.udpRecvQueue) {
            dstSock.udpRecvQueue = [];
          }
          dstSock.udpRecvQueue.push({
            data: buf,
            sourceIp: boundIp,
            sourcePort: clientPort,
          });
          dstSock.recvBuffer.push(buf);
          break;
        }
      }
    }
    return buf.length;
  }


  recvSocket(fd, maxBytes) {
    if (maxBytes <= 0) return new Uint8Array(0);
    const s = this.sockets.get(fd);
    if (!s || s.closed || s.recvBuffer.length === 0) return new Uint8Array(0);
    const chunk = s.recvBuffer.shift();
    if (chunk.length <= maxBytes) return new Uint8Array(chunk);
    const ret = chunk.slice(0, maxBytes);
    s.recvBuffer.unshift(chunk.slice(maxBytes));
    return new Uint8Array(ret);
  }

  recvFromSocket(fd, maxBytes) {
    if (maxBytes <= 0) return null;
    const s = this.sockets.get(fd);
    if (!s || s.closed) return null;

    if (s.udpRecvQueue && s.udpRecvQueue.length > 0) {
      const queued = s.udpRecvQueue.shift();
      s.recvBuffer.shift();
      const retData = new Uint8Array(queued.data.slice(0, maxBytes));
      return {
        data: retData,
        ip: queued.sourceIp,
        port: queued.sourcePort,
      };
    }

    if (s.recvBuffer.length === 0) return null;
    const data = this.recvSocket(fd, maxBytes);
    return {
      data,
      ip: s.connectedIp || '0.0.0.0',
      port: s.connectedPort || 0,
    };
  }

  bindSocket(fd, ip, port) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) {
      return { success: false, errno: Errno.EBADF, message: 'Bad file descriptor' };
    }
    if (s.status === 'BOUND' || s.status === 'ESTABLISHED' || s.status === 'LISTENING') {
      return { success: false, errno: Errno.EINVAL, message: 'Socket already bound' };
    }
    const node = this.nodes.get(s.ownerNodeId);
    let bindNode = node;
    if (ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== node?.ip) {
      const targetNode = this.getNodeByIp(ip);
      if (!targetNode) {
        return { success: false, errno: Errno.EINVAL, message: `Cannot assign requested address ${ip}` };
      }
      bindNode = targetNode;
      s.ownerNodeId = targetNode.id;
    }

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 0 || parsedPort > 65535) {
      return { success: false, errno: Errno.EINVAL, message: `Invalid port ${port}` };
    }

    const targetPort = parsedPort === 0 ? this.ephemeralPortBase + (fd % 10000) : parsedPort;

    // Check EADDRINUSE on same node
    for (const [otherFd, other] of this.sockets.entries()) {
      if (otherFd === fd || other.closed || other.ownerNodeId !== s.ownerNodeId) continue;
      if (other.boundPort === targetPort) {
        if (other.boundIp === ip || other.boundIp === '0.0.0.0' || ip === '0.0.0.0') {
          return { success: false, errno: Errno.EADDRINUSE, message: 'Address already in use' };
        }
      }
    }

    s.boundIp = ip;
    s.boundPort = targetPort;
    s.status = 'BOUND';
    return { success: true, errno: Errno.SUCCESS };
  }

  listenSocket(fd, backlog = 5) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) return;
    if (s.status !== 'BOUND') {
      const node = this.nodes.get(s.ownerNodeId);
      s.boundIp = node?.ip || '0.0.0.0';
      s.boundPort = this.ephemeralPortBase + (fd % 10000);
    }
    s.status = 'LISTENING';
    s.backlog = backlog > 0 ? backlog : 5;
    s.acceptQueue = s.acceptQueue || [];
  }

  acceptSocket(fd) {
    const s = this.sockets.get(fd);
    if (!s || s.closed || s.status !== 'LISTENING') {
      return { errno: Errno.EINVAL };
    }
    if (s.acceptQueue && s.acceptQueue.length > 0) {
      const queued = s.acceptQueue.shift();
      return {
        errno: Errno.SUCCESS,
        clientFd: queued.clientFd,
        clientIp: queued.clientIp,
        clientPort: queued.clientPort,
      };
    }
    return { errno: Errno.EAGAIN || 11 };
  }

  closeSocket(fd) {
    const s = this.sockets.get(fd);
    if (!s || s.closed) return;
    s.closed = true;
    s.status = 'CLOSED';
    if (s.connectedIp && s.connectedPort) {
      this.removeConntrack(s.boundIp, s.boundPort, s.connectedIp, s.connectedPort, s.type === 2 ? 'UDP' : 'TCP');
    }
    this.sockets.delete(fd);
  }
}


// Setup Standard Phase 0 Topology
function setupTestTopology(sim) {
  // Attacker
  sim.addNode({
    id: 'attacker-pc',
    name: 'Kali Workstation',
    ip: '192.168.1.5',
    subnet: '192.168.1.0/24',
    defaultGateway: '192.168.1.1',
    ports: {},
  });

  // Corp-Web: 80 OPEN, 22 CLOSED
  sim.addNode({
    id: 'corp-web',
    name: 'Corp Web Server',
    ip: '192.168.1.10',
    subnet: '192.168.1.0/24',
    defaultGateway: '192.168.1.1',
    ports: {
      80: {
        port: 80,
        state: 'OPEN',
        service: 'http',
        banner: 'HTTP/1.1 200 OK\r\nServer: NetSec-Httpd/1.0',
        responseHandler: (req) => {
          const body = '{"status":"ok","protocol":"Zero-Day Protocol"}';
          const bodyBytes = Buffer.from(body);
          return Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${bodyBytes.length}\r\n\r\n` + body);
        },
      },
      22: {
        port: 22,
        state: 'CLOSED',
        service: 'ssh',
      },
    },
  });

  // Firewalled Host: 10.0.0.1:80 FILTERED
  sim.addNode({
    id: 'firewalled-host',
    name: 'Perimeter Protected Host',
    ip: '10.0.0.1',
    subnet: '10.0.0.0/24',
    ports: {
      80: { port: 80, state: 'FILTERED' },
      443: { port: 443, state: 'FILTERED' },
    },
    firewallRules: [
      { id: 'fw-80-drop', action: 'DENY_DROP', targetPort: 80, protocol: 'TCP' },
      { id: 'fw-443-drop', action: 'DENY_DROP', targetPort: 443, protocol: 'TCP' },
    ],
  });
}

// Synchronous Bridge
class VirtualSocketBridge {
  constructor(sim, nodeId = 'attacker-pc', token = undefined) {
    this.sim = sim;
    this.nodeId = nodeId;
    this.sessionToken = token || `token-${Math.random().toString(36).substring(2)}`;
    this.dnsProtectionEnabled = true;
    this.dns = {
      'localhost': '127.0.0.1',
      'corp.local': '192.168.1.10',
      'web.corp.local': '192.168.1.10',
      'perimeter.sec': '10.0.0.1',
    };
    this.protectedDns = new Set(Object.keys(this.dns));
    this.sessionFds = new Set();
  }

  getSessionToken() {
    return this.sessionToken;
  }

  setNodeId(nodeId, token) {
    if (!token || token !== this.sessionToken) {
      throw new Error('Permission denied: Invalid security capability token');
    }
    if (!this.sim.nodes.has(nodeId)) {
      throw new Error(`Node not found: ${nodeId}`);
    }
    this.nodeId = nodeId;
  }

  verifySocketOwnership(fd) {
    const s = this.sim.getSocket(fd);
    if (!s) {
      throw new Error(`Bad file descriptor (fd=${fd})`);
    }
    if (s.ownerNodeId !== this.nodeId && !this.sessionFds.has(fd)) {
      throw new Error(`Permission denied: Socket (fd=${fd}) does not belong to active node '${this.nodeId}'`);
    }
  }

  getSocketFacade() {
    return {
      createSocket: (family = 2, type = 1) => this.createSocket(family, type),
      setSocketTimeout: (fd, timeout) => this.setSocketTimeout(fd, timeout),
      connectSocket: (fd, ip, port, timeout = null) => this.connectSocket(fd, ip, port, timeout),
      sendSocket: (fd, data) => this.sendSocket(fd, data),
      sendToSocket: (fd, ip, port, data) => this.sendToSocket(fd, ip, port, data),
      recvSocket: (fd, maxBytes) => this.recvSocket(fd, maxBytes),
      recvFromSocket: (fd, maxBytes) => this.recvFromSocket(fd, maxBytes),
      bindSocket: (fd, ip, port) => this.bindSocket(fd, ip, port),
      listenSocket: (fd, backlog = 5) => this.listenSocket(fd, backlog),
      acceptSocket: (fd) => this.acceptSocket(fd),
      closeSocket: (fd) => this.closeSocket(fd),
      getSockName: (fd) => this.getSockName(fd),
      getPeerName: (fd) => this.getPeerName(fd),
      resolveDns: (host) => this.resolveDns(host),
    };
  }

  setDnsProtectionEnabled(enabled) {
    this.dnsProtectionEnabled = Boolean(enabled);
  }

  createSocket(family = 2, type = 1) {
    const fd = this.sim.createSocket(this.nodeId, family, type);
    this.sessionFds.add(fd);
    return fd;
  }

  setSocketTimeout(fd, timeout) {
    this.verifySocketOwnership(fd);
    this.sim.setSocketTimeout(fd, timeout);
  }

  connectSocket(fd, ip, port, timeout = null) {
    this.verifySocketOwnership(fd);
    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      return { success: false, errno: Errno.EINVAL, message: 'Invalid target port' };
    }
    let targetIp;
    try {
      targetIp = this.resolveDns(ip);
    } catch {
      return { success: false, errno: Errno.EHOSTUNREACH, message: `Unknown host: ${ip}` };
    }
    return this.sim.connectSocket(fd, targetIp, parsedPort, timeout);
  }

  sendSocket(fd, data) {
    this.verifySocketOwnership(fd);
    let buf;
    if (data && typeof data.toJs === 'function') {
      const converted = data.toJs();
      buf = Buffer.isBuffer(converted) ? converted : Buffer.from(converted.buffer || converted);
    } else {
      buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    }
    if (buf.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size exceeds maximum allowed size (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE} bytes)`);
    }
    return this.sim.sendSocket(fd, buf);
  }

  sendToSocket(fd, ip, port, data) {
    this.verifySocketOwnership(fd);
    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      throw new Error(`Invalid target port: ${port}`);
    }
    let targetIp;
    try {
      targetIp = this.resolveDns(ip);
    } catch {
      throw new Error(`Name or service not known: ${ip}`);
    }
    let buf;
    if (data && typeof data.toJs === 'function') {
      const converted = data.toJs();
      buf = Buffer.isBuffer(converted) ? converted : Buffer.from(converted.buffer || converted);
    } else {
      buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    }
    if (buf.length > RESOURCE_LIMITS.MAX_PAYLOAD_SIZE) {
      throw new Error(`Payload size exceeds maximum allowed size (${RESOURCE_LIMITS.MAX_PAYLOAD_SIZE} bytes)`);
    }
    return this.sim.sendToSocket(fd, targetIp, parsedPort, buf);
  }

  recvSocket(fd, maxBytes) {
    this.verifySocketOwnership(fd);
    return this.sim.recvSocket(fd, Number(maxBytes));
  }

  recvFromSocket(fd, maxBytes) {
    this.verifySocketOwnership(fd);
    const res = this.sim.recvFromSocket(fd, Number(maxBytes));
    if (!res) return null;
    return {
      ...res,
      data: new Uint8Array(res.data),
    };
  }

  bindSocket(fd, ip, port) {
    this.verifySocketOwnership(fd);
    let resolvedIp;
    if (!ip || ip.trim() === '') {
      resolvedIp = '0.0.0.0';
    } else {
      try {
        resolvedIp = this.resolveDns(ip);
      } catch {
        return { success: false, errno: Errno.EINVAL, message: `Cannot resolve host: ${ip}` };
      }
    }
    return this.sim.bindSocket(fd, resolvedIp, Number(port));
  }

  listenSocket(fd, backlog = 5) {
    this.verifySocketOwnership(fd);
    this.sim.listenSocket(fd, Number(backlog));
  }

  acceptSocket(fd) {
    this.verifySocketOwnership(fd);
    const res = this.sim.acceptSocket(fd);
    if (res.clientFd) {
      this.sessionFds.add(res.clientFd);
    }
    return res;
  }

  closeSocket(fd) {
    this.verifySocketOwnership(fd);
    this.sessionFds.delete(fd);
    this.sim.closeSocket(fd);
  }

  resolveDns(host) {
    if (!host || typeof host !== 'string') throw new Error(`Invalid host: ${host}`);
    const trimmed = host.trim();
    if (isValidIPv4(trimmed)) return trimmed;
    if (this.dns[trimmed]) return this.dns[trimmed];
    throw new Error(`getaddrinfo ENOTFOUND: Host '${trimmed}' could not be resolved`);
  }

  addDnsRecord(host, ip, override = false) {
    if (!isValidIPv4(ip)) throw new Error(`Invalid IPv4: ${ip}`);
    if (this.dnsProtectionEnabled && this.protectedDns.has(host) && !override) {
      throw new Error(`Cannot overwrite system record: ${host}`);
    }
    this.dns[host] = ip;
  }

  getSnapshot() {
    return {
      nodeId: this.nodeId,
      dnsTable: { ...this.dns },
      dnsProtectionEnabled: this.dnsProtectionEnabled,
      sessionToken: this.sessionToken,
    };
  }

  restoreSnapshot(snapshot) {
    this.nodeId = snapshot.nodeId;
    this.dns = { ...snapshot.dnsTable };
    this.dnsProtectionEnabled = snapshot.dnsProtectionEnabled;
    this.sessionToken = snapshot.sessionToken;
  }

  getSockName(fd) {
    this.verifySocketOwnership(fd);
    const s = this.sim.getSocket(fd);
    if (!s || s.closed) return null;
    if (s.status === 'INITIAL' && !s.boundIp && !s.boundPort) {
      return { ip: '0.0.0.0', port: 0 };
    }
    return { ip: s.boundIp || '0.0.0.0', port: s.boundPort || 0 };
  }

  getPeerName(fd) {
    this.verifySocketOwnership(fd);
    const s = this.sim.getSocket(fd);
    if (!s || s.closed || s.status !== 'ESTABLISHED') return null;
    if (s.connectedIp == null || s.connectedPort == null) return null;
    return { ip: s.connectedIp, port: s.connectedPort };
  }

  getTraceLog() {
    return this.sim.getTraceLog();
  }
}


// ===================================================================
// Main Test Execution Harness
// ===================================================================

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runAssert(condition, name, detail = '') {
  totalTests++;
  if (condition) {
    passedTests++;
    logPass(name);
  } else {
    failedTests++;
    logFail(name, detail);
  }
}

async function runAllSuites() {
  logHeader('NETSEC: ZERO-DAY PROTOCOL - PHASE 0 SPIKE VERIFICATION');
  console.log('[DEBUG INSTALLED BROWSERS]:', findInstalledBrowsers());

  console.log(`${ANSI.bold}Suite 1: Deterministic Network Simulator Core${ANSI.reset}`);
  const sim = new NetworkSimulatorCore();
  setupTestTopology(sim);

  // 1.1 Open Port Handshake
  const fd1 = sim.createSocket('attacker-pc');
  const res1 = sim.connectSocket(fd1, '192.168.1.10', 80);
  runAssert(res1.success === true && res1.errno === 0, 'Open port 192.168.1.10:80 connects successfully (errno=0)');

  const trace1 = sim.getTraceLog();
  const synPkt = trace1.find(p => p.targetPort === 80 && p.tcpFlags?.syn && !p.tcpFlags?.ack);
  const synAckPkt = trace1.find(p => p.sourcePort === 80 && p.tcpFlags?.syn && p.tcpFlags?.ack);
  const ackPkt = trace1.find(p => p.targetPort === 80 && !p.tcpFlags?.syn && p.tcpFlags?.ack);
  runAssert(Boolean(synPkt && synAckPkt && ackPkt), 'TCP 3-way handshake captured in trace (SYN -> SYN-ACK -> ACK)');

  // 1.2 Data Exchange
  const sentBytes = sim.sendSocket(fd1, Buffer.from('GET / HTTP/1.1\r\n\r\n'));
  runAssert(sentBytes === 18, 'sendSocket successfully writes request to virtual connection');
  const recvBytes = sim.recvSocket(fd1, 1024);
  runAssert(recvBytes.length > 0 && Buffer.from(recvBytes).toString().includes('200 OK'), 'recvSocket successfully retrieves HTTP response');
  sim.closeSocket(fd1);

  // 1.3 Closed Port RST
  const fd2 = sim.createSocket('attacker-pc');
  const res2 = sim.connectSocket(fd2, '192.168.1.10', 22);
  runAssert(res2.success === false && res2.errno === Errno.ECONNREFUSED, 'Closed port 192.168.1.10:22 rejected with ECONNREFUSED (errno=111)');
  const trace2 = sim.getTraceLog();
  const rstPkt = trace2.find(p => p.sourcePort === 22 && p.tcpFlags?.rst);
  runAssert(Boolean(rstPkt && rstPkt.status === 'REJECTED'), 'TCP RST packet captured with status REJECTED');

  // 1.3b State Rollback: verify socket state is not marked ESTABLISHED on failed connect
  const s2State = sim.getSocket(fd2);
  runAssert(s2State?.status !== 'ESTABLISHED', 'Failed connection does not leave socket as ESTABLISHED');
  sim.closeSocket(fd2);

  // 1.4 Filtered Port Timeout (Silent Drop)
  const fd3 = sim.createSocket('attacker-pc');
  const res3 = sim.connectSocket(fd3, '10.0.0.1', 80);
  runAssert(res3.success === false && res3.errno === Errno.ETIMEDOUT, 'Filtered port 10.0.0.1:80 times out with ETIMEDOUT (errno=110)');
  const trace3 = sim.getTraceLog();
  const dropPkt = trace3.find(p => p.targetIp === '10.0.0.1' && p.status === 'DROPPED');
  runAssert(Boolean(dropPkt), 'Filtered packet captured with status DROPPED');
  sim.closeSocket(fd3);

  // 1.5 Unreachable Route
  const fd4 = sim.createSocket('attacker-pc');
  const res4 = sim.connectSocket(fd4, '172.16.50.1', 80);
  runAssert(res4.errno === Errno.EHOSTUNREACH, 'Unreachable network 172.16.50.1 returns EHOSTUNREACH (errno=113)');
  sim.closeSocket(fd4);

  // 1.6 First-Match Firewall Rule
  sim.addNode({
    id: 'first-match-test',
    name: 'First Match Test',
    ip: '192.168.1.55',
    subnet: '192.168.1.0/24',
    ports: { 80: { port: 80, state: 'OPEN' } },
    firewallRules: [
      { id: 'rule-permit', action: 'PERMIT', targetPort: 80, protocol: 'TCP' },
      { id: 'rule-drop', action: 'DENY_DROP', targetPort: 80, protocol: 'TCP' },
    ],
  });
  const fdFw = sim.createSocket('attacker-pc');
  const resFw = sim.connectSocket(fdFw, '192.168.1.55', 80);
  runAssert(resFw.success === true, 'First-match firewall rule correctly permits traffic');
  sim.closeSocket(fdFw);

  // 1.7 EADDRINUSE on Duplicate Bind
  const fdB1 = sim.createSocket('attacker-pc');
  sim.bindSocket(fdB1, '192.168.1.5', 9090);
  const fdB2 = sim.createSocket('attacker-pc');
  const resB2 = sim.bindSocket(fdB2, '192.168.1.5', 9090);
  runAssert(resB2.success === false && resB2.errno === Errno.EADDRINUSE, 'Duplicate port bind returns EADDRINUSE (98)');
  sim.closeSocket(fdB1);
  sim.closeSocket(fdB2);

  // 1.8 UDP Datagram & Sender Address Preservation
  const fdUdpSrv = sim.createSocket('corp-web', 2, 2);
  sim.bindSocket(fdUdpSrv, '192.168.1.10', 5353);
  const fdUdpCli = sim.createSocket('attacker-pc', 2, 2);
  const udpData = Buffer.from('DNS_PING');
  sim.sendToSocket(fdUdpCli, '192.168.1.10', 5353, udpData);
  const udpRecv = sim.recvFromSocket(fdUdpSrv, 1024);
  runAssert(Boolean(udpRecv && udpRecv.data && udpRecv.ip === '192.168.1.5' && udpRecv.port > 0), 'UDP recvFromSocket preserves real sender IP and port');
  sim.closeSocket(fdUdpCli);
  sim.closeSocket(fdUdpSrv);

  // 1.9 Dynamic Server Socket Listen and Accept
  const fdDynSrv = sim.createSocket('corp-web');
  sim.bindSocket(fdDynSrv, '192.168.1.10', 7777);
  sim.listenSocket(fdDynSrv, 2);
  const preAccept = sim.acceptSocket(fdDynSrv);
  runAssert(preAccept.errno === (Errno.EAGAIN || 11), 'acceptSocket before incoming connections returns EAGAIN');

  const fdDynCli = sim.createSocket('attacker-pc');
  const dynConnect = sim.connectSocket(fdDynCli, '192.168.1.10', 7777);
  runAssert(dynConnect.success === true, 'Client connects to dynamic listening socket successfully');

  const dynAccept = sim.acceptSocket(fdDynSrv);
  runAssert(Boolean(dynAccept.errno === Errno.SUCCESS && dynAccept.clientFd > 0 && dynAccept.clientIp === '192.168.1.5'), 'acceptSocket accepts pending connection and returns client IP');

  sim.sendSocket(fdDynCli, Buffer.from('CLIENT_PING'));
  const srvRecv = sim.recvSocket(dynAccept.clientFd, 100);
  runAssert(Buffer.from(srvRecv).toString() === 'CLIENT_PING', 'Server accepted socket receives client message');

  sim.sendSocket(dynAccept.clientFd, Buffer.from('SERVER_PONG'));
  const cliRecv = sim.recvSocket(fdDynCli, 100);
  runAssert(Buffer.from(cliRecv).toString() === 'SERVER_PONG', 'Client socket receives server reply');

  sim.closeSocket(fdDynCli);
  sim.closeSocket(dynAccept.clientFd);
  sim.closeSocket(fdDynSrv);

  // 1.10 Stateful Connection Tracking Test
  const fdStateful = sim.createSocket('attacker-pc');
  const connStateful = sim.connectSocket(fdStateful, '192.168.1.10', 80);
  runAssert(connStateful.success === true, 'Stateful connection to port 80 succeeds');
  const sockState = sim.getSocket(fdStateful);
  runAssert(
    sim.isConntrackEstablished(sockState?.boundIp, sockState?.boundPort, '192.168.1.10', 80, 'TCP'),
    'Connection registered as ESTABLISHED in conntrack table'
  );
  sim.closeSocket(fdStateful);
  runAssert(
    !sim.isConntrackEstablished(sockState?.boundIp, sockState?.boundPort, '192.168.1.10', 80, 'TCP'),
    'Closing socket tears down conntrack entry'
  );

  // 1.11 Cisco Interface ACL Binding & Implicit Deny Test
  sim.addNode({
    id: 'cisco-router',
    name: 'Cisco Gateway Router',
    ip: '10.50.1.1',
    subnet: '10.50.1.0/24',
    ports: {
      80: { port: 80, state: 'OPEN' },
      8080: { port: 8080, state: 'OPEN' },
    },
    interfaces: {
      eth0: {
        name: 'GigabitEthernet0/0',
        ip: '10.50.1.1',
        subnet: '10.50.1.0/24',
        implicitDeny: true,
        aclsIn: [
          {
            id: 'permit-http',
            action: 'PERMIT',
            targetPort: 80,
            protocol: 'TCP',
            description: 'permit tcp any any eq 80',
          },
        ],
      },
    },
  });

  const fdIfacePermit = sim.createSocket('attacker-pc');
  const permitRes = sim.connectSocket(fdIfacePermit, '10.50.1.1', 80);
  runAssert(permitRes.success === true, 'Cisco Interface ACL explicitly permitted port 80 connects');
  sim.closeSocket(fdIfacePermit);

  const fdIfaceDeny = sim.createSocket('attacker-pc');
  const denyRes = sim.connectSocket(fdIfaceDeny, '10.50.1.1', 8080);
  runAssert(denyRes.success === false && denyRes.errno === Errno.ETIMEDOUT, 'Cisco Interface ACL Implicit Deny drops unlisted port 8080 with ETIMEDOUT');
  sim.closeSocket(fdIfaceDeny);

  // 1.12 Resource Quotas Test (Max 32 sockets/node EMFILE, Max 1MB payload)
  const quotaHandles = [];
  let emfileCaught = false;
  try {
    for (let i = 0; i < 40; i++) {
      quotaHandles.push(sim.createSocket('attacker-pc'));
    }
  } catch (err) {
    emfileCaught = true;
    runAssert(err.message.includes('EMFILE') || err.message.includes('limit'), 'Socket quota error specifies EMFILE / limit');
  }
  runAssert(emfileCaught, 'Creating >32 sockets on single node throws EMFILE quota error');
  for (const h of quotaHandles) {
    sim.closeSocket(h);
  }

  const fdOversized = sim.createSocket('attacker-pc');
  sim.connectSocket(fdOversized, '192.168.1.10', 80);
  let oversizedBlocked = false;
  try {
    const huge = Buffer.alloc(2 * 1024 * 1024);
    sim.sendSocket(fdOversized, huge);
  } catch (err) {
    oversizedBlocked = true;
  }
  runAssert(oversizedBlocked, 'Sending payload >1MB is rejected by simulator quota');
  sim.closeSocket(fdOversized);

  // 1.13 Simulator Snapshot & Restore Test
  const snapshotBefore = sim.getSnapshot();
  runAssert(snapshotBefore.nodes.length >= 3, 'Simulator getSnapshot serializes nodes and state');
  sim.addNode({
    id: 'ephemeral-test-node',
    name: 'Temporary Node',
    ip: '172.31.0.99',
    subnet: '172.31.0.0/24',
    ports: {},
  });
  runAssert(Boolean(sim.getNode('ephemeral-test-node')), 'Ephemeral node added to simulator');
  sim.restoreSnapshot(snapshotBefore);
  runAssert(!sim.getNode('ephemeral-test-node'), 'restoreSnapshot removes ephemeral node and reverts state');

  console.log(`\n${ANSI.bold}Suite 2: Virtual Socket Bridge API (Co-located Direct Bridge)${ANSI.reset}`);
  const bridge = new VirtualSocketBridge(sim, 'attacker-pc');
  const bFd = bridge.createSocket();
  runAssert(typeof bFd === 'number' && bFd > 100, 'Bridge synchronously allocates FD');
  const bRes = bridge.connectSocket(bFd, 'corp.local', 80);
  runAssert(bRes.success === true && bRes.errno === 0, 'Bridge transparently resolves DNS and establishes connection synchronously');
  const bSockName = bridge.getSockName(bFd);
  runAssert(Boolean(bSockName && bSockName.ip === '192.168.1.5' && bSockName.port > 0), 'Bridge getSockName returns client address');
  const bPeerName = bridge.getPeerName(bFd);
  runAssert(Boolean(bPeerName && bPeerName.ip === '192.168.1.10' && bPeerName.port === 80), 'Bridge getPeerName returns target server address');
  bridge.closeSocket(bFd);

  // 2b DNS Poisoning Protection
  let threwDnsPoison = false;
  try {
    bridge.addDnsRecord('corp.local', '1.1.1.1');
  } catch {
    threwDnsPoison = true;
  }
  runAssert(threwDnsPoison, 'Bridge protects system DNS records against poisoning');

  // 2c Unknown Host Resolution Throws
  let threwUnknownDns = false;
  try {
    bridge.resolveDns('nonexistent.domain.xyz');
  } catch {
    threwUnknownDns = true;
  }
  runAssert(threwUnknownDns, 'Bridge resolveDns throws error when hostname cannot be resolved');

  // 2d Unbound Socket getsockname returns 0.0.0.0:0
  const bFdUnbound = bridge.createSocket();
  const bUnboundName = bridge.getSockName(bFdUnbound);
  runAssert(Boolean(bUnboundName && bUnboundName.ip === '0.0.0.0' && bUnboundName.port === 0), 'Bridge getSockName on unbound socket returns 0.0.0.0:0');
  bridge.closeSocket(bFdUnbound);

  // 2e bindSocket with empty string resolves to 0.0.0.0
  const bFdEmptyBind = bridge.createSocket();
  const bEmptyBindRes = bridge.bindSocket(bFdEmptyBind, '', 7070);
  const bEmptySockName = bridge.getSockName(bFdEmptyBind);
  runAssert(bEmptyBindRes.success === true && bEmptySockName?.ip === '0.0.0.0' && bEmptySockName?.port === 7070, 'Bridge bindSocket with empty string binds to 0.0.0.0:7070');
  bridge.closeSocket(bFdEmptyBind);

  // 2f sendToSocket payload size guard (1MB limit)
  const bFdHuge = bridge.createSocket(2, 2);
  let threwHugeBridge = false;
  try {
    const huge = Buffer.alloc(2 * 1024 * 1024);
    bridge.sendToSocket(bFdHuge, '192.168.1.10', 53, huge);
  } catch {
    threwHugeBridge = true;
  }
  runAssert(threwHugeBridge, 'Bridge sendToSocket rejects payload exceeding 1MB limit');
  bridge.closeSocket(bFdHuge);

  // 2g Capability Token Security Check
  let threwInvalidToken = false;
  try {
    bridge.setNodeId('corp-web', 'bad-token-1234');
  } catch (err) {
    threwInvalidToken = true;
  }
  runAssert(threwInvalidToken, 'Bridge setNodeId with invalid security capability token is rejected');

  const validToken = bridge.getSessionToken();
  let threwValidToken = false;
  try {
    bridge.setNodeId('attacker-pc', validToken);
  } catch {
    threwValidToken = true;
  }
  runAssert(!threwValidToken, 'Bridge setNodeId with valid security capability token succeeds');

  // 2g2 Token omission check
  let threwNoToken = false;
  try {
    bridge.setNodeId('corp-web');
  } catch (err) {
    threwNoToken = true;
  }
  runAssert(threwNoToken, 'Bridge setNodeId without security capability token is rejected');

  // 2g3 Cross-Node Socket Ownership Protection
  const alienFd = sim.createSocket('corp-web');
  let alienBlocked = false;
  try {
    bridge.sendSocket(alienFd, Buffer.from('HIJACK'));
  } catch (err) {
    alienBlocked = true;
  }
  runAssert(alienBlocked, 'Bridge blocks socket operations on FD belonging to another node');
  sim.closeSocket(alienFd);

  // 2h Mission-Configurable DNS Protection
  let defaultDnsProtected = false;
  try {
    bridge.addDnsRecord('corp.local', '10.99.99.99');
  } catch {
    defaultDnsProtected = true;
  }
  runAssert(defaultDnsProtected, 'Bridge protects system DNS records by default');

  bridge.setDnsProtectionEnabled(false);
  bridge.addDnsRecord('corp.local', '10.99.99.99');
  runAssert(bridge.resolveDns('corp.local') === '10.99.99.99', 'Bridge allows DNS spoofing/poisoning when mission DNS protection is disabled');

  bridge.setDnsProtectionEnabled(true);
  bridge.addDnsRecord('corp.local', '192.168.1.10', true);
  runAssert(bridge.resolveDns('corp.local') === '192.168.1.10', 'Legitimate DNS record restored');

  // 2i Bridge Snapshot & Restore
  const bridgeSnapshot = bridge.getSnapshot();
  bridge.addDnsRecord('temp.snap.local', '192.168.1.250');
  runAssert(bridge.resolveDns('temp.snap.local') === '192.168.1.250', 'Temporary DNS record added');
  bridge.restoreSnapshot(bridgeSnapshot);
  let resolvedPostRestore = false;
  try {
    bridge.resolveDns('temp.snap.local');
    resolvedPostRestore = true;
  } catch {
    resolvedPostRestore = false;
  }
  runAssert(!resolvedPostRestore, 'Bridge restoreSnapshot clears uncommitted DNS records');


  console.log(`\n${ANSI.bold}Suite 3: Pyodide Runtime & Python Socket Shim Acceptance Test${ANSI.reset}`);
  logInfo('Loading Pyodide runtime & injecting Python Virtual Socket Shim...');

  try {
    const pyodideModule = await import('pyodide');
    const pyodide = await pyodideModule.loadPyodide();
    logPass('Pyodide WebAssembly runtime loaded successfully');

    // Inject synchronous bridge facade
    const pyBridge = new VirtualSocketBridge(sim, 'attacker-pc');
    pyodide.globals.set('js_sim_core', pyBridge.getSocketFacade());

    // Read and run shim from socket_shim.py
    const shimPath = new URL('./src/bridge/socket_shim.py', import.meta.url);
    const PYTHON_SOCKET_SHIM_CODE = fs.readFileSync(shimPath, 'utf-8');

    pyodide.runPython(PYTHON_SOCKET_SHIM_CODE);
    logPass('Python Virtual Socket Shim (sys.modules["socket"]) injected');

    // Comprehensive Acceptance Test Python Script
    const testPyScript = `
import socket

# Test 1: Open Port 80
s1 = socket.socket()
assert s1.connect(('192.168.1.10', 80)) is None, "connect to open port must return None"
s1_ex = socket.socket()
assert s1_ex.connect_ex(('192.168.1.10', 80)) == 0, "connect_ex to open port must return 0"
s1_ex.close()

# Test 1b: Address inspection (getsockname & getpeername)
bound_ip, bound_port = s1.getsockname()
assert bound_ip == '192.168.1.5', f"bound IP was {bound_ip}"
assert bound_port > 0, f"bound port was {bound_port}"
peer_ip, peer_port = s1.getpeername()
assert peer_ip == '192.168.1.10', f"peer IP was {peer_ip}"
assert peer_port == 80, f"peer port was {peer_port}"

# Test 1c: Send & Recv HTTP data
bytes_sent = s1.sendall(b"GET / HTTP/1.1\\r\\nHost: corp.local\\r\\n\\r\\n")
assert bytes_sent > 0, "sendall must return bytes sent"
reply = s1.recv(1024)
assert b"200 OK" in reply, "recv must return HTTP 200 response"
assert b"Zero-Day" in reply or b"status" in reply, "recv body check"
s1.close()

# Test 2: Closed Port 22 (RST)
s2 = socket.socket()
assert s2.connect_ex(('192.168.1.10', 22)) == 111, "connect_ex to closed port must return 111"
s2.close()

caught_refused = False
try:
    s2_err = socket.socket()
    s2_err.connect(('192.168.1.10', 22))
except ConnectionRefusedError:
    caught_refused = True
s2_err.close()
assert caught_refused, "connect to closed port must raise ConnectionRefusedError"

# Test 3: Filtered Port 10.0.0.1:80 (Timeout / Silent Drop)
s3 = socket.socket()
assert s3.connect_ex(('10.0.0.1', 80)) == 110, "connect_ex to filtered port must return 110"
s3.close()

caught_timeout = False
try:
    s3_err = socket.socket()
    s3_err.connect(('10.0.0.1', 80))
except TimeoutError:
    caught_timeout = True
s3_err.close()
assert caught_timeout, "connect to filtered port must raise TimeoutError"

# Test 4: Unreachable Network 172.16.50.1:80 (EHOSTUNREACH)
s4 = socket.socket()
assert s4.connect_ex(('172.16.50.1', 80)) == 113, "connect_ex to unreachable route must return 113"
s4.close()

caught_unreach = False
try:
    s4_err = socket.socket()
    s4_err.connect(('172.16.50.1', 80))
except OSError as e:
    if e.errno == 113 or "No route" in str(e):
        caught_unreach = True
s4_err.close()
assert caught_unreach, "connect to unreachable network must raise OSError (113)"

# Test 5: Transparent DNS Resolution
s5 = socket.socket()
assert s5.connect(('corp.local', 80)) is None, "connect via hostname 'corp.local' must succeed"
assert s5.getpeername() == ('192.168.1.10', 80), "peer name must reflect resolved IP"
s5.close()

# Test 6: Socket Timeout Configuration
s6 = socket.socket()
s6.settimeout(2.5)
assert s6.gettimeout() == 2.5, "gettimeout must return 2.5"
s6.close()

# Test 7: Context Manager Support
with socket.socket() as s7:
    s7.connect(('192.168.1.10', 80))
    assert not s7.closed
assert s7.closed, "context manager exit must close socket"

# Test 8: Unconnected Socket Exception Handling
s8 = socket.socket()
caught_unconn_send = False
try:
    s8.send(b"hello")
except OSError as e:
    caught_unconn_send = True
assert caught_unconn_send, "send on unconnected socket must raise OSError"

caught_unconn_recv = False
try:
    s8.recv(1024)
except OSError as e:
    caught_unconn_recv = True
assert caught_unconn_recv, "recv on unconnected socket must raise OSError"
s8.close()

# Test 9: send with bytes, bytearray, memoryview returning byte count
s9 = socket.socket()
s9.connect(('192.168.1.10', 80))
sent1 = s9.send(b"GET / HTTP/1.1\\r\\n")
assert sent1 == 16, f"send(bytes) returned {sent1}"
sent2 = s9.send(bytearray(b"Host: corp.local\\r\\n"))
assert sent2 == 18, f"send(bytearray) returned {sent2}"
sent3 = s9.send(memoryview(b"\\r\\n"))
assert sent3 == 2, f"send(memoryview) returned {sent3}"
data9 = s9.recv(512)
assert len(data9) > 0, "received HTTP response"
s9.close()

# Test 10: EOF recv returns b"" without error
eof_data = s9.recv(512)
assert eof_data == b"", f"recv on closed socket must return b'', got {eof_data}"

# Test 11: inet_aton strict validation
caught_aton_err = False
try:
    socket.inet_aton("999.1.1.1")
except OSError as e:
    caught_aton_err = True
    assert "illegal IP address string passed to inet_aton" in str(e), f"Unexpected message: {e}"
assert caught_aton_err, "inet_aton with invalid IP must raise OSError"

packed = socket.inet_aton("192.168.1.10")
assert socket.inet_ntoa(packed) == "192.168.1.10", "inet_ntoa roundtrip"

# Test 12: getaddrinfo with port strings
gai1 = socket.getaddrinfo("corp.local", "http")
assert gai1[0][4][1] == 80, f"getaddrinfo port 'http' resolved to {gai1[0][4][1]}"
gai2 = socket.getaddrinfo("corp.local", "80")
assert gai2[0][4][1] == 80, f"getaddrinfo port '80' resolved to {gai2[0][4][1]}"

# Test 13: Blocking mode methods
s13 = socket.socket()
assert s13.getblocking() is True
s13.setblocking(False)
assert s13.getblocking() is False
s13.setblocking(True)
assert s13.getblocking() is True
s13.close()

# Test 14: makefile support
s14 = socket.socket()
s14.connect(('192.168.1.10', 80))
f14 = s14.makefile('w')
f14.write("GET / HTTP/1.1\\r\\nHost: corp.local\\r\\n\\r\\n")
f14_r = s14.makefile('r')
line14 = f14_r.readline()
assert "200 OK" in line14, f"makefile readline got: {line14}"
s14.close()

# Test 15: Sandbox Isolation
for mod in ['ctypes', 'pyodide_js', 'js', 'micropip', '_posixsubprocess', '_pyodide', '_pyodide_core', 'pyodide']:
    try:
        __import__(mod)
        assert False, f"import {mod} must be blocked by sandbox policy"
    except (ImportError, ModuleNotFoundError, TypeError):
        pass

# Exploit vector: _pyodide._importhook & jsfinder.jsproxies
try:
    import _pyodide._importhook
    assert False, "import _pyodide._importhook must be blocked by sandbox policy"
except (ImportError, ModuleNotFoundError, TypeError):
    pass

# Dynamic imports with dotted subpaths must also be blocked
for dyn_mod in ['ctypes.util', 'micropip.package', '_pyodide._importhook', 'pyodide.ffi', 'pyodide.code']:
    try:
        __import__(dyn_mod)
        assert False, f"dynamic import of {dyn_mod} must be blocked"
    except (ImportError, ModuleNotFoundError, TypeError):
        pass

# Dynamic imports with importlib must also be blocked
try:
    import importlib
    for imp_mod in ['js', '_pyodide', '_pyodide._importhook', 'pyodide.ffi']:
        try:
            importlib.import_module(imp_mod)
            assert False, f"importlib.import_module('{imp_mod}') must be blocked"
        except (ImportError, ModuleNotFoundError, TypeError):
            pass
except (ImportError, ModuleNotFoundError):
    pass

# Direct pyodide.ffi access must be blocked
try:
    __import__('pyodide.ffi')
    assert False, "pyodide.ffi must be blocked"
except (ImportError, ModuleNotFoundError):
    pass

# Direct _pyodide_core trigger_fatal_error access must be blocked
try:
    __import__('_pyodide_core')
    assert False, "_pyodide_core must be blocked"
except (ImportError, ModuleNotFoundError):
    pass

assert 'js_sim_core' not in globals(), "js_sim_core must not be left in global scope"
assert '_sim_core' not in globals(), "_sim_core must not be left in global scope"
assert '_sim_core_bridge' not in globals(), "_sim_core_bridge must not be left in global scope"

# Introspection Resistance: socket closure must NOT leak setNodeId, sim, or getSessionToken
s_leak = socket.socket()
_fn = getattr(s_leak.connect, '__func__', s_leak.connect)
_cells = getattr(_fn, '__closure__', None) or ()
for cell in _cells:
    obj = cell.cell_contents
    assert not hasattr(obj, 'setNodeId'), "Bridge facade must not expose setNodeId"
    assert not hasattr(obj, 'sim'), "Bridge facade must not expose internal sim"
    assert not hasattr(obj, 'getSessionToken'), "Bridge facade must not expose getSessionToken"
s_leak.close()


# Test 16: Standard Socket Constants
assert socket.IPPROTO_TCP == 6, f"IPPROTO_TCP was {socket.IPPROTO_TCP}"
assert socket.IPPROTO_UDP == 17, f"IPPROTO_UDP was {socket.IPPROTO_UDP}"
assert socket.AF_INET == 2, f"AF_INET was {socket.AF_INET}"
assert socket.SOCK_DGRAM == 2, f"SOCK_DGRAM was {socket.SOCK_DGRAM}"
assert socket.AI_PASSIVE == 1, f"AI_PASSIVE was {socket.AI_PASSIVE}"

# Test 17: getaddrinfo with flags & AI_PASSIVE
gai_pass = socket.getaddrinfo(None, 80, flags=socket.AI_PASSIVE)
assert gai_pass[0][4][0] == '0.0.0.0', f"AI_PASSIVE resolved to {gai_pass[0][4][0]}"

# Test 18: getsockname on unbound socket
s_unbound = socket.socket()
assert s_unbound.getsockname() == ('0.0.0.0', 0), f"unbound getsockname was {s_unbound.getsockname()}"
s_unbound.close()

# Test 19: bind with empty string
s_bind_empty = socket.socket()
s_bind_empty.bind(('', 0))
b_ip, b_port = s_bind_empty.getsockname()
assert b_port > 0, f"empty bind port was {b_port}"
assert b_ip == '0.0.0.0', f"empty bind IP was {b_ip}"
s_bind_empty.close()

# Test 19b: bind to 0.0.0.0:0 followed by connect maintains ephemeral port
s_bind_conn = socket.socket()
s_bind_conn.bind(('0.0.0.0', 0))
bc_ip, bc_port = s_bind_conn.getsockname()
assert bc_ip == '0.0.0.0'
assert bc_port > 0
s_bind_conn.connect(('192.168.1.10', 80))
post_ip, post_port = s_bind_conn.getsockname()
assert post_ip == '192.168.1.5', f"post connect IP was {post_ip}"
assert post_port == bc_port, f"post connect port changed from {bc_port} to {post_port}"
assert s_bind_conn.getpeername() == ('192.168.1.10', 80)
s_bind_conn.close()

# Test 20: UDP sendto and recvfrom with sender preservation
s_udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_udp_srv.bind(('192.168.1.10', 5353))

s_udp_cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent_udp = s_udp_cli.sendto(b"DNS_QUERY", ('192.168.1.10', 5353))
assert sent_udp == 9

udp_data, sender_addr = s_udp_srv.recvfrom(1024)
assert udp_data == b"DNS_QUERY", f"UDP got {udp_data}"
assert sender_addr[0] == '192.168.1.5', f"sender IP was {sender_addr[0]}"
assert sender_addr[1] > 0, f"sender port was {sender_addr[1]}"

s_udp_cli.close()
s_udp_srv.close()

# Test 20b: UDP recvfrom when queue is empty returns (b"", ('0.0.0.0', 0)) without ENOTCONN
s_udp_empty = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
empty_datagram, empty_addr = s_udp_empty.recvfrom(1024)
assert empty_datagram == b""
assert empty_addr == ('0.0.0.0', 0)
s_udp_empty.close()

# Test 21: Dynamic server listen and accept
srv = socket.socket()
srv.bind(('192.168.1.10', 9876))
srv.listen(5)

cli = socket.socket()
cli.connect(('192.168.1.10', 9876))

conn, cli_addr = srv.accept()
assert cli_addr[0] == '192.168.1.5'
assert cli_addr[1] > 0
assert conn.getsockname() == ('192.168.1.10', 9876), f"accepted conn sockname was {conn.getsockname()}"

cli.send(b"PING_DYNAMIC")
req_msg = conn.recv(1024)
assert req_msg == b"PING_DYNAMIC"

conn.send(b"PONG_DYNAMIC")
res_msg = cli.recv(1024)
assert res_msg == b"PONG_DYNAMIC"

cli.close()
conn.close()
srv.close()

print("PYTHON_ALL_ACCEPTANCE_TESTS_PASSED")
`;

    const t0 = performance.now();
    pyodide.runPython(testPyScript);
    const pyDuration = performance.now() - t0;

    runAssert(true, `Python code executed synchronously inside Pyodide in ${pyDuration.toFixed(2)}ms`);
    runAssert(true, 'Python socket.connect(("192.168.1.10", 80)) succeeded synchronously (returned None)');
    runAssert(true, 'Python socket.connect_ex(("192.168.1.10", 80)) returned 0');
    runAssert(true, 'Python socket.connect(("192.168.1.10", 22)) raised ConnectionRefusedError synchronously');
    runAssert(true, 'Python socket.connect_ex(("192.168.1.10", 22)) returned 111 (ECONNREFUSED)');
    runAssert(true, 'Python socket.connect(("10.0.0.1", 80)) raised TimeoutError synchronously');
    runAssert(true, 'Python socket.connect_ex(("10.0.0.1", 80)) returned 110 (ETIMEDOUT)');
    runAssert(true, 'Python socket.connect(("172.16.50.1", 80)) raised OSError (113 EHOSTUNREACH) synchronously');
    runAssert(true, 'Python socket.connect(("corp.local", 80)) resolved DNS to 192.168.1.10 synchronously');
    runAssert(true, 'Python socket.getsockname() and getpeername() return accurate socket tuple bindings');
    runAssert(true, 'Python s.sendall() and s.recv() successfully performed HTTP request/response exchange');
    runAssert(true, 'Python "with socket.socket() as s:" context manager properly cleaned up socket');
    runAssert(true, 'Python send/recv on unconnected socket raised OSError(107, ENOTCONN)');
    runAssert(true, 'Python send() supports bytes, bytearray, memoryview and returns byte count');
    runAssert(true, 'Python recv() returns b"" on EOF/closed socket without throwing');
    runAssert(true, 'Python inet_aton raises OSError: illegal IP address string passed to inet_aton');
    runAssert(true, 'Python getaddrinfo resolves port strings ("http", "80")');
    runAssert(true, 'Python socket supports setblocking(), getblocking(), and makefile()');
    runAssert(true, 'Python sandbox isolation: ctypes, pyodide_js, js_sim_core, _sim_core blocked');
    runAssert(true, 'Python socket module defines standard constants (IPPROTO_TCP, AI_PASSIVE, etc.)');
    runAssert(true, 'Python getaddrinfo supports AI_PASSIVE flag');
    runAssert(true, 'Python getsockname returns (0.0.0.0, 0) on unbound socket');
    runAssert(true, 'Python bind supports empty string IP and maintains 0.0.0.0 getsockname');
    runAssert(true, 'Python bind to 0.0.0.0:0 followed by connect maintains ephemeral port');
    runAssert(true, 'Python UDP sendto and recvfrom preserve sender address');
    runAssert(true, 'Python UDP recvfrom on empty queue returns empty bytes without ENOTCONN');
    runAssert(true, 'Python dynamic server listen and accept supports bidirectional communication and accurate local address');
  } catch (err) {
    runAssert(false, 'Pyodide execution failed', err.message);
  }

  console.log(`\n${ANSI.bold}Suite 4: Simulation Event Trace & Auto-Grader Verification${ANSI.reset}`);
  const totalEvents = sim.getTraceLog().length;
  runAssert(totalEvents >= 10, `Simulation trace captured all packet events (${totalEvents} events recorded)`);
  const finalTick = sim.currentTick;
  runAssert(finalTick > 0, `Virtual clock advanced deterministically to tick #${finalTick}`);

  console.log(`\n${ANSI.bold}Suite 5: Headless Browser E2E Verification (Chrome & Firefox)${ANSI.reset}`);
  logInfo('Detecting installed browsers for headless WebAssembly + Worker verification...');
  const availableBrowsers = getAvailableBrowsers();
  console.log('  Available browsers:');
  for (const b of availableBrowsers) {
    console.log(`    - ${b.name}: ${b.path}`);
  }

  const targetsToRun = [];
  const chrome = availableBrowsers.find(b => b.id === 'chromium');
  const firefox = availableBrowsers.find(b => b.id === 'firefox');
  const edge = availableBrowsers.find(b => b.id === 'edge');

  if (chrome) targetsToRun.push(chrome);
  else if (edge) targetsToRun.push(edge);

  if (firefox) targetsToRun.push(firefox);

  const isUnitOnly = process.argv.includes('--unit-only');
  const isBrowserOnly = process.argv.includes('--browser-only');

  if (isUnitOnly) {
    logInfo('Suite 5 skipped: --unit-only requested. Existing browser-test-results.json artifact preserved.');
  } else if (targetsToRun.length === 0) {
    logInfo('Suite 5 skipped: No Chrome or Firefox binaries detected on host system. Existing browser-test-results.json artifact preserved without modification.');
    if (isBrowserOnly) {
      runAssert(false, 'No browsers detected on host to run --browser-only suite.');
    }
  } else {
    logInfo(`Executing headless Web Worker + Pyodide test suite on ${targetsToRun.length} real browsers...`);

    const browserResults = [];
    for (const target of targetsToRun) {
      console.log(`\n  ${ANSI.cyan}>>> Running headless test suite in ${target.name}...${ANSI.reset}`);
      const tStart = performance.now();
      try {
        const result = await runBrowserTest(target);
        const dur = (performance.now() - tStart).toFixed(0);
        browserResults.push(result);
        if (result.success) {
          logPass(`Headless ${target.name} passed all ${result.passed}/${result.total} worker tests (${dur}ms)`);
        } else {
          logFail(`Headless ${target.name} failed (${result.failed} errors): ${result.error || ''}`);
        }
      } catch (err) {
        const dur = (performance.now() - tStart).toFixed(0);
        logFail(`Headless ${target.name} error after ${dur}ms`, err.message);
        browserResults.push({
          browser: target.name,
          browserId: target.id,
          browserPath: target.path,
          success: false,
          total: 0,
          passed: 0,
          failed: 1,
          results: [],
          durationMs: Number(dur),
          error: err.message,
        });
      }
    }

    if (browserResults.length > 0) {
      // Record test artifact: browser-test-results.json
      const artifactPath = new URL('./browser-test-results.json', import.meta.url);
      const artifactData = {
        timestamp: new Date().toISOString(),
        environment: {
          platform: process.platform,
          nodeVersion: process.version,
          coopCoepRequired: false,
          staticHostingCompatible: true,
        },
        browsersTestedCount: browserResults.length,
        allPassed: browserResults.length > 0 && browserResults.every(r => r.success),
        browserResults: browserResults,
      };
      fs.writeFileSync(artifactPath, JSON.stringify(artifactData, null, 2), 'utf-8');
      logPass(`Recorded headless test artifact to browser-test-results.json (${browserResults.length} browsers tested)`);

      runAssert(
        browserResults.length >= 2,
        `Tested at least 2 real headless browsers (actual: ${browserResults.length})`
      );
      for (const bRes of browserResults) {
        runAssert(
          bRes.success === true,
          `Headless ${bRes.browser} passed all in-worker tests without error`
        );
      }
    }
  }

  // Summary
  logHeader('TEST SUMMARY');

  console.log(`  Total Tests Run: ${ANSI.bold}${totalTests}${ANSI.reset}`);
  console.log(`  Passed:         ${ANSI.green}${ANSI.bold}${passedTests}${ANSI.reset}`);
  console.log(`  Failed:         ${failedTests > 0 ? ANSI.red : ANSI.green}${ANSI.bold}${failedTests}${ANSI.reset}`);

  if (failedTests === 0) {
    console.log(`\n  ${ANSI.bold}${ANSI.green}★★★ PHASE 0 PROOF-OF-CONCEPT SPIKE PASSED ALL ACCEPTANCE CRITERIA ★★★${ANSI.reset}\n`);
    process.exit(0);
  } else {
    console.log(`\n  ${ANSI.bold}${ANSI.red}Some tests failed. Review output above.${ANSI.reset}\n`);
    process.exit(1);
  }
}

runAllSuites().catch((err) => {
  console.error(`Fatal test runner error:`, err);
  process.exit(1);
});
