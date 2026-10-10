/**
 * Core type definitions for NetSec: Zero-Day Protocol
 * Phase 0: Deterministic In-Memory Network Simulator
 */

export type PortState = 'OPEN' | 'CLOSED' | 'FILTERED';

export interface PortConfig {
  port: number;
  state: PortState;
  service?: string;
  banner?: string;
  responseHandler?: (requestData: Uint8Array) => Uint8Array;
}

export type FirewallAction = 'PERMIT' | 'DENY_DROP' | 'DENY_RST';

export interface FirewallRule {
  id: string;
  action: FirewallAction;
  sourceIp?: string; // 'any' or CIDR or specific IP
  targetIp?: string;
  targetPort?: number;
  protocol?: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  description?: string;
}

export interface NetworkInterface {
  name: string; // e.g. "eth0"
  ip: string;
  subnet: string;
  defaultGateway?: string;
  aclsIn?: FirewallRule[];  // Cisco ip access-group IN
  aclsOut?: FirewallRule[]; // Cisco ip access-group OUT
  implicitDeny?: boolean;   // Cisco ACL implicit deny at end
}

export interface NetworkNode {
  id: string;
  name: string;
  ip: string;
  subnet: string; // e.g. "192.168.1.0/24"
  defaultGateway?: string;
  ports: Record<number, PortConfig>;
  firewallRules?: FirewallRule[]; // Node-level rules (backward compatible)
  interfaces?: Record<string, NetworkInterface>; // Interface-bound ACLs
  implicitDeny?: boolean;
}

export type ProtocolType = 'TCP' | 'UDP' | 'ICMP';

export enum AddressFamily {
  AF_UNSPEC = 0,
  AF_INET = 2,
  AF_INET6 = 10,
}

export enum SocketType {
  SOCK_STREAM = 1,
  SOCK_DGRAM = 2,
  SOCK_RAW = 3,
}

export enum ProtocolTypeEnum {
  IP = 0,
  ICMP = 1,
  TCP = 6,
  UDP = 17,
}

export interface TcpFlags {
  syn?: boolean;
  ack?: boolean;
  rst?: boolean;
  fin?: boolean;
  psh?: boolean;
}

export type PacketDeliveryStatus = 'DELIVERED' | 'DROPPED' | 'REJECTED';

export interface PacketTraceEntry {
  id: string;
  tick: number;
  timestamp: number;
  sourceNodeId: string;
  sourceIp: string;
  sourcePort?: number;
  targetNodeId?: string;
  targetIp: string;
  targetPort?: number;
  protocol: ProtocolType;
  tcpFlags?: TcpFlags;
  status: PacketDeliveryStatus;
  reason?: string;
  payloadSize?: number;
}

export enum Errno {
  SUCCESS = 0,
  EBADF = 9,         // Bad file descriptor
  EAGAIN = 11,       // Resource temporarily unavailable
  EACCES = 13,       // Permission denied
  EINVAL = 22,       // Invalid argument
  EMFILE = 24,       // Too many open sockets on node
  EADDRINUSE = 98,   // Address already in use
  ENOBUFS = 105,     // No buffer space available (Quota exceeded)
  EISCONN = 106,     // Transport endpoint is already connected
  ENOTCONN = 107,    // Transport endpoint is not connected
  ETIMEDOUT = 110,   // Connection timed out (Filtered port / drop)
  ECONNREFUSED = 111,// Connection refused (Closed port / RST)
  EHOSTUNREACH = 113,// No route to host
  EALREADY = 114     // Operation already in progress
}

export interface ConnectResult {
  success: boolean;
  errno: Errno;
  message?: string;
  connectedIp?: string;
  connectedPort?: number;
  boundIp?: string;
  boundPort?: number;
}

export interface BindResult {
  success: boolean;
  errno: Errno;
  message?: string;
}

export interface AcceptResult {
  errno: Errno;
  clientFd?: number;
  clientIp?: string;
  clientPort?: number;
}

export type SocketStatus = 'INITIAL' | 'BOUND' | 'CONNECTING' | 'ESTABLISHED' | 'LISTENING' | 'CLOSED';

export interface VirtualSocketState {
  fd: number;
  ownerNodeId: string;
  family: number;
  type: number;
  boundIp?: string;
  boundPort?: number;
  connectedIp?: string;
  connectedPort?: number;
  connectedFd?: number;
  timeout: number | null; // in seconds
  status: SocketStatus;
  closed: boolean;
  backlog?: number;
  acceptQueue?: Array<{
    clientFd: number;
    clientIp: string;
    clientPort: number;
  }>;
  udpRecvQueue?: Array<{
    data: Uint8Array;
    sourceIp: string;
    sourcePort: number;
  }>;
  sendBuffer: Uint8Array[];
  recvBuffer: Uint8Array[];
}

export type ConnectionState = 'NEW' | 'ESTABLISHED' | 'CLOSED';

export interface ConntrackEntry {
  id: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: ProtocolType;
  state: ConnectionState;
  createdAtTick: number;
  lastSeenTick: number;
}

export const RESOURCE_LIMITS = {
  MAX_PAYLOAD_SIZE: 1 * 1024 * 1024,            // 1MB per single send call
  MAX_PAYLOAD_SIZE_BYTES: 1 * 1024 * 1024,      // 1MB per single send call
  MAX_SOCKET_BUFFER_SIZE: 1 * 1024 * 1024,     // 1MB queue limit per socket
  MAX_SOCKET_BUFFER_BYTES: 1 * 1024 * 1024,     // 1MB queue limit per socket
  MAX_NODE_BUFFER_SIZE: 8 * 1024 * 1024,       // 8MB aggregate queue limit across all sockets on node
  MAX_NODE_BUFFER_BYTES: 8 * 1024 * 1024,       // 8MB aggregate queue limit across all sockets on node
  MAX_SOCKETS_PER_NODE: 32,                     // Max 32 active virtual sockets per node
};

export interface SimulatorSnapshot {
  nodes: NetworkNode[];
  dnsTable: Record<string, string>;
  currentTick: number;
  missionConfig?: {
    dnsProtectionEnabled: boolean;
  };
}

