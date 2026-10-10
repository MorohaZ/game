import { NetworkSimulator } from './NetworkSimulator';
import { NetworkNode } from './types';

export function createDefaultTopology(sim: NetworkSimulator): void {
  // 1. Attacker / Player Station
  const attackerNode: NetworkNode = {
    id: 'attacker-pc',
    name: 'Kali Workstation (Player)',
    ip: '192.168.1.5',
    subnet: '192.168.1.0/24',
    defaultGateway: '192.168.1.1',
    ports: {},
  };

  // 2. Corporate Web Server
  // Port 80 is OPEN (HTTP server)
  // Port 22 is CLOSED (SSH daemon stopped -> returns TCP RST)
  const corpWebNode: NetworkNode = {
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
        responseHandler: (reqData: Uint8Array) => {
          // Payload validation guard
          if (!reqData || reqData.length === 0 || reqData.length > 1024 * 1024) {
            return new Uint8Array(0);
          }
          try {
            // Safe UTF-8 decode
            new TextDecoder('utf-8', { fatal: false }).decode(reqData);
          } catch {
            return new Uint8Array(0);
          }
          const body = JSON.stringify({
            status: 'online',
            service: 'Corporate Intranet Portal',
            protocol: 'Zero-Day Protocol v1.0',
          });
          const bodyBytes = new TextEncoder().encode(body);
          const response =
            `HTTP/1.1 200 OK\r\n` +
            `Content-Type: application/json\r\n` +
            `Content-Length: ${bodyBytes.length}\r\n` +
            `Connection: close\r\n\r\n` +
            body;
          return new TextEncoder().encode(response);
        },
      },
      22: {
        port: 22,
        state: 'CLOSED',
        service: 'ssh',
      },
    },
  };

  // 3. Firewalled Host (External / DMZ)
  // Port 80 and 443 are FILTERED (Firewall silently drops TCP SYN packets -> Timeout)
  const firewalledHost: NetworkNode = {
    id: 'firewalled-host',
    name: 'Perimeter Protected Host',
    ip: '10.0.0.1',
    subnet: '10.0.0.0/24',
    defaultGateway: '10.0.0.254',
    ports: {
      80: {
        port: 80,
        state: 'FILTERED',
        service: 'http-filtered',
      },
      443: {
        port: 443,
        state: 'FILTERED',
        service: 'https-filtered',
      },
    },
    firewallRules: [
      {
        id: 'fw-drop-all-80',
        action: 'DENY_DROP',
        targetPort: 80,
        protocol: 'TCP',
        description: 'Drop all inbound TCP 80 traffic (Stealth mode)',
      },
      {
        id: 'fw-drop-all-443',
        action: 'DENY_DROP',
        targetPort: 443,
        protocol: 'TCP',
        description: 'Drop all inbound TCP 443 traffic (Stealth mode)',
      },
    ],
  };

  sim.addNode(attackerNode);
  sim.addNode(corpWebNode);
  sim.addNode(firewalledHost);
}
