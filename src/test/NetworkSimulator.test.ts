import { NetworkSimulator, isInSubnet, isValidIPv4, ipToUint } from '../core/NetworkSimulator';
import { createDefaultTopology } from '../core/default-topology';
import { Errno } from '../core/types';

export function runSimulatorTests(): { passed: number; failed: number; errors: string[] } {
  const errors: string[] = [];
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, msg: string) {
    if (condition) {
      passed++;
    } else {
      failed++;
      errors.push(`Assertion failed: ${msg}`);
    }
  }

  const sim = new NetworkSimulator();
  createDefaultTopology(sim);

  // 1. Open Port Handshake Test (192.168.1.10:80)
  const fd1 = sim.createSocket('attacker-pc');
  const res1 = sim.connectSocket(fd1, '192.168.1.10', 80);
  assert(res1.success === true, 'Open port 80 must return success: true');
  assert(res1.errno === Errno.SUCCESS, 'Open port 80 must return errno: 0');

  // Verify TCP 3-way handshake in trace
  const trace1 = sim.getTraceLog();
  const last3 = trace1.slice(-3);
  assert(last3.length === 3, 'Must have 3 handshake packets in trace');
  assert(last3[0].tcpFlags?.syn === true, 'First packet must be SYN');
  assert(last3[1].tcpFlags?.syn === true && last3[1].tcpFlags?.ack === true, 'Second packet must be SYN-ACK');
  assert(last3[2].tcpFlags?.ack === true, 'Third packet must be ACK');

  // Data transmission
  const req = new TextEncoder().encode('GET / HTTP/1.1\r\n\r\n');
  const sent = sim.sendSocket(fd1, req);
  assert(sent === req.length, `Sent bytes must match (${req.length})`);
  const reply = sim.recvSocket(fd1, 1024);
  assert(reply.length > 0, 'Must receive HTTP response bytes');
  const replyStr = new TextDecoder().decode(reply);
  assert(replyStr.includes('Content-Length:'), 'Reply must include Content-Length header');
  sim.closeSocket(fd1);

  // 2. Closed Port RST Test (192.168.1.10:22)
  const fd2 = sim.createSocket('attacker-pc');
  const res2 = sim.connectSocket(fd2, '192.168.1.10', 22);
  assert(res2.success === false, 'Closed port 22 must return success: false');
  assert(res2.errno === Errno.ECONNREFUSED, 'Closed port 22 must return errno: 111 (ECONNREFUSED)');
  const trace2 = sim.getTraceLog();
  const rstPkt = trace2[trace2.length - 1];
  assert(rstPkt.tcpFlags?.rst === true, 'Closed port reply must have TCP RST flag');
  assert(rstPkt.status === 'REJECTED', 'Closed port reply must have status REJECTED');

  // 2b. State Rollback Test: Verify failed connection does NOT leave socket connected
  const sock2State = sim.getSocket(fd2);
  assert(sock2State?.status !== 'ESTABLISHED', 'Failed connection must not be marked ESTABLISHED');
  assert(sock2State?.connectedIp === undefined, 'Failed connection must not leave connectedIp');
  sim.closeSocket(fd2);

  // 3. Filtered Port Timeout Test (10.0.0.1:80)
  const fd3 = sim.createSocket('attacker-pc');
  const res3 = sim.connectSocket(fd3, '10.0.0.1', 80);
  assert(res3.success === false, 'Filtered port 80 must return success: false');
  assert(res3.errno === Errno.ETIMEDOUT, 'Filtered port 80 must return errno: 110 (ETIMEDOUT)');
  const trace3 = sim.getTraceLog();
  const dropPkt = trace3[trace3.length - 1];
  assert(dropPkt.status === 'DROPPED', 'Filtered port packet must have status DROPPED');

  // 4. Host Unreachable (172.16.99.1)
  const fd4 = sim.createSocket('attacker-pc');
  const res4 = sim.connectSocket(fd4, '172.16.99.1', 80);
  assert(res4.success === false, 'Unreachable host must return success: false');
  assert(res4.errno === Errno.EHOSTUNREACH, 'Unreachable host must return errno: 113');
  sim.closeSocket(fd4);

  // 5. First-Match Firewall Rule Logic
  sim.addNode({
    id: 'first-match-host',
    name: 'First Match Test Host',
    ip: '192.168.1.50',
    subnet: '192.168.1.0/24',
    ports: {
      80: { port: 80, state: 'OPEN' },
    },
    firewallRules: [
      { id: 'rule-permit-first', action: 'PERMIT', targetPort: 80, protocol: 'TCP' },
      { id: 'rule-deny-second', action: 'DENY_DROP', targetPort: 80, protocol: 'TCP' },
    ],
  });
  const fdFw = sim.createSocket('attacker-pc');
  const resFw = sim.connectSocket(fdFw, '192.168.1.50', 80);
  assert(resFw.success === true, 'First-match firewall rule must allow traffic when PERMIT is first');
  sim.closeSocket(fdFw);

  // 6. EADDRINUSE on Duplicate Bind
  const fdBind1 = sim.createSocket('attacker-pc');
  const bindRes1 = sim.bindSocket(fdBind1, '192.168.1.5', 9000);
  assert(bindRes1.success === true, 'First bind on port 9000 must succeed');

  const fdBind2 = sim.createSocket('attacker-pc');
  const bindRes2 = sim.bindSocket(fdBind2, '192.168.1.5', 9000);
  assert(bindRes2.success === false, 'Duplicate bind on port 9000 must fail');
  assert(bindRes2.errno === Errno.EADDRINUSE, 'Duplicate bind must return EADDRINUSE (98)');
  sim.closeSocket(fdBind1);
  sim.closeSocket(fdBind2);

  // 7. Strict IP and Subnet Validation
  assert(isValidIPv4('192.168.1.1') === true, '192.168.1.1 is valid IPv4');
  assert(isValidIPv4('999.1.1.1') === false, '999.1.1.1 is invalid IPv4');
  assert(isValidIPv4('192.168.01.1') === false, 'Leading zero in IPv4 is invalid');
  assert(isValidIPv4('abc.def.ghi.jkl') === false, 'Non-digits in IPv4 is invalid');
  assert(ipToUint('999.999.999.999') === null, 'ipToUint returns null for invalid IP');
  assert(isInSubnet('192.168.1.5', '192.168.1.0/24') === true, '192.168.1.5 is in 192.168.1.0/24');
  assert(isInSubnet('192.168.2.5', '192.168.1.0/24') === false, '192.168.2.5 is not in 192.168.1.0/24');
  assert(isInSubnet('invalid', '192.168.1.0/24') === false, 'Invalid IP is not in subnet');

  // 8. Negative/Zero guards
  const fdGuard = sim.createSocket('attacker-pc');
  const emptyRecv = sim.recvSocket(fdGuard, -5);
  assert(emptyRecv.length === 0, 'recvSocket with negative maxBytes returns empty');
  const tickBefore = sim.getTick();
  sim.tick(-10);
  assert(sim.getTick() === tickBefore, 'tick with negative count must not rewind time');
  sim.closeSocket(fdGuard);

  // 9. UDP Support (sendToSocket / recvFromSocket) with Sender Preservation
  const fdUdpServer = sim.createSocket('corp-web', 2, 2);
  sim.bindSocket(fdUdpServer, '192.168.1.10', 5353);

  const fdUdpClient = sim.createSocket('attacker-pc', 2, 2);
  const udpData = new Uint8Array([1, 2, 3, 4]);
  const udpSent = sim.sendToSocket(fdUdpClient, '192.168.1.10', 5353, udpData);
  assert(udpSent === 4, 'UDP sendToSocket must send datagram');

  const udpRecv = sim.recvFromSocket(fdUdpServer, 1024);
  assert(udpRecv !== null, 'recvFromSocket must receive sent datagram');
  assert(Boolean(udpRecv && udpRecv.data.length === 4), 'recvFromSocket data length must match');
  assert(Boolean(udpRecv && udpRecv.ip === '192.168.1.5'), 'recvFromSocket must preserve sender IP');
  assert(Boolean(udpRecv && udpRecv.port > 0), 'recvFromSocket must preserve sender port');

  sim.closeSocket(fdUdpClient);
  sim.closeSocket(fdUdpServer);

  // 10. Dynamic Server Socket Listen & Accept Test
  const fdServer = sim.createSocket('corp-web');
  const bindSrv = sim.bindSocket(fdServer, '192.168.1.10', 8888);
  assert(bindSrv.success === true, 'Server socket bind on 8888 succeeds');
  sim.listenSocket(fdServer, 2);

  // Empty accept before connection returns EAGAIN
  const emptyAccept = sim.acceptSocket(fdServer);
  assert(emptyAccept.errno === Errno.EAGAIN, 'acceptSocket on empty queue returns EAGAIN');

  // Client connects to listening socket
  const fdCli = sim.createSocket('attacker-pc');
  const connSrv = sim.connectSocket(fdCli, '192.168.1.10', 8888);
  assert(connSrv.success === true && connSrv.errno === Errno.SUCCESS, 'Client connects to dynamic listening socket');

  // Server accepts connection
  const acceptRes = sim.acceptSocket(fdServer);
  assert(acceptRes.errno === Errno.SUCCESS, 'acceptSocket returns SUCCESS');
  assert(typeof acceptRes.clientFd === 'number' && acceptRes.clientFd > 0, 'acceptSocket returns valid clientFd');
  assert(acceptRes.clientIp === '192.168.1.5', 'acceptSocket returns client IP');

  // Bidirectional communication between client and accepted server client
  const clientPayload = new TextEncoder().encode('PING');
  sim.sendSocket(fdCli, clientPayload);
  const serverReceived = sim.recvSocket(acceptRes.clientFd!, 100);
  assert(new TextDecoder().decode(serverReceived) === 'PING', 'Accepted server socket receives client data');

  const serverReply = new TextEncoder().encode('PONG');
  sim.sendSocket(acceptRes.clientFd!, serverReply);
  const clientReceived = sim.recvSocket(fdCli, 100);
  assert(new TextDecoder().decode(clientReceived) === 'PONG', 'Client socket receives server reply');

  sim.closeSocket(fdCli);
  sim.closeSocket(acceptRes.clientFd!);
  sim.closeSocket(fdServer);

  // 11. Stateful Connection Tracking Test
  // Outbound connection to port 80 creates conntrack entry.
  // Bidirectional packets pass without requiring explicit inbound reverse firewall rule.
  const fdStateful = sim.createSocket('attacker-pc');
  const connStateful = sim.connectSocket(fdStateful, '192.168.1.10', 80);
  assert(connStateful.success === true, 'Stateful connection to port 80 succeeds');
  const sockState = sim.getSocket(fdStateful);
  assert(
    sim.isConntrackEstablished(sockState?.boundIp!, sockState?.boundPort!, '192.168.1.10', 80, 'TCP'),
    'Connection must be tracked as ESTABLISHED in conntrack table'
  );
  sim.closeSocket(fdStateful);
  assert(
    !sim.isConntrackEstablished(sockState?.boundIp!, sockState?.boundPort!, '192.168.1.10', 80, 'TCP'),
    'Closing socket removes connection from conntrack table'
  );

  // 12. Cisco Interface ACL Binding & Implicit Deny Test
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
        implicitDeny: true, // Cisco ACL standard: implicit deny any at end
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

  // Explicitly permitted port 80 connects
  const fdIfacePermit = sim.createSocket('attacker-pc');
  const permitRes = sim.connectSocket(fdIfacePermit, '10.50.1.1', 80);
  assert(permitRes.success === true, 'Interface ACL permitted rule allows port 80');
  sim.closeSocket(fdIfacePermit);

  // Unlisted port 8080 hits Cisco Implicit Deny -> Dropped (ETIMEDOUT)
  const fdIfaceDeny = sim.createSocket('attacker-pc');
  const denyRes = sim.connectSocket(fdIfaceDeny, '10.50.1.1', 8080);
  assert(denyRes.success === false && denyRes.errno === Errno.ETIMEDOUT, 'Cisco Interface ACL Implicit Deny drops unlisted port 8080');
  sim.closeSocket(fdIfaceDeny);

  // 13. Resource Quotas & Limits Test
  // 13a: Max Sockets Per Node (Limit 32)
  const socketHandles: number[] = [];
  let emfileThrown = false;
  try {
    for (let i = 0; i < 40; i++) {
      socketHandles.push(sim.createSocket('attacker-pc'));
    }
  } catch (err: any) {
    emfileThrown = true;
    assert(err.message.includes('EMFILE') || err.message.includes('limit'), 'Socket quota error must mention EMFILE or limit');
  }
  assert(emfileThrown === true, 'Creating more than 32 sockets on a single node must throw EMFILE error');
  for (const h of socketHandles) {
    sim.closeSocket(h);
  }

  // 13b: Max Payload Size per send (1MB limit)
  const fdPayload = sim.createSocket('attacker-pc');
  sim.connectSocket(fdPayload, '192.168.1.10', 80);
  let payloadExceeded = false;
  try {
    const oversized = new Uint8Array(2 * 1024 * 1024); // 2MB > 1MB
    sim.sendSocket(fdPayload, oversized);
  } catch (err: any) {
    payloadExceeded = true;
    assert(err.message.includes('exceeds maximum allowed'), 'Oversized payload throws maximum allowed error');
  }
  assert(payloadExceeded === true, 'Sending payload exceeding 1MB must be rejected');
  sim.closeSocket(fdPayload);

  // 14. Simulator Snapshot & Restore Test
  const snapshotBefore = sim.getSnapshot();
  assert(snapshotBefore.nodes.length >= 3, 'Snapshot must serialize current network nodes');

  // Add a temporary node, verify snapshot restore can revert or preserve
  sim.addNode({
    id: 'ephemeral-node',
    name: 'Ephemeral Testing Box',
    ip: '172.20.0.99',
    subnet: '172.20.0.0/24',
    ports: {},
  });
  assert(sim.getNode('ephemeral-node') !== undefined, 'Ephemeral node was added');

  // Restore snapshot from before ephemeral node
  sim.restoreSnapshot(snapshotBefore);
  assert(sim.getNode('ephemeral-node') === undefined, 'restoreSnapshot restores previous topology and clears added node');
  assert(sim.getNode('attacker-pc') !== undefined, 'restoreSnapshot preserved attacker-pc node');
  assert(sim.getNode('corp-web') !== undefined, 'restoreSnapshot preserved corp-web node');

  return { passed, failed, errors };
}
