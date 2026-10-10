import { NetworkSimulator } from '../core/NetworkSimulator';
import { createDefaultTopology } from '../core/default-topology';
import { VirtualSocketBridge } from '../bridge/VirtualSocketBridge';
import { Errno } from '../core/types';

export function runBridgeTests(): { passed: number; failed: number; errors: string[] } {
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
  const bridge = new VirtualSocketBridge(sim, 'attacker-pc');

  // 1. Bridge createSocket
  const fd = bridge.createSocket(2, 1);
  assert(typeof fd === 'number' && fd > 0, 'createSocket must return a valid integer fd');

  // 2. Bridge connectSocket (Open)
  const resOpen = bridge.connectSocket(fd, '192.168.1.10', 80);
  assert(resOpen.success === true && resOpen.errno === Errno.SUCCESS, 'connectSocket on port 80 must succeed');

  // 3. Bridge send & recv
  const sent = bridge.sendSocket(fd, [71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 13, 10]);
  assert(sent === 18, 'sendSocket must return bytes count');

  const recvData = bridge.recvSocket(fd, 512);
  assert(recvData.length > 0, 'recvSocket must return Uint8Array');

  bridge.closeSocket(fd);

  // 4. Bridge DNS resolution
  const resolved = bridge.resolveDns('corp.local');
  assert(resolved === '192.168.1.10', 'resolveDns must map corp.local to 192.168.1.10');

  // 4b. DNS resolution failure (must throw error instead of returning original hostname)
  let threwDns = false;
  try {
    bridge.resolveDns('nonexistent.corp.local');
  } catch {
    threwDns = true;
  }
  assert(threwDns === true, 'resolveDns must throw error when hostname is not found');

  // 4c. DNS Poisoning Protection
  let threwPoison = false;
  try {
    bridge.addDnsRecord('corp.local', '1.2.3.4');
  } catch {
    threwPoison = true;
  }
  assert(threwPoison === true, 'addDnsRecord must prevent unauthorized overwrite of system DNS records');

  // 5. Port Validation in connectSocket
  const fdPortVal = bridge.createSocket(2, 1);
  const badPortRes = bridge.connectSocket(fdPortVal, '192.168.1.10', 99999);
  assert(badPortRes.success === false && badPortRes.errno === Errno.EINVAL, 'Port 99999 must return EINVAL');
  const badPortNaN = bridge.connectSocket(fdPortVal, '192.168.1.10', 'abc' as any);
  assert(badPortNaN.success === false && badPortNaN.errno === Errno.EINVAL, 'Port "abc" must return EINVAL');
  bridge.closeSocket(fdPortVal);

  // 6. Bridge Closed port
  const fdClosed = bridge.createSocket(2, 1);
  const resClosed = bridge.connectSocket(fdClosed, '192.168.1.10', 22);
  assert(resClosed.errno === Errno.ECONNREFUSED, 'Closed port must return errno 111');
  bridge.closeSocket(fdClosed);

  // 7. Bridge Filtered port
  const fdFiltered = bridge.createSocket(2, 1);
  const resFiltered = bridge.connectSocket(fdFiltered, '10.0.0.1', 80);
  assert(resFiltered.errno === Errno.ETIMEDOUT, 'Filtered port must return errno 110');
  bridge.closeSocket(fdFiltered);

  // 8. Node ID Validation in setNodeId
  let threwNodeId = false;
  try {
    bridge.setNodeId('nonexistent-node');
  } catch {
    threwNodeId = true;
  }
  assert(threwNodeId === true, 'setNodeId must throw error if node ID does not exist in simulator');

  // 9. bindSocket with DNS hostname resolution
  const fdBind = bridge.createSocket(2, 1);
  const bindRes = bridge.bindSocket(fdBind, 'localhost', 8088);
  assert(bindRes.success === true, 'bindSocket must resolve localhost and bind port 8088');
  bridge.closeSocket(fdBind);

  // 10. getTraceLog returns cloned copy
  const logs1 = bridge.getTraceLog();
  const count1 = logs1.length;
  if (logs1.length > 0) {
    logs1[0].reason = 'MUTATED';
  }
  const logs2 = bridge.getTraceLog();
  assert(logs2.length === count1, 'Trace log length must match');
  if (logs2.length > 0) {
    assert(logs2[0].reason !== 'MUTATED', 'Mutating returned trace log must not mutate simulator trace');
  }

  // 11. getSockName on unbound socket returns 0.0.0.0:0
  const fdUnbound = bridge.createSocket(2, 1);
  const sockNameUnbound = bridge.getSockName(fdUnbound);
  assert(sockNameUnbound?.ip === '0.0.0.0' && sockNameUnbound?.port === 0, 'Unbound socket getSockName must return 0.0.0.0:0');
  bridge.closeSocket(fdUnbound);

  // 12. bindSocket with empty string resolves to 0.0.0.0
  const fdEmptyBind = bridge.createSocket(2, 1);
  const emptyBindRes = bridge.bindSocket(fdEmptyBind, '', 8099);
  assert(emptyBindRes.success === true, 'bindSocket with empty host string must bind to 0.0.0.0');
  bridge.closeSocket(fdEmptyBind);

  // 13. sendToSocket payload size guard (1MB limit)
  const fdHuge = bridge.createSocket(2, 2);
  let threwHuge = false;
  try {
    const hugeBuf = new Uint8Array(2 * 1024 * 1024);
    bridge.sendToSocket(fdHuge, '192.168.1.10', 53, hugeBuf);
  } catch {
    threwHuge = true;
  }
  assert(threwHuge === true, 'sendToSocket must throw error when payload exceeds payload limit');
  bridge.closeSocket(fdHuge);

  // 14. Capability Token Security Check
  let threwInvalidToken = false;
  try {
    bridge.setNodeId('corp-web', 'bad-token-1234');
  } catch (err: any) {
    threwInvalidToken = true;
    assert(err.message.includes('Permission denied'), 'Invalid token must throw Permission denied');
  }
  assert(threwInvalidToken === true, 'setNodeId with invalid security token must be rejected');

  // Valid token passes
  const validToken = bridge.getSessionToken();
  let threwValidToken = false;
  try {
    bridge.setNodeId('attacker-pc', validToken);
  } catch {
    threwValidToken = true;
  }
  assert(threwValidToken === false, 'setNodeId with matching capability token must succeed');

  // 15. Mission-Configurable DNS Protection (Red Team DNS Poisoning / Hijack Mode)
  // By default, DNS protection is enabled:
  let defaultBlocked = false;
  try {
    bridge.addDnsRecord('corp.local', '10.99.99.99');
  } catch {
    defaultBlocked = true;
  }
  assert(defaultBlocked === true, 'System DNS record is protected by default');

  // For Red Team missions, disable DNS protection via mission config:
  bridge.setDnsProtectionEnabled(false);
  bridge.addDnsRecord('corp.local', '10.99.99.99');
  assert(bridge.resolveDns('corp.local') === '10.99.99.99', 'When DNS protection is disabled for mission, DNS record can be poisoned/hijacked');

  // Re-enable protection and restore
  bridge.setDnsProtectionEnabled(true);
  bridge.addDnsRecord('corp.local', '192.168.1.10', true);
  assert(bridge.resolveDns('corp.local') === '192.168.1.10', 'Restored legitimate DNS record');

  // 16. Bridge Snapshot & Restore
  const bridgeSnapshot = bridge.getSnapshot();
  assert(bridgeSnapshot.dnsTable['corp.local'] === '192.168.1.10', 'Snapshot captures DNS table');
  bridge.addDnsRecord('temp.test.local', '192.168.1.200');
  assert(bridge.resolveDns('temp.test.local') === '192.168.1.200', 'Temporary DNS record added');
  bridge.restoreSnapshot(bridgeSnapshot);
  let tempResolved = false;
  try {
    bridge.resolveDns('temp.test.local');
    tempResolved = true;
  } catch {
    tempResolved = false;
  }
  assert(tempResolved === false, 'restoreSnapshot clears uncommitted DNS records');

  return { passed, failed, errors };
}
