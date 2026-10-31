import test from 'node:test';
import assert from 'node:assert/strict';
import {
  COMMON_SENSITIVE_PORTS,
  canonicalizeIp,
  isValidIpv4,
  isValidIpv6,
  isPrivateOrLocalAddress,
  isGloballyRoutablePublicIp,
  isSafeExternalUrl,
  formatTestStatusLabelFa,
  isValidGeoCoordinate,
  resolveGlobeVisualStatus,
  parseIceCandidateLine,
  evaluateWebRtcCandidates,
  evaluateDnsTestResult,
  evaluateIndependentBrowserDnsObservation,
  evaluateVpnHeuristic,
  calculateHttpPingMetrics,
  evaluatePortLeakResult,
  evaluateOverallSummary,
  evaluateObservedIpSources,
  isValidDnsObservationRecord,
  isValidDnsRunId,
  isValidDnsLeakBaseDomain,
  buildDnsLeakProbeQname,
  parseDnsLeakProbeQname,
  validateAiAuditPayload
} from './networkEvaluator';
import { createBoundedSignal } from '../services/networkTester';
import * as THREE from 'three';
import {
  latLonToVector3,
  createGlobeResourceManager,
  initGlobeWebGLSafe,
} from '../components/Globe3D';
import cloudflareWorker, { type Env as CloudflareEnv } from '../../cloudflare/worker';
// @ts-ignore
import { extractRunIdFromQname, parseDnsLeakQname, evaluateDnsQueryPacket } from '../../cloudflare/authoritative-dns-udp53.mjs';

test('IP validation and RFC1918/mDNS private address classification', () => {
  assert.equal(isValidIpv4('1.1.1.1'), true);
  assert.equal(isValidIpv4('999.1.1.1'), false);
  assert.equal(isValidIpv6('2001:4860:4860::8888'), true);

  assert.equal(isPrivateOrLocalAddress('192.168.1.50'), true);
  assert.equal(isPrivateOrLocalAddress('10.0.0.1'), true);
  assert.equal(isPrivateOrLocalAddress('172.16.5.4'), true);
  assert.equal(isPrivateOrLocalAddress('172.32.0.1'), false);
  assert.equal(isPrivateOrLocalAddress('a1b2c3d4.local'), true);
  assert.equal(isPrivateOrLocalAddress('8.8.8.8'), false);
});

test('parseIceCandidateLine accurately extracts host, srflx, relay, IPv6, and mDNS candidates', () => {
  const hostCand = parseIceCandidateLine(
    'candidate:1 1 UDP 2122252543 192.168.1.25 54321 typ host'
  );
  assert.ok(hostCand);
  assert.equal(hostCand.ip, '192.168.1.25');
  assert.equal(hostCand.type, 'host');
  assert.equal(hostCand.isLocalLanIp, true);
  assert.equal(hostCand.isPublicIp, false);

  const srflxCand = parseIceCandidateLine(
    'candidate:2 1 udp 1686052607 203.0.113.45 61234 typ srflx raddr 192.168.1.25 rport 54321'
  );
  assert.ok(srflxCand);
  assert.equal(srflxCand.ip, '203.0.113.45');
  assert.equal(srflxCand.type, 'srflx');
  assert.equal(srflxCand.isLocalLanIp, false);
  assert.equal(srflxCand.isPublicIp, true);

  const relayCand = parseIceCandidateLine(
    'candidate:4 1 udp 41885439 198.51.100.200 59000 typ relay raddr 203.0.113.45 rport 61234'
  );
  assert.ok(relayCand);
  assert.equal(relayCand.type, 'relay');
  assert.equal(relayCand.isPublicIp, true);

  const mdnsCand = parseIceCandidateLine(
    'candidate:3 1 udp 2122260223 4f9a2b1c-8812-4c11-9b00.local 55111 typ host'
  );
  assert.ok(mdnsCand);
  assert.equal(mdnsCand.version, 'mDNS');
  assert.equal(mdnsCand.isLocalLanIp, true);
  assert.equal(mdnsCand.isPublicIp, false);

  assert.equal(parseIceCandidateLine('invalid candidate line'), null);
});

test('evaluateWebRtcCandidates never converts missing STUN candidates or errors into PASS', () => {
  const now = new Date().toISOString();

  // Case 1: WebRTC unsupported
  const unsupported = evaluateWebRtcCandidates({
    isSupported: false,
    candidates: [],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(unsupported.status, 'UNSUPPORTED');
  assert.equal(unsupported.isLeakingRealIp, null);
  assert.equal(unsupported.localIps.length, 0); // No fake 192.168.1.105!

  // Case 2: WebRTC supported, but 0 public STUN candidates gathered (timeout/UDP blocked)
  const noStun = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(noStun.status, 'INCONCLUSIVE');
  assert.equal(noStun.isLeakingRealIp, null);
  assert.equal(noStun.localIps.length, 0);

  // Case 3: Real IP Leak (STUN returns different public IP than reference VPN IP)
  const leaked = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [
      {
        ip: '203.0.113.99',
        version: 'IPv4',
        type: 'srflx',
        protocol: 'UDP',
        port: 51000,
        isLocalLanIp: false,
        isPublicIp: true,
      },
    ],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(leaked.status, 'LEAK_DETECTED');
  assert.equal(leaked.isLeakingRealIp, true);
  assert.equal(leaked.confidence, 'high');

  // Case 4: Verified PASS (STUN returns exact same public IP as reference IP)
  const verifiedPass = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [
      {
        ip: '198.51.100.10',
        version: 'IPv4',
        type: 'srflx',
        protocol: 'UDP',
        port: 51000,
        isLocalLanIp: false,
        isPublicIp: true,
      },
    ],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(verifiedPass.status, 'PASS');
  assert.equal(verifiedPass.isLeakingRealIp, false);
});

test('evaluateDnsTestResult marks unconfigured authoritative DNS as NOT_CONFIGURED and detects ISP leak when configured', () => {
  const now = new Date().toISOString();

  const unconfigured = evaluateDnsTestResult({
    runId: 'test-token-1234',
    authoritativeConfigured: false,
    resolvers: [],
    ipDetails: null,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(unconfigured.status, 'NOT_CONFIGURED');
  assert.equal(unconfigured.isLeaking, null);

  const failed = evaluateDnsTestResult({
    runId: 'test-token-1234',
    authoritativeConfigured: true,
    resolvers: [],
    ipDetails: null,
    startedAt: now,
    completedAt: now,
    errorMessage: 'Timeout reaching collector',
  });
  assert.equal(failed.status, 'ERROR');
  assert.equal(failed.isLeaking, null);

  // Authoritative DNS configured, VPN active in DE, but DNS resolver reports leak/mismatch
  const vpnIpDetails: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    countryCode: 'DE',
    asn: 'AS24940',
    isDatacenter: true,
  };
  const leakedDns = evaluateDnsTestResult({
    runId: 'test-token-5678',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'res-1',
        name: 'Iran Telecommunication Company PJS',
        primaryIp: '91.98.0.1',
        asn: 'AS58224',
        isp: 'TCI',
        location: 'IR',
        runId: 'test-token-5678',
        queryName: 'p1.test-token-5678.leak.example.com',
        observedAt: now,
        status: 'مغایرت کشور با تونل (Leak)',
        responseTimeMs: 32,
        isEncryptedDoH: false,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: vpnIpDetails,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(leakedDns.status, 'LEAK_DETECTED');
  assert.equal(leakedDns.isLeaking, true);
});

test('evaluateVpnHeuristic reports probabilistic ASN classification and never fabricates tunnel protocols', () => {
  const now = new Date().toISOString();
  const dnsPass: any = { status: 'PASS', isLeaking: false };

  const datacenterIp: any = {
    status: 'PASS',
    ip: '138.201.0.1',
    isp: 'Hetzner Online GmbH',
    asn: 'AS24940',
    isDatacenter: true,
    isVpnOrProxyDetected: true,
    ipMismatchDetected: false,
    startedAt: now,
    completedAt: now,
  };

  const vpnRes = evaluateVpnHeuristic(datacenterIp, dnsPass);
  // Datacenter IP classification is separated from tunnel leak status:
  // isDatacenterIp is true (probabilistic ASN classification), while browser tunnel verification status is INCONCLUSIVE (never automatic PASS)
  assert.equal(vpnRes.status, 'INCONCLUSIVE');
  assert.equal(vpnRes.isDatacenterIp, true);
  assert.equal(vpnRes.isKnownProxy, null);
  assert.equal(vpnRes.confidence, 'medium');
  assert.equal(vpnRes.protocolDetails.isProvableFromBrowser, false);
  assert.equal(vpnRes.protocolDetails.code, 'unknown_protocol');

  const missingIp = evaluateVpnHeuristic(null, null);
  assert.equal(missingIp.status, 'INCONCLUSIVE');
  assert.equal(missingIp.isDatacenterIp, null);
  assert.equal(missingIp.confidence, 'none');
});

test('calculateHttpPingMetrics computes real packet loss and returns ERROR when all probes fail', () => {
  const now = new Date().toISOString();

  const allFailed = calculateHttpPingMetrics({
    rttSamplesMs: [],
    probesSent: 8,
    probesReceived: 0,
    downloadMbps: null,
    bytesTransferred: 0,
    durationMs: 0,
    startedAt: now,
    completedAt: now,
    errorMessage: 'Network offline',
  });
  assert.equal(allFailed.status, 'ERROR');
  assert.equal(allFailed.pingMs, null);
  assert.equal(allFailed.packetLossPercent, 100);

  const partialLoss = calculateHttpPingMetrics({
    rttSamplesMs: [40, 50, 45, 55],
    probesSent: 5,
    probesReceived: 4,
    downloadMbps: 12.4,
    bytesTransferred: 1024 * 1024,
    durationMs: 670,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(partialLoss.status, 'PASS');
  assert.equal(partialLoss.pingMs, 48);
  assert.equal(partialLoss.packetLossPercent, 20);
  assert.equal(partialLoss.jitterMs, 8.3);
});

test('evaluateOverallSummary refuses to compute a numeric score when evidence is incomplete, and computes accurately when complete', () => {
  const now = new Date().toISOString();

  const unconfiguredDns = evaluateDnsTestResult({
    runId: 'run-test-0001',
    authoritativeConfigured: false,
    resolvers: [],
    ipDetails: null,
    startedAt: now,
    completedAt: now,
  });

  const webRtcPass = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [
      {
        ip: '198.51.100.10',
        version: 'IPv4',
        type: 'srflx',
        protocol: 'UDP',
        port: 50000,
        isLocalLanIp: false,
        isPublicIp: true,
      },
    ],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });

  const mockIpDetails: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    ipMismatchDetected: false,
    isDatacenter: true,
    fraudRiskScore: null,
  };

  // Incomplete because Authoritative DNS is NOT_CONFIGURED
  const incompleteSummary = evaluateOverallSummary({
    ipDetails: mockIpDetails,
    dnsLeak: unconfiguredDns,
    webRtcLeak: webRtcPass,
    vpnProxy: evaluateVpnHeuristic(mockIpDetails, unconfiguredDns),
  });

  assert.equal(incompleteSummary.isScoreCalculable, false);
  assert.equal(incompleteSummary.privacyScore, null);
  assert.equal(incompleteSummary.overallStatus, 'INCONCLUSIVE');

  // Complete when Authoritative DNS is configured and returns verified resolvers
  const configuredDns = evaluateDnsTestResult({
    runId: 'run-test-0002',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'cf-1',
        name: 'Cloudflare',
        primaryIp: '1.1.1.1',
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.',
        location: 'Anycast',
        runId: 'run-test-0002',
        queryName: 'p1.run-test-0002.leak.example.com',
        observedAt: now,
        status: 'مشاهده‌شده در Authoritative DNS',
        responseTimeMs: 12,
        isEncryptedDoH: true,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: mockIpDetails,
    startedAt: now,
    completedAt: now,
  });

  const completeSummary = evaluateOverallSummary({
    ipDetails: mockIpDetails,
    dnsLeak: configuredDns,
    webRtcLeak: webRtcPass,
    vpnProxy: evaluateVpnHeuristic(mockIpDetails, configuredDns),
  });

  assert.equal(completeSummary.isScoreCalculable, true);
  assert.equal(completeSummary.privacyScore, 100);
  assert.equal(completeSummary.overallStatus, 'PASS');
});

test('evaluateIndependentBrowserDnsObservation stays strictly separate from Authoritative DNS status', () => {
  const now = new Date().toISOString();
  const mockIpDetails: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    countryCode: 'DE',
    countryName: 'Germany',
  };

  const emptyObs = evaluateIndependentBrowserDnsObservation([], mockIpDetails);
  assert.equal(emptyObs.status, 'INCONCLUSIVE');
  assert.equal(emptyObs.matchesPrimaryEgressIp, null);

  // Observing a single recursive resolver in the browser does not prove absence of DNS leak (status: INCONCLUSIVE)
  // and does not compare a resolver IP as an egress IP (matchesPrimaryEgressIp: null)
  const validBrowserObs = evaluateIndependentBrowserDnsObservation(
    [
      {
        sourceName: 'ip-api EDNS Recursive Resolver',
        observedIp: '172.64.36.1',
        locationOrGeo: 'Germany - Cloudflare',
        role: 'edns_recursive_resolver',
        responseTimeMs: 42,
      },
    ],
    mockIpDetails
  );
  assert.equal(validBrowserObs.status, 'INCONCLUSIVE');
  assert.equal(validBrowserObs.matchesPrimaryEgressIp, null);

  // Even when independent browser observation is present, Authoritative DNS without env vars MUST remain NOT_CONFIGURED
  const dnsResult = evaluateDnsTestResult({
    runId: 'token-abc',
    authoritativeConfigured: false,
    missingEnvVars: ['DNS_LEAK_DOMAIN', 'DNS_COLLECTOR_API_URL', 'DNS_COLLECTOR_API_TOKEN'],
    resolvers: [],
    ipDetails: mockIpDetails,
    independentBrowserObservation: validBrowserObs,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(dnsResult.status, 'NOT_CONFIGURED');
  assert.equal(dnsResult.isLeaking, null);
  assert.equal(dnsResult.independentBrowserObservation?.status, 'INCONCLUSIVE');
  assert.deepEqual(dnsResult.missingEnvVars, [
    'DNS_LEAK_DOMAIN',
    'DNS_COLLECTOR_API_URL',
    'DNS_COLLECTOR_API_TOKEN',
  ]);
});

test('evaluatePortLeakResult accurately classifies local unverifiable sockets, open ports, and closed ports', () => {
  const now = new Date().toISOString();

  // 1. Local socket -> INCONCLUSIVE (never fake PASS)
  const localRes = evaluatePortLeakResult({
    targetIp: '127.0.0.1',
    targetSource: 'unverifiable_local_socket',
    canScanFromServer: false,
    ports: [],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(localRes.status, 'INCONCLUSIVE');
  assert.equal(localRes.isExposingSensitivePorts, null);

  // 2. Public IP with critical open port 8291 -> LEAK_DETECTED
  const openPortRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: [
      {
        port: 8291,
        protocol: 'TCP',
        serviceName: 'TCP/8291 (MikroTik Winbox Candidate)',
        category: 'router_admin',
        descriptionFa: 'Winbox',
        descriptionEn: 'Winbox',
        state: 'open',
        responseTimeMs: 18,
        riskLevel: 'critical',
      },
      {
        port: 80,
        protocol: 'TCP',
        serviceName: 'HTTP Web / TCP-80 Service',
        category: 'router_admin',
        descriptionFa: 'HTTP',
        descriptionEn: 'HTTP',
        state: 'closed',
        responseTimeMs: 15,
        riskLevel: 'high',
      },
    ],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(openPortRes.status, 'LEAK_DETECTED');
  assert.equal(openPortRes.isExposingSensitivePorts, true);
  assert.equal(openPortRes.confidence, 'medium');
  assert.deepEqual(openPortRes.openPorts, [8291]);

  // 3. Public IP with ALL expected ports in COMMON_SENSITIVE_PORTS closed/filtered -> PASS
  const allClosedPorts = COMMON_SENSITIVE_PORTS.map((def, idx) => ({
    ...def,
    state: (idx % 2 === 0 ? 'closed' : 'filtered_timeout') as 'closed' | 'filtered_timeout',
    responseTimeMs: idx % 2 === 0 ? 14 : null,
  }));
  const closedPortRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: allClosedPorts,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(closedPortRes.status, 'PASS');
  assert.equal(closedPortRes.isExposingSensitivePorts, false);
  assert.equal(closedPortRes.scannedPortsCount, COMMON_SENSITIVE_PORTS.length);
});

test('isGloballyRoutablePublicIp blocks all loopback, RFC1918, CGNAT, metadata, IPv4-mapped IPv6, and TEST-NET ranges against SSRF', () => {
  // Blocked IPv4 ranges
  assert.equal(isGloballyRoutablePublicIp('127.0.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('127.0.0.2'), false);
  assert.equal(isGloballyRoutablePublicIp('127.255.255.254'), false);
  assert.equal(isGloballyRoutablePublicIp('0.0.0.0'), false);
  assert.equal(isGloballyRoutablePublicIp('10.0.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('100.64.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('169.254.169.254'), false);
  assert.equal(isGloballyRoutablePublicIp('172.16.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('172.31.255.255'), false);
  assert.equal(isGloballyRoutablePublicIp('192.168.1.1'), false);
  assert.equal(isGloballyRoutablePublicIp('192.0.2.1'), false);
  assert.equal(isGloballyRoutablePublicIp('198.51.100.1'), false);
  assert.equal(isGloballyRoutablePublicIp('203.0.113.1'), false);
  assert.equal(isGloballyRoutablePublicIp('224.0.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('255.255.255.255'), false);

  // Blocked IPv6 and IPv4-mapped IPv6 ranges
  assert.equal(isGloballyRoutablePublicIp('::1'), false);
  assert.equal(isGloballyRoutablePublicIp('::'), false);
  assert.equal(isGloballyRoutablePublicIp('::ffff:127.0.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('::ffff:169.254.169.254'), false);
  assert.equal(isGloballyRoutablePublicIp('::ffff:10.0.0.1'), false);
  assert.equal(isGloballyRoutablePublicIp('fe80::1'), false);
  assert.equal(isGloballyRoutablePublicIp('fc00::1'), false);
  assert.equal(isGloballyRoutablePublicIp('fd12:3456:789a::1'), false);
  assert.equal(isGloballyRoutablePublicIp('ff02::1'), false);
  assert.equal(isGloballyRoutablePublicIp('2001:db8::1'), false);
  assert.equal(isGloballyRoutablePublicIp('localhost'), false);
  assert.equal(isGloballyRoutablePublicIp(''), false);

  // Allowed globally routable public IPs
  assert.equal(isGloballyRoutablePublicIp('8.8.8.8'), true);
  assert.equal(isGloballyRoutablePublicIp('1.1.1.1'), true);
  assert.equal(isGloballyRoutablePublicIp('172.32.0.1'), true);
  assert.equal(isGloballyRoutablePublicIp('2606:4700:4700::1111'), true);
  assert.equal(isGloballyRoutablePublicIp('::ffff:8.8.8.8'), true);
});

test('formatTestStatusLabelFa translates all status enums into distinct Persian labels', () => {
  assert.equal(formatTestStatusLabelFa('PASS'), 'موفق');
  assert.equal(formatTestStatusLabelFa('LEAK_DETECTED'), 'نشت شناسایی شد');
  assert.equal(formatTestStatusLabelFa('INCONCLUSIVE'), 'نامشخص');
  assert.equal(formatTestStatusLabelFa('NOT_CONFIGURED'), 'پیکربندی نشده');
  assert.equal(formatTestStatusLabelFa('UNSUPPORTED'), 'پشتیبانی نشده');
  assert.equal(formatTestStatusLabelFa('ERROR'), 'خطا در آزمون');
  assert.equal(formatTestStatusLabelFa(null), 'نامشخص');
});

test('isValidGeoCoordinate strictly validates finite latitude [-90, 90] and longitude [-180, 180]', () => {
  assert.equal(isValidGeoCoordinate(35.6892, 51.389), true);
  assert.equal(isValidGeoCoordinate(-90, -180), true);
  assert.equal(isValidGeoCoordinate(90, 180), true);
  assert.equal(isValidGeoCoordinate(0, 0), true);

  // Out of bounds
  assert.equal(isValidGeoCoordinate(90.001, 0), false);
  assert.equal(isValidGeoCoordinate(-91, 0), false);
  assert.equal(isValidGeoCoordinate(0, 180.001), false);
  assert.equal(isValidGeoCoordinate(0, -181), false);

  // Non-finite or non-numeric
  assert.equal(isValidGeoCoordinate(Number.NaN, 50), false);
  assert.equal(isValidGeoCoordinate(35, Number.POSITIVE_INFINITY), false);
  assert.equal(isValidGeoCoordinate(Number.NEGATIVE_INFINITY, 10), false);
  assert.equal(isValidGeoCoordinate(null, 51), false);
  assert.equal(isValidGeoCoordinate(undefined, undefined), false);
  assert.equal(isValidGeoCoordinate('35.68', '51.38'), false);
});

test('resolveGlobeVisualStatus separates PASS, LEAK_DETECTED, ERROR, and inconclusive states without false PASS', () => {
  const validIp = { status: 'PASS' as const, ip: '8.8.8.8' };
  const errorIp = { status: 'ERROR' as const, ip: null };

  // 1. ERROR must not be marked as LEAK_DETECTED and must show exact Persian message
  const errState = resolveGlobeVisualStatus('ERROR', errorIp);
  assert.equal(errState.visualCategory, 'error');
  assert.equal(errState.isError, true);
  assert.equal(errState.isLeak, false);
  assert.equal(errState.isPass, false);
  assert.equal(errState.badgeTextFa, 'خطا در اجرای تست؛ نتیجه قابل تأیید نیست');

  // 2. LEAK_DETECTED
  const leakState = resolveGlobeVisualStatus('LEAK_DETECTED', validIp);
  assert.equal(leakState.visualCategory, 'leak');
  assert.equal(leakState.isLeak, true);
  assert.equal(leakState.isError, false);
  assert.equal(leakState.isPass, false);

  // 3. PASS only when overallStatus is PASS AND ipDetails is valid PASS
  const passState = resolveGlobeVisualStatus('PASS', validIp);
  assert.equal(passState.visualCategory, 'pass');
  assert.equal(passState.isPass, true);
  assert.equal(passState.isLeak, false);
  assert.equal(passState.isError, false);

  // 4. Incomplete/invalid ipDetails with PASS overallStatus must NOT become PASS
  const fakePassNullIp = resolveGlobeVisualStatus('PASS', null);
  assert.equal(fakePassNullIp.visualCategory, 'inconclusive');
  assert.equal(fakePassNullIp.isPass, false);

  const fakePassErrorIp = resolveGlobeVisualStatus('PASS', errorIp);
  assert.equal(fakePassErrorIp.visualCategory, 'inconclusive');
  assert.equal(fakePassErrorIp.isPass, false);

  // 5. INCONCLUSIVE and NOT_CONFIGURED
  const incState = resolveGlobeVisualStatus('INCONCLUSIVE', validIp);
  assert.equal(incState.visualCategory, 'inconclusive');
  assert.equal(incState.isPass, false);
  assert.equal(incState.isLeak, false);
  assert.equal(incState.isError, false);
});

test('latLonToVector3 returns null for invalid coordinates and finite 3D vectors for valid coordinates', () => {
  assert.equal(latLonToVector3(Number.NaN, 51.38, 2.25), null);
  assert.equal(latLonToVector3(35.68, Number.POSITIVE_INFINITY, 2.25), null);
  assert.equal(latLonToVector3(95, 10, 2.25), null);
  assert.equal(latLonToVector3(-95, 10, 2.25), null);
  assert.equal(latLonToVector3(10, 185, 2.25), null);
  assert.equal(latLonToVector3(10, -185, 2.25), null);
  assert.equal(latLonToVector3(null, null, 2.25), null);
  assert.equal(latLonToVector3(35.68, 51.38, 0), null);
  assert.equal(latLonToVector3(35.68, 51.38, -2), null);

  const vec = latLonToVector3(35.6892, 51.389, 2.25);
  assert.ok(vec instanceof THREE.Vector3);
  assert.ok(Number.isFinite(vec.x) && Number.isFinite(vec.y) && Number.isFinite(vec.z));
  assert.ok(Math.abs(vec.length() - 2.25) < 1e-6);
});

test('initGlobeWebGLSafe handles WebGL context failure and renderer creation errors gracefully', () => {
  // Case 1: WebGL context probe returns null
  const noGlResult = initGlobeWebGLSafe({
    probeContext: () => null,
  });
  assert.equal(noGlResult.renderer, null);
  assert.equal(noGlResult.webglUnavailable, true);

  // Case 2: WebGLRenderer constructor throws GPU error
  const throwResult = initGlobeWebGLSafe({
    probeContext: () => ({ gl: {} as WebGLRenderingContext, gpuRenderer: 'NVIDIA RTX' }),
    createRenderer: () => {
      throw new Error('Failed to create WebGL context');
    },
  });
  assert.equal(throwResult.renderer, null);
  assert.equal(throwResult.webglUnavailable, true);

  // Case 3: Renderer created but getContext() returns null
  let disposedOnNullCtx = 0;
  const nullCtxResult = initGlobeWebGLSafe({
    probeContext: () => ({ gl: {} as WebGLRenderingContext, gpuRenderer: 'SwiftShader' }),
    createRenderer: () => ({
      getContext: () => null,
      dispose: () => {
        disposedOnNullCtx += 1;
      },
    }),
  });
  assert.equal(nullCtxResult.renderer, null);
  assert.equal(nullCtxResult.webglUnavailable, true);
  assert.equal(nullCtxResult.isLowPowerOrSoftwareGl, true);
  assert.equal(disposedOnNullCtx, 1);

  // Case 4: Successful hardware WebGL renderer creation
  const mockRenderer = {
    getContext: () => ({}),
    dispose: () => {},
  };
  const okResult = initGlobeWebGLSafe({
    probeContext: () => ({ gl: {} as WebGLRenderingContext, gpuRenderer: 'Apple M3 Pro' }),
    createRenderer: () => mockRenderer,
    hardwareConcurrency: 8,
  });
  assert.equal(okResult.renderer, mockRenderer);
  assert.equal(okResult.webglUnavailable, false);
  assert.equal(okResult.isLowPowerOrSoftwareGl, false);
});

test('createGlobeResourceManager disposes all Three.js resources, ResizeObserver, and timers without double-freeing shared resources', () => {
  const manager = createGlobeResourceManager();

  let sharedGeomDisposeCount = 0;
  let sharedMatDisposeCount = 0;
  let sharedTexDisposeCount = 0;
  let rtDisposeCount = 0;
  let controlsDisposeCount = 0;
  let rendererDisposeCount = 0;
  let resizeDisconnectedCount = 0;
  let cancelledFrameId: number | null = null;

  const sharedGeom = manager.trackGeometry({
    dispose: () => {
      sharedGeomDisposeCount += 1;
    },
  });
  // Register the same geometry a second time to test deduplication
  manager.trackGeometry(sharedGeom);

  const sharedTex = manager.trackTexture({
    dispose: () => {
      sharedTexDisposeCount += 1;
    },
  });
  const sharedMat = manager.trackMaterial({
    map: sharedTex,
    dispose: () => {
      sharedMatDisposeCount += 1;
    },
  });
  manager.trackMaterial(sharedMat);

  manager.trackRenderTarget({
    dispose: () => {
      rtDisposeCount += 1;
    },
  });

  // Also test collectFromScene with a real Three.js Scene containing a shared geometry
  const scene = new THREE.Scene();
  const realGeom = new THREE.BoxGeometry(1, 1, 1);
  let realGeomDisposed = 0;
  const origDispose = realGeom.dispose.bind(realGeom);
  realGeom.dispose = () => {
    realGeomDisposed += 1;
    origDispose();
  };
  const realMat = new THREE.MeshBasicMaterial();
  const mesh1 = new THREE.Mesh(realGeom, realMat);
  const mesh2 = new THREE.Mesh(realGeom, realMat);
  scene.add(mesh1);
  scene.add(mesh2);

  manager.collectFromScene(scene);
  manager.disposeAll({
    animationFrameId: 42,
    cancelFrame: id => {
      cancelledFrameId = id;
    },
    resizeObserver: {
      disconnect: () => {
        resizeDisconnectedCount += 1;
      },
    },
    controls: {
      dispose: () => {
        controlsDisposeCount += 1;
      },
    },
    renderer: {
      dispose: () => {
        rendererDisposeCount += 1;
      },
    },
  });

  // Calling disposeAll a second time must not re-dispose already freed resources
  manager.disposeAll({
    controls: {
      dispose: () => {
        controlsDisposeCount += 1;
      },
    },
  });

  assert.equal(manager.isDisposed, true);
  assert.equal(sharedGeomDisposeCount, 1);
  assert.equal(sharedMatDisposeCount, 1);
  assert.equal(sharedTexDisposeCount, 1);
  assert.equal(rtDisposeCount, 1);
  assert.equal(realGeomDisposed, 1);
  assert.equal(controlsDisposeCount, 1);
  assert.equal(rendererDisposeCount, 1);
  assert.equal(resizeDisconnectedCount, 1);
  assert.equal(cancelledFrameId, 42);
});

test('WebRTC UNSUPPORTED, ERROR, INCONCLUSIVE, or NOT_CONFIGURED never produce overall PASS or 100 privacy score', () => {
  const now = new Date().toISOString();
  const validIp: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    asn: 'AS24940',
    isp: 'Hetzner Online GmbH',
    countryCode: 'DE',
    ipMismatchDetected: false,
    isDatacenter: true,
    fraudRiskScore: null,
  };

  const validDns = evaluateDnsTestResult({
    runId: 'run-valid-100',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'cf-1',
        name: 'Cloudflare',
        primaryIp: '1.1.1.1',
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.',
        location: 'Anycast',
        runId: 'run-valid-100',
        queryName: 'p1.run-valid-100.leak.example.com',
        observedAt: now,
        status: 'OK',
        responseTimeMs: 10,
        isEncryptedDoH: true,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: validIp,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(validDns.status, 'PASS');

  const webRtcUnsupported = evaluateWebRtcCandidates({
    isSupported: false,
    candidates: [],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(webRtcUnsupported.status, 'UNSUPPORTED');

  const summaryWithUnsupportedWebRtc = evaluateOverallSummary({
    ipDetails: validIp,
    dnsLeak: validDns,
    webRtcLeak: webRtcUnsupported,
    vpnProxy: evaluateVpnHeuristic(validIp, validDns),
  });
  assert.notEqual(summaryWithUnsupportedWebRtc.overallStatus, 'PASS');
  assert.equal(summaryWithUnsupportedWebRtc.overallStatus, 'INCONCLUSIVE');
  assert.equal(summaryWithUnsupportedWebRtc.isScoreCalculable, false);
  assert.equal(summaryWithUnsupportedWebRtc.privacyScore, null);

  // Also verify WebRTC ERROR -> overallStatus is ERROR, score is null
  const webRtcError = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
    errorMessage: 'RTCPeerConnection blocked',
  });
  const summaryWithErrorWebRtc = evaluateOverallSummary({
    ipDetails: validIp,
    dnsLeak: validDns,
    webRtcLeak: webRtcError,
    vpnProxy: evaluateVpnHeuristic(validIp, validDns),
  });
  assert.equal(summaryWithErrorWebRtc.overallStatus, 'ERROR');
  assert.equal(summaryWithErrorWebRtc.isScoreCalculable, false);
  assert.equal(summaryWithErrorWebRtc.privacyScore, null);
});

test('evaluateDnsTestResult ignores status text strings and requires structured evidence; resolver without comparison metadata or country difference alone is INCONCLUSIVE', () => {
  const now = new Date().toISOString();
  const baseIpDetails: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    countryCode: 'DE',
    asn: 'AS24940',
    isp: 'Hetzner Online GmbH',
    isDatacenter: true,
  };

  // 1. A resolver with NO comparison metadata (missing asn & isp, not matching egress IP) -> INCONCLUSIVE (neither PASS nor LEAK_DETECTED)
  const bareResolverRes = evaluateDnsTestResult({
    runId: 'run-bare-1',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'r-bare',
        name: 'Unknown Resolver',
        primaryIp: '9.9.9.9',
        location: 'DE',
        runId: 'run-bare-1',
        queryName: 'p1.run-bare-1.leak.example.com',
        observedAt: now,
        status: 'مغایرت کشور با تونل (Leak)', // Even with "Leak" / "مغایرت" in status string, must NOT trigger LEAK_DETECTED!
        responseTimeMs: 20,
        isEncryptedDoH: null,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: baseIpDetails,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(bareResolverRes.status, 'INCONCLUSIVE');
  assert.equal(bareResolverRes.isLeaking, null);

  // 2. Country difference alone (e.g. DE vs NL) without unencrypted ISP/ASN leak conflict -> INCONCLUSIVE (not LEAK_DETECTED)
  const countryDiffOnlyRes = evaluateDnsTestResult({
    runId: 'run-country-diff',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'r-nl',
        name: 'Hetzner NL Resolver',
        primaryIp: '185.12.64.1',
        asn: 'AS24940', // Same ASN as tunnel!
        isp: 'Hetzner Online GmbH',
        location: 'NL', // Different country (Netherlands vs Germany)
        runId: 'run-country-diff',
        queryName: 'p1.run-country-diff.leak.example.com',
        observedAt: now,
        status: 'Leak', // Status text must be ignored
        responseTimeMs: 15,
        isEncryptedDoH: false,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: baseIpDetails,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(countryDiffOnlyRes.status, 'INCONCLUSIVE');
  assert.equal(countryDiffOnlyRes.isLeaking, null);

  // 3. Mismatched runId on resolver event -> INCONCLUSIVE
  const mismatchedRunIdRes = evaluateDnsTestResult({
    runId: 'run-active-111',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'r-wrong-run',
        name: 'Cloudflare',
        primaryIp: '1.1.1.1',
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.',
        location: 'Anycast',
        runId: 'run-stale-999',
        queryName: 'p1.run-stale-999.leak.example.com',
        observedAt: now,
        status: 'OK',
        responseTimeMs: 12,
        isEncryptedDoH: true,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: baseIpDetails,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(mismatchedRunIdRes.status, 'INCONCLUSIVE');
  assert.equal(mismatchedRunIdRes.errorCode, 'RUN_ID_MISMATCH');
  assert.equal(mismatchedRunIdRes.isLeaking, null);

  // 4. Missing ipDetails -> INCONCLUSIVE (cannot compare resolvers without primary egress IP)
  const missingIpDetailsRes = evaluateDnsTestResult({
    runId: 'run-no-ip',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'r-cf',
        name: 'Cloudflare',
        primaryIp: '1.1.1.1',
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.',
        location: 'Anycast',
        runId: 'run-no-ip',
        queryName: 'p1.run-no-ip.leak.example.com',
        observedAt: now,
        status: 'OK',
        responseTimeMs: 12,
        isEncryptedDoH: true,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: null,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(missingIpDetailsRes.status, 'INCONCLUSIVE');
  assert.equal(missingIpDetailsRes.isLeaking, null);
});

test('evaluateIndependentBrowserDnsObservation sets matchesPrimaryEgressIp=true ONLY on exact edge_trace_egress IP match and never treats country difference as LEAK_DETECTED', () => {
  const mockIpDetails: any = {
    status: 'PASS',
    ip: '198.51.100.10',
    countryCode: 'DE',
    countryName: 'Germany',
  };

  // 1. Country difference in EDNS resolver (e.g. Iran vs DE) in browser check is INCONCLUSIVE, not LEAK_DETECTED, and matchesPrimaryEgressIp is null
  const geoDiffObs = evaluateIndependentBrowserDnsObservation(
    [
      {
        sourceName: 'ip-api EDNS Recursive Resolver',
        observedIp: '91.98.0.1',
        locationOrGeo: 'Iran - TCI',
        role: 'edns_recursive_resolver',
        responseTimeMs: 50,
      },
    ],
    mockIpDetails
  );
  assert.equal(geoDiffObs.status, 'INCONCLUSIVE');
  assert.equal(geoDiffObs.matchesPrimaryEgressIp, null);

  // 2. Exact IP match of same data type (`edge_trace_egress`) sets matchesPrimaryEgressIp = true, while status remains INCONCLUSIVE (not substitute for authoritative DNS)
  const matchingEdgeObs = evaluateIndependentBrowserDnsObservation(
    [
      {
        sourceName: 'Cloudflare Edge Trace (FRA)',
        observedIp: '::ffff:198.51.100.10', // Canonically matches 198.51.100.10
        locationOrGeo: 'DE',
        role: 'edge_trace_egress',
        responseTimeMs: 28,
      },
    ],
    mockIpDetails
  );
  assert.equal(matchingEdgeObs.matchesPrimaryEgressIp, true);
  assert.equal(matchingEdgeObs.status, 'INCONCLUSIVE');

  // 3. Mismatched `edge_trace_egress` IP sets matchesPrimaryEgressIp = false and status = WARNING
  const mismatchedEdgeObs = evaluateIndependentBrowserDnsObservation(
    [
      {
        sourceName: 'Cloudflare Edge Trace (FRA)',
        observedIp: '203.0.113.77',
        locationOrGeo: 'DE',
        role: 'edge_trace_egress',
        responseTimeMs: 31,
      },
    ],
    mockIpDetails
  );
  assert.equal(mismatchedEdgeObs.matchesPrimaryEgressIp, false);
  assert.equal(mismatchedEdgeObs.status, 'WARNING');
});

test('evaluatePortLeakResult never issues PASS for incomplete or not_tested ports and classifies generic open TCP port as WARNING with medium confidence', () => {
  const now = new Date().toISOString();

  // 1. Only 1 port tested (7 ports missing/not_tested) -> INCONCLUSIVE, never PASS
  const partialPortsRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: [
      {
        port: 80,
        protocol: 'TCP',
        serviceName: 'HTTP Web / TCP-80 Service',
        category: 'router_admin',
        descriptionFa: 'HTTP',
        descriptionEn: 'HTTP',
        state: 'closed',
        responseTimeMs: 14,
        riskLevel: 'high',
      },
    ],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(partialPortsRes.status, 'INCONCLUSIVE');
  assert.equal(partialPortsRes.isExposingSensitivePorts, null);
  assert.equal(partialPortsRes.errorCode, 'INCOMPLETE_PORT_SCAN');

  // 2. All 8 ports provided, but one port has state === 'not_tested' -> INCONCLUSIVE
  const oneNotTestedPorts = COMMON_SENSITIVE_PORTS.map((def, idx) => ({
    ...def,
    state: (idx === 0 ? 'not_tested' : 'closed') as 'not_tested' | 'closed',
    responseTimeMs: idx === 0 ? null : 12,
  }));
  const oneNotTestedRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: oneNotTestedPorts,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(oneNotTestedRes.status, 'INCONCLUSIVE');
  assert.equal(oneNotTestedRes.isExposingSensitivePorts, null);

  // 3. Open TCP/443 or TCP/80 (non-critical service port) -> WARNING with medium confidence (does not claim confirmed router admin panel exposure)
  const genericOpenPorts = COMMON_SENSITIVE_PORTS.map(def => ({
    ...def,
    state: (def.port === 443 ? 'open' : 'closed') as 'open' | 'closed',
    responseTimeMs: 19,
  }));
  const genericOpenRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: genericOpenPorts,
    startedAt: now,
    completedAt: now,
  });
  assert.equal(genericOpenRes.status, 'WARNING');
  assert.equal(genericOpenRes.confidence, 'medium');
  assert.equal(genericOpenRes.isExposingSensitivePorts, true);
  assert.deepEqual(genericOpenRes.openPorts, [443]);
});

test('strict RFC IPv4/IPv6 validation, hex IPv4-mapped IPv6, and isSafeExternalUrl SSRF protection', () => {
  // Malformed IPv4 & leading-zero octal ambiguity
  assert.equal(isValidIpv4('010.0.0.1'), false);
  assert.equal(isValidIpv4('127.0.0.01'), false);
  assert.equal(isValidIpv4('1.2.3.4.5'), false);
  assert.equal(isValidIpv4('1.2.3'), false);

  // Malformed IPv6 strings that naive regexes accept
  assert.equal(isValidIpv6(':::'), false);
  assert.equal(isValidIpv6('2001:db8::1::2'), false);
  assert.equal(isValidIpv6(':1:2:3:4:5:6:7:8'), false);
  assert.equal(isValidIpv6('1:2:3:4:5:6:7:8:'), false);
  assert.equal(isValidIpv6('1:2:3:4:5:6:7:8:9'), false);
  assert.equal(isValidIpv6('::ffff:999.1.1.1'), false);
  assert.equal(isValidIpv6('fe80::1%'), false);

  // Valid IPv6 forms including IPv4-embedded and zone index
  assert.equal(isValidIpv6('::ffff:192.0.2.128'), true);
  assert.equal(isValidIpv6('fe80::1%eth0'), true);
  assert.equal(canonicalizeIp('::ffff:198.51.100.10'), '198.51.100.10');
  assert.equal(canonicalizeIp('0:0:0:0:0:ffff:c633:640a'), '198.51.100.10');

  // Hex-encoded IPv4-mapped IPv6 loopback/private/metadata must be blocked by isGloballyRoutablePublicIp
  assert.equal(isGloballyRoutablePublicIp('::ffff:7f00:1'), false); // 127.0.0.1 in hex
  assert.equal(isGloballyRoutablePublicIp('0:0:0:0:0:ffff:a9fe:a9fe'), false); // 169.254.169.254 in hex
  assert.equal(isGloballyRoutablePublicIp('0:0:0:0:0:ffff:a00:1'), false); // 10.0.0.1 in hex
  assert.equal(isGloballyRoutablePublicIp('64:ff9b::8.8.8.8'), false); // NAT64 prefix
  assert.equal(isGloballyRoutablePublicIp('2001::1'), false); // Teredo prefix
  assert.equal(isGloballyRoutablePublicIp('2002:0808:0808::1'), false); // 6to4 prefix
  assert.equal(isGloballyRoutablePublicIp('fe80::1%eth0'), false); // Scoped link-local

  // isSafeExternalUrl SSRF checks
  assert.equal(isSafeExternalUrl('https://collector.example.com/api/dns').valid, true);
  assert.equal(isSafeExternalUrl('http://127.0.0.1:8080/test').valid, false);
  assert.equal(isSafeExternalUrl('http://[::ffff:7f00:1]/test').valid, false);
  assert.equal(isSafeExternalUrl('http://169.254.169.254/latest/meta-data/').valid, false);
  assert.equal(isSafeExternalUrl('http://metadata.google.internal/computeMetadata/v1/').valid, false);
  assert.equal(isSafeExternalUrl('http://2130706433/').valid, false); // Decimal 127.0.0.1
  assert.equal(isSafeExternalUrl('http://0x7f000001/').valid, false); // Hex 127.0.0.1
  assert.equal(isSafeExternalUrl('https://user:pass@example.com/').valid, false); // Embedded credentials
  assert.equal(isSafeExternalUrl('ftp://example.com/file').valid, false);
});

test('evaluateObservedIpSources distinguishes dual-stack IPv4+IPv6 from same-family split-tunnel IP mismatch', () => {
  // 1. Dual-stack: one IPv6 from ipify and one IPv4 from ipwho.is/server -> NOT a split-tunnel leak
  const dualStackEval = evaluateObservedIpSources([
    {
      sourceName: 'api64.ipify.org',
      ip: '2a01:4f8:c010:1234::1',
      version: 'IPv6',
      observedFrom: 'client_direct',
      responseTimeMs: 45,
    },
    {
      sourceName: 'ipwho.is',
      ip: '198.51.100.10',
      version: 'IPv4',
      observedFrom: 'client_direct',
      responseTimeMs: 60,
    },
  ]);
  assert.equal(dualStackEval.isDualStackObserved, true);
  assert.equal(dualStackEval.ipMismatchDetected, false);
  assert.deepEqual(dualStackEval.uniqueIpv4s, ['198.51.100.10']);
  assert.equal(dualStackEval.uniqueIpv6s.length, 1);

  // 2. Same-family mismatch: two different IPv4 addresses -> confirmed split-tunnel / path mismatch
  const v4MismatchEval = evaluateObservedIpSources([
    {
      sourceName: 'ipwho.is',
      ip: '198.51.100.10',
      version: 'IPv4',
      observedFrom: 'client_direct',
      responseTimeMs: 50,
    },
    {
      sourceName: 'App Server',
      ip: '203.0.113.99',
      version: 'IPv4',
      observedFrom: 'server_socket',
      responseTimeMs: 20,
    },
  ]);
  assert.equal(v4MismatchEval.ipMismatchDetected, true);
  assert.equal(v4MismatchEval.isDualStackObserved, false);

  // 3. Canonical IPv4-mapped IPv6 matching same IPv4 -> no mismatch
  const mappedMatchEval = evaluateObservedIpSources([
    {
      sourceName: 'Client Direct',
      ip: '198.51.100.10',
      version: 'IPv4',
      observedFrom: 'client_direct',
      responseTimeMs: 30,
    },
    {
      sourceName: 'Server Socket',
      ip: '::ffff:198.51.100.10',
      version: 'IPv6',
      observedFrom: 'server_socket',
      responseTimeMs: 12,
    },
  ]);
  assert.equal(mappedMatchEval.ipMismatchDetected, false);
  assert.equal(mappedMatchEval.uniqueIpv4s.length, 1);
});

test('evaluateWebRtcCandidates handles dual-stack IPv6 STUN candidates without false PASS or false LEAK when only IPv4 reference exists', () => {
  const now = new Date().toISOString();

  // Only IPv4 reference IP exists, but STUN discovers an IPv6 public candidate -> WARNING (Dual-Stack unverified), not PASS
  const dualStackWebRtc = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [
      {
        ip: '2a01:4f8:c010:1234::1',
        version: 'IPv6',
        type: 'srflx',
        protocol: 'UDP',
        port: 52000,
        isLocalLanIp: false,
        isPublicIp: true,
      },
    ],
    referencePublicIps: ['198.51.100.10'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(dualStackWebRtc.status, 'WARNING');
  assert.equal(dualStackWebRtc.isLeakingRealIp, null);
  assert.equal(dualStackWebRtc.errorCode, 'DUAL_STACK_FAMILY_UNVERIFIED');

  // When both IPv4 and IPv6 reference IPs are provided and match -> PASS
  const verifiedDualStack = evaluateWebRtcCandidates({
    isSupported: true,
    candidates: [
      {
        ip: '2a01:4f8:c010:1234::1',
        version: 'IPv6',
        type: 'srflx',
        protocol: 'UDP',
        port: 52000,
        isLocalLanIp: false,
        isPublicIp: true,
      },
    ],
    referencePublicIps: ['198.51.100.10', '2a01:4f8:c010:1234:0:0:0:1'],
    stunServersUsed: ['stun:stun.l.google.com:19302'],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(verifiedDualStack.status, 'PASS');
  assert.equal(verifiedDualStack.isLeakingRealIp, false);
});

test('validateAiAuditPayload strictly validates Gemini JSON schema and rejects malformed or out-of-range outputs', () => {
  // Valid payload
  const validCheck = validateAiAuditPayload({
    riskScore: 25,
    statusLevel: 'هشدار',
    summaryFa: 'خلاصه معتبر تست شبکه',
    detailedAnalysisFa: ['مورد اول', 'مورد دوم'],
    threatsFoundFa: ['ریسک جزئی'],
    recommendationsFa: ['توصیه اول'],
  });
  assert.equal(validCheck.valid, true);
  assert.equal(validCheck.audit?.riskScore, 25);
  assert.equal(validCheck.audit?.statusLevel, 'هشدار');

  // Invalid statusLevel
  assert.equal(
    validateAiAuditPayload({
      riskScore: 10,
      statusLevel: 'SAFE_FAKE',
      summaryFa: 'متن',
      detailedAnalysisFa: [],
      threatsFoundFa: [],
      recommendationsFa: [],
    }).valid,
    false
  );

  // Out-of-bounds riskScore
  assert.equal(
    validateAiAuditPayload({
      riskScore: 150,
      statusLevel: 'امن',
      summaryFa: 'متن',
      detailedAnalysisFa: [],
      threatsFoundFa: [],
      recommendationsFa: [],
    }).valid,
    false
  );

  // Non-array detailedAnalysisFa or non-object payload
  assert.equal(
    validateAiAuditPayload({
      riskScore: null,
      statusLevel: 'نامشخص',
      summaryFa: 'متن',
      detailedAnalysisFa: 'not-an-array',
      threatsFoundFa: [],
      recommendationsFa: [],
    }).valid,
    false
  );
  assert.equal(validateAiAuditPayload(null).valid, false);
  assert.equal(validateAiAuditPayload(['array']).valid, false);
});

test('createBoundedSignal and RUNNING status support work accurately for cancellation and lifecycle states', () => {
  const controller = new AbortController();
  const bounded = createBoundedSignal(10_000, controller.signal);
  assert.equal(bounded.aborted, false);
  controller.abort();
  assert.equal(bounded.aborted, true);

  assert.equal(formatTestStatusLabelFa('RUNNING'), 'در حال آزمایش...');
  assert.equal(formatTestStatusLabelFa('IDLE'), 'اجرا نشده');

  const runningGlobe = resolveGlobeVisualStatus('RUNNING', null);
  assert.equal(runningGlobe.visualCategory, 'inconclusive');
  assert.equal(runningGlobe.isPass, false);

  const errGlobe = resolveGlobeVisualStatus('ERROR', null);
  assert.equal(errGlobe.badgeTextFa, 'خطا در اجرای تست؛ نتیجه قابل تأیید نیست');
  assert.equal(errGlobe.badgeTextEn, 'Test execution failed; result cannot be verified.');
});

test('Cloudflare Worker keeps DNS test NOT_CONFIGURED until UDP/53 is verified and enforces strict runId + Bearer auth on ingest', async () => {
  const kvStore = new Map<string, string>();
  const mockKv = {
    async get(key: string) {
      return kvStore.get(key) ?? null;
    },
    async put(key: string, value: string) {
      kvStore.set(key, value);
    },
  };

  // 1. Default unverified state -> authoritativeConfigured must be false («پیکربندی نشده»)
  const unverifiedEnv: CloudflareEnv = {
    DNS_LEAK_DOMAIN: '',
    DNS_UDP53_VERIFIED: 'false',
    DNS_LOGS_KV: mockKv,
  };

  const probeUnconfiguredResp = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-leak-probe?runId=run-12345678'),
    unverifiedEnv
  );
  assert.equal(probeUnconfiguredResp.status, 200);
  const probeUnconfiguredJson: any = await probeUnconfiguredResp.json();
  assert.equal(probeUnconfiguredJson.authoritativeConfigured, false);
  assert.deepEqual(probeUnconfiguredJson.resolvers, []);
  assert.ok(probeUnconfiguredJson.messageFa.includes('پیکربندی نشده'));

  // 2. Even if DNS_LEAK_DOMAIN is set, without DNS_UDP53_VERIFIED="true", it MUST remain NOT_CONFIGURED
  const halfConfiguredEnv: CloudflareEnv = {
    DNS_LEAK_DOMAIN: 'leak.example.com',
    DNS_COLLECTOR_API_TOKEN: 'test-secret-token-for-unit-test-only',
    DNS_UDP53_VERIFIED: 'false',
    DNS_LOGS_KV: mockKv,
  };
  const halfResp = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-leak-probe?runId=run-12345678'),
    halfConfiguredEnv
  );
  const halfJson: any = await halfResp.json();
  assert.equal(halfJson.authoritativeConfigured, false);

  // 3. Fully configured & verified environment
  const verifiedEnv: CloudflareEnv = {
    DNS_LEAK_DOMAIN: 'leak.example.com',
    DNS_COLLECTOR_API_TOKEN: 'test-secret-token-for-unit-test-only',
    DNS_UDP53_VERIFIED: 'true',
    DNS_LOGS_KV: mockKv,
  };

  // Health endpoint must NEVER leak the secret token
  const healthResp = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/health'),
    verifiedEnv
  );
  const healthText = await healthResp.text();
  assert.equal(healthText.includes('test-secret-token-for-unit-test-only'), false);
  const healthJson = JSON.parse(healthText);
  assert.equal(healthJson.optionalIntegrations.authoritativeDnsConfigured, true);

  // 4. Ingest without valid Bearer token -> 401 Unauthorized
  const unauthorizedIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer wrong-token' },
      body: JSON.stringify({ runId: 'run-12345678', resolverIp: '9.9.9.9' }),
    }),
    verifiedEnv
  );
  assert.equal(unauthorizedIngest.status, 401);

  // 5. Ingest with private/loopback IP -> 400 Bad Request
  const privateIpIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-secret-token-for-unit-test-only',
      },
      body: JSON.stringify({ runId: 'run-12345678', resolverIp: '127.0.0.1' }),
    }),
    verifiedEnv
  );
  assert.equal(privateIpIngest.status, 400);

  // 6. Ingest with mismatched qname vs runId -> 400 Bad Request
  const mismatchQnameIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-secret-token-for-unit-test-only',
      },
      body: JSON.stringify({
        runId: 'run-12345678',
        resolverIp: '9.9.9.9',
        qname: 'p1.other-run-99999999.leak.example.com',
      }),
    }),
    verifiedEnv
  );
  assert.equal(mismatchQnameIngest.status, 400);

  // 7. Valid ingest for run-12345678
  const validIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-secret-token-for-unit-test-only',
      },
      body: JSON.stringify({
        runId: 'run-12345678',
        resolverIp: '9.9.9.9',
        isp: 'Quad9 Recursive DNS',
        asn: 'AS19281',
        countryCode: 'CH',
        qname: 'p1.run-12345678.leak.example.com',
        observedAt: new Date().toISOString(),
      }),
    }),
    verifiedEnv
  );
  assert.equal(validIngest.status, 200);

  // 8. Querying probe for a DIFFERENT runId returns empty resolvers (no cross-session leakage)
  const otherProbe = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-leak-probe?runId=run-99999999'),
    verifiedEnv
  );
  const otherProbeJson: any = await otherProbe.json();
  assert.equal(otherProbeJson.authoritativeConfigured, true);
  assert.equal(otherProbeJson.resolvers.length, 0);

  // 9. Querying probe for matching run-12345678 returns the verified UDP/53 resolver
  const matchingProbe = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-leak-probe?runId=run-12345678'),
    verifiedEnv
  );
  const matchingProbeJson: any = await matchingProbe.json();
  assert.equal(matchingProbeJson.authoritativeConfigured, true);
  assert.equal(matchingProbeJson.resolvers.length, 1);
  assert.equal(matchingProbeJson.resolvers[0].primaryIp, '9.9.9.9');
  assert.equal(matchingProbeJson.resolvers[0].runId, 'run-12345678');
  assert.equal(matchingProbeJson.resolvers[0].observationMethod, 'authoritative_dns_log');
});

test('DNS anti-replay, stale timestamp rejection, CGNAT/TEST-NET rejection, token rotation, and 413 payload limit work accurately', async () => {
  const sampleIpDetails: any = {
    status: 'PASS',
    ip: '185.220.101.5',
    asn: 'AS200000',
    isp: 'Privacy VPN Provider',
    countryCode: 'DE',
  };

  // 1. Stale observation timestamp (>5 minutes old) is rejected by evaluateDnsTestResult
  const nowIso = new Date().toISOString();
  const staleIso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const staleEval = evaluateDnsTestResult({
    runId: 'run-fresh-001',
    authoritativeConfigured: true,
    startedAt: nowIso,
    completedAt: nowIso,
    resolvers: [
      {
        id: 'r1',
        name: 'Quad9',
        primaryIp: '9.9.9.9',
        asn: 'AS19281',
        isp: 'Quad9',
        location: 'CH',
        countryCode: 'CH',
        runId: 'run-fresh-001',
        queryName: 'p1.run-fresh-001.leak.example.com',
        observedAt: staleIso,
        status: 'Observed',
        responseTimeMs: null,
        isEncryptedDoH: null,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: sampleIpDetails,
  });
  assert.equal(staleEval.status, 'INCONCLUSIVE');
  assert.equal(staleEval.errorCode, 'STALE_DNS_OBSERVATION');

  // 2. CGNAT (100.64.0.1) or TEST-NET (198.51.100.1) resolver IP is rejected by evaluateDnsTestResult
  const cgnatEval = evaluateDnsTestResult({
    runId: 'run-cgnat-001',
    authoritativeConfigured: true,
    startedAt: nowIso,
    completedAt: nowIso,
    resolvers: [
      {
        id: 'r2',
        name: 'CGNAT Fake Resolver',
        primaryIp: '100.64.0.1',
        asn: 'AS200000',
        isp: 'Privacy VPN Provider',
        location: 'DE',
        countryCode: 'DE',
        runId: 'run-cgnat-001',
        queryName: 'p1.run-cgnat-001.leak.example.com',
        observedAt: nowIso,
        status: 'Observed',
        responseTimeMs: null,
        isEncryptedDoH: null,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: sampleIpDetails,
  });
  assert.equal(cgnatEval.status, 'INCONCLUSIVE');
  assert.equal(cgnatEval.errorCode, 'INVALID_RESOLVER_EVIDENCE');

  // 3. Cloudflare Worker token rotation (DNS_COLLECTOR_API_TOKEN_PREVIOUS), stale timestamp, domain mismatch, and 413 payload limit
  const kvStore = new Map<string, string>();
  const rotationEnv: CloudflareEnv = {
    DNS_LEAK_DOMAIN: 'leak.example.com',
    DNS_COLLECTOR_API_TOKEN: 'new-rotated-token-2026',
    DNS_COLLECTOR_API_TOKEN_PREVIOUS: 'old-previous-token-2026',
    DNS_UDP53_VERIFIED: 'true',
    DNS_LOGS_KV: {
      async get(k) {
        return kvStore.get(k) ?? null;
      },
      async put(k, v) {
        kvStore.set(k, v);
      },
    },
  };

  // Ingest using previous token during rotation succeeds
  const prevTokenIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer old-previous-token-2026',
      },
      body: JSON.stringify({
        runId: 'run-rot-12345678',
        resolverIp: '1.1.1.1',
        qname: 'p1.run-rot-12345678.leak.example.com',
        observedAt: new Date().toISOString(),
      }),
    }),
    rotationEnv
  );
  assert.equal(prevTokenIngest.status, 200);

  // Ingest with stale timestamp is rejected with 400 STALE_OR_FUTURE_TIMESTAMP
  const staleIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer new-rotated-token-2026',
      },
      body: JSON.stringify({
        runId: 'run-rot-12345678',
        resolverIp: '8.8.8.8',
        qname: 'p2.run-rot-12345678.leak.example.com',
        observedAt: staleIso,
      }),
    }),
    rotationEnv
  );
  assert.equal(staleIngest.status, 400);
  const staleIngestJson: any = await staleIngest.json();
  assert.equal(staleIngestJson.errorCode, 'STALE_OR_FUTURE_TIMESTAMP');

  // Ingest with wrong domain suffix is rejected with 400 QNAME_DOMAIN_MISMATCH
  const wrongDomainIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer new-rotated-token-2026',
      },
      body: JSON.stringify({
        runId: 'run-rot-12345678',
        resolverIp: '8.8.8.8',
        qname: 'p2.run-rot-12345678.evil.example.org',
        observedAt: new Date().toISOString(),
      }),
    }),
    rotationEnv
  );
  assert.equal(wrongDomainIngest.status, 400);
  const wrongDomainJson: any = await wrongDomainIngest.json();
  assert.equal(wrongDomainJson.errorCode, 'QNAME_DOMAIN_MISMATCH');

  // Ingest with oversized payload (>32KB) is rejected with 413 PAYLOAD_TOO_LARGE
  const oversizedPayload = JSON.stringify({
    runId: 'run-rot-12345678',
    resolverIp: '8.8.8.8',
    padding: 'A'.repeat(40_000),
  });
  const oversizedIngest = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer new-rotated-token-2026',
      },
      body: oversizedPayload,
    }),
    rotationEnv
  );
  assert.equal(oversizedIngest.status, 413);
});

test('Cloudflare Worker Static Assets binding, API routes, and wrangler.toml configuration are compatible and free of hardcoded secrets', async () => {
  let assetsFetchedUrl: string | null = null;
  const mockEnvWithAssets: CloudflareEnv = {
    ASSETS: {
      async fetch(req: Request) {
        assetsFetchedUrl = req.url;
        return new Response('<!doctype html><html><body>SPA Index</body></html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
        });
      },
    },
  };

  // 1. Non-API path delegates to env.ASSETS.fetch(request)
  const spaRes = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/dashboard'),
    mockEnvWithAssets
  );
  assert.equal(spaRes.status, 200);
  assert.equal(assetsFetchedUrl, 'https://example.workers.dev/dashboard');
  const spaHtml = await spaRes.text();
  assert.match(spaHtml, /SPA Index/);

  // 2. Unknown /api/* path returns 404 JSON from Worker and NEVER falls through to env.ASSETS
  assetsFetchedUrl = null;
  const unknownApiRes = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/non-existent-endpoint'),
    mockEnvWithAssets
  );
  assert.equal(unknownApiRes.status, 404);
  assert.equal(assetsFetchedUrl, null);

  // 3. /api/port-scan on Cloudflare Edge returns honest not_tested ports and never claims open/closed
  const portScanRes = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/port-scan', {
      headers: { 'CF-Connecting-IP': '198.51.100.42' },
    }),
    mockEnvWithAssets
  );
  assert.equal(portScanRes.status, 200);
  const portScanJson: any = await portScanRes.json();
  assert.equal(portScanJson.canScanFromServer, false);
  assert.ok(Array.isArray(portScanJson.ports) && portScanJson.ports.length > 0);
  assert.ok(portScanJson.ports.every((p: any) => p.state === 'not_tested'));
});

test('isValidDnsObservationRecord and DNS evidence validation strictly enforce runId, timestamps, anti-replay, and public IP ranges', async () => {
  const now = Date.now();
  const validIso = new Date(now).toISOString();
  const validRunId = 'run-strict-001';

  const baseRecord = {
    id: 'res-1',
    name: 'Quad9 DNS',
    primaryIp: '9.9.9.9',
    asn: 'AS19281',
    isp: 'Quad9',
    location: 'CH',
    countryCode: 'CH',
    runId: validRunId,
    queryName: `p1.${validRunId}.leak.example.com`,
    observedAt: validIso,
    status: 'Observed',
    responseTimeMs: 25,
    isEncryptedDoH: true,
    observationMethod: 'authoritative_dns_log' as const,
  };

  // 1. Positive case: valid public IPv4 + matching runId + canonical queryName + fresh timestamp -> true
  assert.equal(isValidDnsObservationRecord(baseRecord, validRunId, now), true);

  // 2. Positive case: valid public IPv6 (Quad9 IPv6 2620:fe::fe) -> true
  assert.equal(
    isValidDnsObservationRecord({ ...baseRecord, primaryIp: '2620:fe::fe' }, validRunId, now),
    true
  );

  // 3. Negative case: missing runId -> false
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, runId: '' }, validRunId, now), false);
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, runId: undefined }, validRunId, now), false);

  // 4. Negative case: mismatched runId -> false
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, runId: 'run-different-999' }, validRunId, now), false);

  // 5. Negative case: missing observedAt -> false
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, observedAt: '' }, validRunId, now), false);
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, observedAt: undefined }, validRunId, now), false);

  // 6. Negative case: unparseable/invalid observedAt string -> false
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, observedAt: 'not-a-valid-date' }, validRunId, now), false);

  // 7. Negative case: stale observedAt (> 5 minutes old) -> false
  const staleIso = new Date(now - 6 * 60 * 1000).toISOString();
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, observedAt: staleIso }, validRunId, now), false);

  // 8. Negative case: future observedAt (> 60s in future) -> false
  const futureIso = new Date(now + 90 * 1000).toISOString();
  assert.equal(isValidDnsObservationRecord({ ...baseRecord, observedAt: futureIso }, validRunId, now), false);

  // 9. Negative cases: Non-public / reserved IP ranges -> false
  const nonPublicIps = [
    '127.0.0.1', // Loopback IPv4
    '::1', // Loopback IPv6
    '10.0.0.1', // RFC1918 Private
    '192.168.1.1', // RFC1918 Private
    '172.16.5.1', // RFC1918 Private
    '100.64.0.1', // RFC6598 CGNAT
    '169.254.169.254', // Link-local / Cloud metadata
    'fe80::1', // Link-local IPv6
    'fc00::1', // Unique Local IPv6 (ULA)
    '224.0.0.1', // Multicast IPv4
    'ff02::1', // Multicast IPv6
    '192.0.2.1', // TEST-NET-1 Documentation
    '198.51.100.1', // TEST-NET-2 Documentation
    '203.0.113.1', // TEST-NET-3 Documentation
    '2001:db8::1', // Documentation IPv6
    '::ffff:192.168.1.1', // IPv4-mapped IPv6 private
  ];
  for (const nonPublicIp of nonPublicIps) {
    assert.equal(
      isValidDnsObservationRecord({ ...baseRecord, primaryIp: nonPublicIp }, validRunId, now),
      false,
      `Failed to reject non-public IP: ${nonPublicIp}`
    );
  }

  // 10. Negative case: queryName missing or mismatch vs runId -> false
  assert.equal(
    isValidDnsObservationRecord({ ...baseRecord, queryName: '' }, validRunId, now),
    false
  );
  assert.equal(
    isValidDnsObservationRecord({ ...baseRecord, queryName: undefined }, validRunId, now),
    false
  );
  assert.equal(
    isValidDnsObservationRecord(
      { ...baseRecord, queryName: 'p1.other-run-token.leak.example.com' },
      validRunId,
      now
    ),
    false
  );

  // 11. Positive case: queryName contains matching runId -> true
  assert.equal(
    isValidDnsObservationRecord(
      { ...baseRecord, queryName: `p1.${validRunId}.leak.example.com` },
      validRunId,
      now
    ),
    true
  );

  // 12. Negative case: invalid observationMethod -> false
  assert.equal(
    isValidDnsObservationRecord(
      { ...baseRecord, observationMethod: 'browser_edns_client_subnet' as any },
      validRunId,
      now
    ),
    false
  );

  // 13. Test evaluateDnsTestResult behavior on missing runId in resolver records -> INCONCLUSIVE (RUN_ID_MISMATCH)
  const missingRunIdResult = evaluateDnsTestResult({
    runId: validRunId,
    authoritativeConfigured: true,
    resolvers: [
      {
        ...baseRecord,
        runId: '',
      },
    ],
    ipDetails: { status: 'PASS', ip: '185.220.101.5', countryCode: 'DE', asn: 'AS200000', isp: 'VPN' } as any,
    startedAt: validIso,
    completedAt: validIso,
  });
  assert.equal(missingRunIdResult.status, 'INCONCLUSIVE');
  assert.equal(missingRunIdResult.errorCode, 'RUN_ID_MISMATCH');

  // 14. Test evaluateDnsTestResult behavior on missing observedAt in resolver records -> INCONCLUSIVE (STALE_DNS_OBSERVATION)
  const missingTimestampResult = evaluateDnsTestResult({
    runId: validRunId,
    authoritativeConfigured: true,
    resolvers: [
      {
        ...baseRecord,
        observedAt: '',
      },
    ],
    ipDetails: { status: 'PASS', ip: '185.220.101.5', countryCode: 'DE', asn: 'AS200000', isp: 'VPN' } as any,
    startedAt: validIso,
    completedAt: validIso,
  });
  assert.equal(missingTimestampResult.status, 'INCONCLUSIVE');
  assert.equal(missingTimestampResult.errorCode, 'STALE_DNS_OBSERVATION');

  // 15. Test streaming chunked request without Content-Length exceeding 32KB payload
  const oversizedChunk = new Uint8Array(20 * 1024); // 20KB chunk
  oversizedChunk.fill(65); // 'A'
  const chunkedStream = new ReadableStream({
    start(controller) {
      controller.enqueue(oversizedChunk);
      controller.enqueue(oversizedChunk); // Total 40KB > 32KB limit
      controller.close();
    },
  });

  const workerEnv: any = {
    DNS_LEAK_DOMAIN: 'leak.example.com',
    DNS_COLLECTOR_API_TOKEN: 'secret-token-test',
    DNS_UDP53_VERIFIED: 'true',
    DNS_LOGS_KV: { async get() { return null; }, async put() {} },
  };

  const streamOverLimitReq = new Request('https://example.workers.dev/api/dns-collector/ingest', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer secret-token-test',
      'Content-Type': 'application/json',
      // Note: No Content-Length header provided! Stream reader must abort and return 413
    },
    body: chunkedStream,
    // @ts-ignore
    duplex: 'half',
  });

  const streamOverLimitRes = await cloudflareWorker.fetch(streamOverLimitReq, workerEnv);
  assert.equal(streamOverLimitRes.status, 413);
  const streamOverLimitJson: any = await streamOverLimitRes.json();
  assert.equal(streamOverLimitJson.errorCode, 'PAYLOAD_TOO_LARGE');

  // 16. Ingest without observedAt is rejected with 400 MISSING_OBSERVED_AT
  const missingObservedAtReq = new Request('https://example.workers.dev/api/dns-collector/ingest', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer secret-token-test',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      runId: validRunId,
      resolverIp: '9.9.9.9',
      qname: `p1.${validRunId}.leak.example.com`,
      // observedAt omitted!
    }),
  });
  const missingObservedAtRes = await cloudflareWorker.fetch(missingObservedAtReq, workerEnv);
  assert.equal(missingObservedAtRes.status, 400);
  const missingObservedAtJson: any = await missingObservedAtRes.json();
  assert.equal(missingObservedAtJson.errorCode, 'MISSING_OBSERVED_AT');
});

test('Canonical QNAME format p<N>.<runId>.<domain> and UDP/53 responder extraction accurately extract UUIDv4 and reject malformed/wrong-domain names', () => {
  const domain = 'leak.example.com';
  const uuid = crypto.randomUUID(); // e.g. 550e8400-e29b-41d4-a716-446655440000 (36 chars)

  // 1. Positive: Build & extract exact crypto.randomUUID() across probes p1, p2, p3
  for (const probeNum of [1, 2, 3]) {
    const qname = buildDnsLeakProbeQname(probeNum, uuid, domain);
    assert.equal(qname, `p${probeNum}.${uuid.toLowerCase()}.${domain}`);

    const parsedEval = parseDnsLeakProbeQname(qname, domain);
    assert.equal(parsedEval.valid, true);
    assert.equal(parsedEval.probeLabel, `p${probeNum}`);
    assert.equal(parsedEval.probeNumber, probeNum);
    assert.equal(parsedEval.runId, uuid.toLowerCase());
    assert.equal(parsedEval.baseDomain, domain);
    assert.equal(parsedEval.errorCode, null);

    // Verify UDP/53 responder (`cloudflare/authoritative-dns-udp53.mjs`) extracts the exact UUID without prefix/suffix
    const parsedUdp = parseDnsLeakQname(qname, domain);
    assert.ok(parsedUdp);
    assert.equal(parsedUdp.probeNumber, probeNum);
    assert.equal(parsedUdp.runId, uuid.toLowerCase());
    assert.equal(extractRunIdFromQname(qname, domain), uuid.toLowerCase());
  }

  // 2. Negative: Legacy hyphenated format `p1-<uuid>.<domain>` MUST be rejected (never extract `p1-<uuid>`)
  const hyphenatedQname = `p1-${uuid}.${domain}`;
  const hyphenEval = parseDnsLeakProbeQname(hyphenatedQname, domain);
  assert.equal(hyphenEval.valid, false);
  assert.equal(hyphenEval.errorCode, 'INVALID_QNAME_STRUCTURE');
  assert.equal(extractRunIdFromQname(hyphenatedQname, domain), null);
  assert.equal(parseDnsLeakQname(hyphenatedQname, domain), null);

  // 3. Negative: Prefixed UUID placed in runId slot (`p1.p1-<uuid>.<domain>`) MUST be rejected
  const prefixedSlotQname = `p1.p1-${uuid}.${domain}`;
  assert.equal(isValidDnsRunId(`p1-${uuid}`), false);
  assert.equal(parseDnsLeakProbeQname(prefixedSlotQname, domain).valid, false);
  assert.equal(extractRunIdFromQname(prefixedSlotQname, domain), null);

  // 4. Negative: Incomplete / invalid runId (too short < 8 chars, leading/trailing hyphen, > 63 chars)
  assert.equal(buildDnsLeakProbeQname(1, 'short1', domain), null);
  assert.equal(parseDnsLeakProbeQname(`p1.short1.${domain}`, domain).valid, false);
  assert.equal(parseDnsLeakProbeQname(`p1.short1.${domain}`, domain).errorCode, 'INVALID_RUN_ID_LABEL');
  assert.equal(extractRunIdFromQname(`p1.short1.${domain}`, domain), null);

  assert.equal(parseDnsLeakProbeQname(`p1.-badstart123.${domain}`, domain).valid, false);
  assert.equal(extractRunIdFromQname(`p1.-badstart123.${domain}`, domain), null);

  const label64Chars = 'a'.repeat(64); // Exceeds RFC 1035 63-octet label limit
  assert.equal(isValidDnsRunId(label64Chars), false);
  assert.equal(parseDnsLeakProbeQname(`p1.${label64Chars}.${domain}`, domain).valid, false);
  assert.equal(extractRunIdFromQname(`p1.${label64Chars}.${domain}`, domain), null);

  // 5. Negative: Wrong domain
  const wrongDomainQname = `p1.${uuid}.wrong.example.org`;
  const wrongDomainRes = parseDnsLeakProbeQname(wrongDomainQname, domain);
  assert.equal(wrongDomainRes.valid, false);
  assert.equal(wrongDomainRes.errorCode, 'QNAME_DOMAIN_MISMATCH');
  assert.equal(extractRunIdFromQname(wrongDomainQname, domain), null);

  // 6. Negative: Invalid QNAME structure (missing probe label, extra subdomain labels, invalid probe label)
  assert.equal(parseDnsLeakProbeQname(`${uuid}.${domain}`, domain).valid, false);
  assert.equal(extractRunIdFromQname(`${uuid}.${domain}`, domain), null);

  assert.equal(parseDnsLeakProbeQname(`extra.p1.${uuid}.${domain}`, domain).valid, false);
  assert.equal(extractRunIdFromQname(`extra.p1.${uuid}.${domain}`, domain), null);

  assert.equal(parseDnsLeakProbeQname(`x1.${uuid}.${domain}`, domain).valid, false);
  assert.equal(parseDnsLeakProbeQname(`x1.${uuid}.${domain}`, domain).errorCode, 'INVALID_PROBE_LABEL');
  assert.equal(extractRunIdFromQname(`x1.${uuid}.${domain}`, domain), null);

  assert.equal(parseDnsLeakProbeQname(`p0.${uuid}.${domain}`, domain).valid, false);
  assert.equal(extractRunIdFromQname(`p0.${uuid}.${domain}`, domain), null);

  // 7. Base domain validation
  assert.equal(isValidDnsLeakBaseDomain('leak.example.com'), true);
  assert.equal(isValidDnsLeakBaseDomain('localhost'), false);
  assert.equal(isValidDnsLeakBaseDomain('127.0.0.1'), false);
});

test('KV polling retention vs cross-run isolation and duplicate resolver deduplication work strictly', async () => {
  const kvStore = new Map<string, string>();
  const env: CloudflareEnv = {
    DNS_LEAK_DOMAIN: 'leak.example.com',
    DNS_COLLECTOR_API_TOKEN: 'secret-collector-token-2026',
    DNS_UDP53_VERIFIED: 'true',
    DNS_LOGS_KV: {
      async get(k) {
        return kvStore.get(k) ?? null;
      },
      async put(k, v) {
        kvStore.set(k, v);
      },
    },
  };

  const runIdA = crypto.randomUUID();
  const runIdB = crypto.randomUUID();
  const nowIso = new Date().toISOString();

  // 1. Ingest without qname is rejected with 400 MISSING_QNAME
  const missingQnameRes = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer secret-collector-token-2026',
      },
      body: JSON.stringify({
        runId: runIdA,
        resolverIp: '9.9.9.9',
        observedAt: nowIso,
      }),
    }),
    env
  );
  assert.equal(missingQnameRes.status, 400);
  const missingQnameJson: any = await missingQnameRes.json();
  assert.equal(missingQnameJson.errorCode, 'MISSING_QNAME');

  // 2. Ingest with legacy hyphenated qname `p1-<runId>.leak.example.com` is rejected with 400 INVALID_QNAME_FORMAT
  const badFormatRes = await cloudflareWorker.fetch(
    new Request('https://example.workers.dev/api/dns-collector/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer secret-collector-token-2026',
      },
      body: JSON.stringify({
        runId: runIdA,
        resolverIp: '9.9.9.9',
        qname: `p1-${runIdA}.leak.example.com`,
        observedAt: nowIso,
      }),
    }),
    env
  );
  assert.equal(badFormatRes.status, 400);
  const badFormatJson: any = await badFormatRes.json();
  assert.equal(badFormatJson.errorCode, 'INVALID_QNAME_FORMAT');

  // 3. Ingest 3 probes (p1, p2, p3) for runIdA all resolved by the SAME recursive resolver IP (9.9.9.9)
  for (const probeNum of [1, 2, 3]) {
    const ingestRes = await cloudflareWorker.fetch(
      new Request('https://example.workers.dev/api/dns-collector/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer secret-collector-token-2026',
        },
        body: JSON.stringify({
          runId: runIdA,
          resolverIp: probeNum === 2 ? '::ffff:9.9.9.9' : '9.9.9.9',
          isp: 'Quad9',
          asn: 'AS19281',
          countryCode: 'CH',
          qname: `p${probeNum}.${runIdA}.leak.example.com`,
          observedAt: nowIso,
        }),
      }),
      env
    );
    assert.equal(ingestRes.status, 200);
  }

  // 4. Sequential polling for runIdA succeeds across multiple polls AND deduplicates 9.9.9.9 to a SINGLE resolver witness (not 3!)
  for (let pollAttempt = 1; pollAttempt <= 2; pollAttempt++) {
    const pollRes = await cloudflareWorker.fetch(
      new Request(`https://example.workers.dev/api/dns-leak-probe?runId=${runIdA}`),
      env
    );
    assert.equal(pollRes.status, 200);
    const pollJson: any = await pollRes.json();
    assert.equal(pollJson.resolvers.length, 1);
    assert.equal(pollJson.resolvers[0].primaryIp, '9.9.9.9');
    assert.equal(pollJson.resolvers[0].runId, runIdA);
    assert.equal(pollJson.resolvers[0].queryName, `p1.${runIdA}.leak.example.com`);
  }

  // 5. Cross-run isolation: Polling for runIdB returns 0 resolvers (cannot reuse runIdA's evidence)
  const pollResB = await cloudflareWorker.fetch(
    new Request(`https://example.workers.dev/api/dns-leak-probe?runId=${runIdB}`),
    env
  );
  const pollJsonB: any = await pollResB.json();
  assert.equal(pollJsonB.resolvers.length, 0);

  // 6.Even if KV or collector returns runIdA's record when evaluating runIdB, evaluateDnsTestResult rejects it as RUN_ID_MISMATCH (INCONCLUSIVE)
  const crossRunEval = evaluateDnsTestResult({
    runId: runIdB,
    authoritativeConfigured: true,
    dnsLeakDomain: 'leak.example.com',
    resolvers: [
      {
        id: 'stolen-rec',
        name: 'Quad9',
        primaryIp: '9.9.9.9',
        asn: 'AS19281',
        isp: 'Quad9',
        location: 'CH',
        countryCode: 'CH',
        runId: runIdB, // Attacker rewrote runId field, but queryName still belongs to runIdA!
        queryName: `p1.${runIdA}.leak.example.com`,
        observedAt: nowIso,
        status: 'Observed',
        responseTimeMs: 15,
        isEncryptedDoH: true,
        observationMethod: 'authoritative_dns_log',
      },
    ],
    ipDetails: { status: 'PASS', ip: '9.9.9.9', countryCode: 'CH', asn: 'AS19281', isp: 'Quad9' } as any,
    startedAt: nowIso,
    completedAt: nowIso,
  });
  assert.equal(crossRunEval.status, 'INCONCLUSIVE');
  assert.equal(crossRunEval.errorCode, 'RUN_ID_MISMATCH');
});

test('Authoritative UDP/53 DNS packet responder enforces RFC 1035 QR=1 ignore, FORMERR, REFUSED, NXDOMAIN, NOTIMP, and NOERROR', () => {
  const allowedDomain = 'leak.example.com';
  const validRunId = crypto.randomUUID().toLowerCase();

  function encodeDnsQueryPacket(params: {
    txId?: number;
    flags?: number;
    qname: string;
    qtype?: number;
    qclass?: number;
  }): Buffer {
    const { txId = 0x1a2b, flags = 0x0100, qname, qtype = 1, qclass = 1 } = params;
    const header = Buffer.alloc(12);
    header.writeUInt16BE(txId, 0);
    header.writeUInt16BE(flags, 2);
    header.writeUInt16BE(1, 4); // QDCOUNT = 1

    const labelBuffers: Buffer[] = [];
    for (const label of qname.split('.').filter(Boolean)) {
      const ascii = Buffer.from(label, 'ascii');
      labelBuffers.push(Buffer.from([ascii.length]), ascii);
    }
    labelBuffers.push(Buffer.from([0x00])); // Root null terminator

    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(qtype, 0);
    tail.writeUInt16BE(qclass, 2);

    return Buffer.concat([header, ...labelBuffers, tail]);
  }

  // 1. Valid A query (QTYPE=1) for p1.<runId>.leak.example.com -> NOERROR (RCODE=0, AA=1, ANCOUNT=1) + observation extracted
  const validAQuery = encodeDnsQueryPacket({
    txId: 0x4321,
    qname: `p1.${validRunId}.${allowedDomain}`,
    qtype: 1,
  });
  const resA = evaluateDnsQueryPacket(validAQuery, allowedDomain);
  assert.equal(resA.ignore, false);
  assert.equal(resA.rcode, 0);
  assert.ok(resA.responseBuffer);
  assert.equal(resA.responseBuffer.readUInt16BE(0), 0x4321); // Preserves TXID
  assert.equal((resA.responseBuffer.readUInt16BE(2) & 0x8000) !== 0, true); // QR=1
  assert.equal((resA.responseBuffer.readUInt16BE(2) & 0x0400) !== 0, true); // AA=1
  assert.equal(resA.responseBuffer.readUInt16BE(2) & 0x000f, 0); // RCODE=0 (NOERROR)
  assert.equal(resA.responseBuffer.readUInt16BE(6), 1); // ANCOUNT=1 (0.0.0.0 A record)
  assert.ok(resA.observation);
  assert.equal(resA.observation.runId, validRunId);
  assert.equal(resA.observation.probeNumber, 1);

  // 2. Valid AAAA query (QTYPE=28) for p2.<runId>.leak.example.com -> NOERROR NODATA (RCODE=0, AA=1, ANCOUNT=0) + observation extracted
  const validAAAAQuery = encodeDnsQueryPacket({
    qname: `p2.${validRunId}.${allowedDomain}`,
    qtype: 28,
  });
  const resAAAA = evaluateDnsQueryPacket(validAAAAQuery, allowedDomain);
  assert.equal(resAAAA.ignore, false);
  assert.equal(resAAAA.rcode, 0);
  assert.equal(resAAAA.responseBuffer.readUInt16BE(6), 0); // ANCOUNT=0 (NODATA)
  assert.ok(resAAAA.observation);
  assert.equal(resAAAA.observation.runId, validRunId);
  assert.equal(resAAAA.observation.probeNumber, 2);

  // 3. Incoming packet with QR=1 (already a response) -> ignored to prevent UDP reflection loops
  const qr1Packet = encodeDnsQueryPacket({
    flags: 0x8180, // QR=1
    qname: `p1.${validRunId}.${allowedDomain}`,
    qtype: 1,
  });
  const resQr1 = evaluateDnsQueryPacket(qr1Packet, allowedDomain);
  assert.equal(resQr1.ignore, true);
  assert.equal(resQr1.responseBuffer, null);
  assert.equal(resQr1.observation, null);

  // 4. Out-of-domain query (e.g. google.com) -> REFUSED (RCODE=5, AA=0) and NO observation recorded
  const outOfZoneQuery = encodeDnsQueryPacket({
    qname: 'www.example.org',
    qtype: 1,
  });
  const resRefused = evaluateDnsQueryPacket(outOfZoneQuery, allowedDomain);
  assert.equal(resRefused.ignore, false);
  assert.equal(resRefused.rcode, 5); // REFUSED
  assert.equal((resRefused.responseBuffer.readUInt16BE(2) & 0x0400) !== 0, false); // AA=0
  assert.equal(resRefused.observation, null);

  // 5. In-domain query that does NOT match p<N>.<runId>.<domain> -> NXDOMAIN (RCODE=3, AA=1) and NO observation recorded
  const invalidSubdomainQuery = encodeDnsQueryPacket({
    qname: `unknown-host.${allowedDomain}`,
    qtype: 1,
  });
  const resNx = evaluateDnsQueryPacket(invalidSubdomainQuery, allowedDomain);
  assert.equal(resNx.ignore, false);
  assert.equal(resNx.rcode, 3); // NXDOMAIN
  assert.equal((resNx.responseBuffer.readUInt16BE(2) & 0x0400) !== 0, true); // AA=1
  assert.equal(resNx.observation, null);

  // 6. Unsupported QTYPE (e.g. AXFR=252) or QCLASS (e.g. CH=3) -> NOTIMP (RCODE=4) and NO observation recorded
  const axfrQuery = encodeDnsQueryPacket({
    qname: `p1.${validRunId}.${allowedDomain}`,
    qtype: 252,
  });
  const resNotImp = evaluateDnsQueryPacket(axfrQuery, allowedDomain);
  assert.equal(resNotImp.ignore, false);
  assert.equal(resNotImp.rcode, 4); // NOTIMP
  assert.equal(resNotImp.observation, null);

  // 7. Malformed DNS query packet (truncated question) -> FORMERR (RCODE=1)
  const malformedBuf = Buffer.alloc(14);
  malformedBuf.writeUInt16BE(0x9999, 0);
  malformedBuf.writeUInt16BE(0x0100, 2);
  malformedBuf.writeUInt16BE(1, 4); // QDCOUNT=1, but question is truncated
  malformedBuf[12] = 10; // Label length 10 exceeding buffer length
  const resFormErr = evaluateDnsQueryPacket(malformedBuf, allowedDomain);
  assert.equal(resFormErr.ignore, false);
  assert.equal(resFormErr.rcode, 1); // FORMERR
  assert.equal(resFormErr.observation, null);
});

