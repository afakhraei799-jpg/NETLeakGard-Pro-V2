import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidIpv4,
  isValidIpv6,
  isPrivateOrLocalAddress,
  isGloballyRoutablePublicIp,
  formatTestStatusLabelFa,
  parseIceCandidateLine,
  evaluateWebRtcCandidates,
  evaluateDnsTestResult,
  evaluateIndependentBrowserDnsObservation,
  evaluateVpnHeuristic,
  calculateHttpPingMetrics,
  evaluatePortLeakResult,
  evaluateOverallSummary
} from './networkEvaluator';

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
  assert.equal(vpnRes.status, 'PASS');
  assert.equal(vpnRes.isDatacenterIp, true);
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
    runId: 'run-1',
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
    runId: 'run-2',
    authoritativeConfigured: true,
    resolvers: [
      {
        id: 'cf-1',
        name: 'Cloudflare',
        primaryIp: '1.1.1.1',
        asn: 'AS13335',
        isp: 'Cloudflare, Inc.',
        location: 'Anycast',
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
  assert.equal(validBrowserObs.status, 'PASS');

  // Even when independent browser observation succeeds, Authoritative DNS without env vars MUST remain NOT_CONFIGURED
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
  assert.equal(dnsResult.independentBrowserObservation?.status, 'PASS');
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

  // 2. Public IP with open router port 8291 -> LEAK_DETECTED
  const openPortRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: [
      {
        port: 8291,
        protocol: 'TCP',
        serviceName: 'MikroTik Winbox',
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
        serviceName: 'HTTP Router Admin',
        category: 'router_admin',
        descriptionFa: 'HTTP',
        descriptionEn: 'HTTP',
        state: 'closed',
        responseTimeMs: 15,
        riskLevel: 'critical',
      },
    ],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(openPortRes.status, 'LEAK_DETECTED');
  assert.equal(openPortRes.isExposingSensitivePorts, true);
  assert.deepEqual(openPortRes.openPorts, [8291]);

  // 3. Public IP with all ports closed/filtered -> PASS
  const closedPortRes = evaluatePortLeakResult({
    targetIp: '203.0.113.55',
    targetSource: 'server_socket',
    canScanFromServer: true,
    ports: [
      {
        port: 80,
        protocol: 'TCP',
        serviceName: 'HTTP Router Admin',
        category: 'router_admin',
        descriptionFa: 'HTTP',
        descriptionEn: 'HTTP',
        state: 'closed',
        responseTimeMs: 14,
        riskLevel: 'critical',
      },
    ],
    startedAt: now,
    completedAt: now,
  });
  assert.equal(closedPortRes.status, 'PASS');
  assert.equal(closedPortRes.isExposingSensitivePorts, false);
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


