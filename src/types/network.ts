export type Language = 'fa' | 'en';

/**
 * Standardized test statuses:
 * - PASS / pass: Verified with sufficient real evidence
 * - LEAK_DETECTED / leak_detected: Confirmed leak based on real evidence
 * - WARNING / warning: Potential risk or direct connection without leak proof
 * - INCONCLUSIVE / inconclusive: Insufficient evidence to prove pass or leak
 * - UNSUPPORTED / unsupported: Feature not supported in current browser/environment
 * - ERROR / error: Test failed due to network/API/timeout error
 * - NOT_CONFIGURED / not_configured: External infrastructure (e.g., Authoritative DNS domain or API key) not configured
 * - IDLE / TESTING: Execution lifecycle states
 */
export type TestStatus =
  | 'IDLE'
  | 'TESTING'
  | 'PASS'
  | 'WARNING'
  | 'LEAK_DETECTED'
  | 'INCONCLUSIVE'
  | 'UNSUPPORTED'
  | 'ERROR'
  | 'NOT_CONFIGURED';

export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'none';

export interface StandardTestMetadata {
  status: TestStatus;
  testName: string;
  startedAt: string | null;
  completedAt: string | null;
  observations: string[];
  evidence: Record<string, unknown>;
  limitations: string[];
  errorCode: string | null;
  source: string;
  confidence: ConfidenceLevel;
}

export type BlacklistSourceStatus = 'clean' | 'flagged' | 'not_configured' | 'error' | 'unknown';

export interface IpBlacklistDetails {
  googleSafeBrowsingStatus: BlacklistSourceStatus;
  spamhausDnsblStatus: BlacklistSourceStatus;
  abuseIpDbStatus: BlacklistSourceStatus;
  abuseConfidenceScore: number | null;
  isGoogleFlagged: boolean | null;
  isSpamhausFlagged: boolean | null;
  isAbuseIpFlagged: boolean | null;
  verifiedSourcesCount: number;
  threatCategoryFa: string;
  threatCategoryEn: string;
}

export interface ObservedIpSource {
  sourceName: string;
  ip: string;
  version: 'IPv4' | 'IPv6';
  observedFrom: 'client_direct' | 'server_socket' | 'server_trusted_header';
  responseTimeMs: number;
}

export interface IpDetails extends StandardTestMetadata {
  ip: string | null;
  clientObservedIp: string | null;
  serverObservedIp: string | null;
  serverSocketIp: string | null;
  forwardedHeaderIp: string | null;
  proxyHeaderTrusted: boolean;
  ipSources: ObservedIpSource[];
  ipMismatchDetected: boolean;
  version: 'IPv4' | 'IPv6' | 'Unknown';
  countryName: string | null;
  countryCode: string | null;
  city: string | null;
  region: string | null;
  isp: string | null;
  asn: string | null;
  org: string | null;
  lat: number | null;
  lon: number | null;
  timezone: string | null;
  isGeoEstimated: boolean;

  usageType: 'Residential' | 'Commercial' | 'Datacenter' | 'Mobile' | 'Unknown';
  usageTypeFa: string;
  connectionType: 'VPN / Proxy Probable' | 'Direct Connection Probable' | 'Tor Exit Node' | 'Unknown';
  connectionTypeFa: string;
  isVpnOrProxyDetected: boolean | null;
  isDatacenter: boolean | null;

  fraudRiskScore: number | null;
  riskFactorsFa: string[];
  fraudStatusFa: string;
  fraudStatusEn: string;
  blacklistDetails: IpBlacklistDetails;
  userIntentAnalysisFa: string;
}

export interface DnsResolver {
  id: string;
  name: string;
  primaryIp: string;
  asn?: string;
  isp?: string;
  location: string;
  status: string;
  responseTimeMs: number | null;
  isEncryptedDoH: boolean | null;
  observationMethod: 'authoritative_dns_log' | 'doh_trace_observation' | 'server_system_resolver';
}

export interface IndependentBrowserDnsEntry {
  sourceName: string;
  observedIp: string;
  locationOrGeo: string;
  role: 'edns_recursive_resolver' | 'client_subnet_edns' | 'edge_trace_egress';
  responseTimeMs: number;
}

export interface IndependentBrowserDnsObservation {
  status: TestStatus;
  entries: IndependentBrowserDnsEntry[];
  matchesPrimaryEgressIp: boolean | null;
  summaryFa: string;
  summaryEn: string;
  limitationsFa: string[];
}

export interface DnsLeakResult extends StandardTestMetadata {
  runId: string;
  authoritativeConfigured: boolean;
  missingEnvVars?: string[];
  detectedResolversCount: number;
  resolvers: DnsResolver[];
  isLeaking: boolean | null;
  independentBrowserObservation?: IndependentBrowserDnsObservation;
  messageFa: string;
  messageEn: string;
}

export interface WebRtcCandidate {
  ip: string;
  version: 'IPv4' | 'IPv6' | 'mDNS';
  type: 'host' | 'srflx' | 'relay' | 'prflx' | 'unknown';
  protocol: string;
  port: number;
  isLocalLanIp: boolean;
  isPublicIp: boolean;
}

export interface WebRtcLeakResult extends StandardTestMetadata {
  isSupported: boolean;
  stunServersUsed: string[];
  localIps: string[];
  mdnsHosts: string[];
  publicCandidates: string[];
  isLeakingRealIp: boolean | null;
  candidates: WebRtcCandidate[];
  messageFa: string;
  messageEn: string;
}

export interface VpnProtocolDetails {
  name: string;
  code: 'wireguard' | 'openvpn' | 'l2tp' | 'v2ray' | 'direct' | 'unknown_protocol';
  isProvableFromBrowser: boolean;
  encryptionNameFa: string;
  estimatedMtu: number | null;
  obfuscationStatusFa: string;
  descriptionFa: string;
}

export interface VpnProxyResult extends StandardTestMetadata {
  score: number | null;
  isDatacenterIp: boolean | null;
  isTorNode: boolean | null;
  isKnownProxy: boolean | null;
  mismatchDnsCountry: boolean | null;
  encryptionStrength: string;
  protocolType: string;
  protocolDetails: VpnProtocolDetails;
  messageFa: string;
  messageEn: string;
}

export interface OptimalVpnNodeSuggestion {
  recommendedCountryNameFa: string;
  recommendedCountryCode: string;
  recommendedCityFa: string;
  estimatedPingMs: number | null;
  privacyRatingFa: string;
  recommendationReasonFa: string;
  recommendedProtocolsFa: string[];
  isHeuristicSuggestion: boolean;
}

export interface EncryptedDnsRecommendation {
  id: string;
  nameFa: string;
  provider: string;
  dohUrl: string;
  primaryIp: string;
  secondaryIp: string;
  estimatedPingMs: number | null;
  unfilteredStatusFa: string;
  featuresFa: string[];
}

export interface NetworkMetrics extends StandardTestMetadata {
  measurementMethod: 'HTTP_RTT';
  pingMs: number | null;
  jitterMs: number | null;
  downloadMbps: number | null;
  packetLossPercent: number | null;
  probesSent: number;
  probesReceived: number;
  bytesTransferred: number;
  durationMs: number;
  pingSamples: number[];
  stabilityScore: number | null;
  stabilityStatusFa: string;
  testingPing: boolean;
  testingSpeed: boolean;
}

export type PortProbeState = 'open' | 'closed' | 'filtered_timeout' | 'not_tested';

export type PortRiskCategory = 'router_admin' | 'remote_access' | 'proxy_relay' | 'file_share';

export interface PortProbeEntry {
  port: number;
  protocol: 'TCP';
  serviceName: string;
  category: PortRiskCategory;
  descriptionFa: string;
  descriptionEn: string;
  state: PortProbeState;
  responseTimeMs: number | null;
  riskLevel: 'critical' | 'high' | 'medium';
}

export interface PortLeakResult extends StandardTestMetadata {
  targetIp: string | null;
  targetSource: 'server_socket' | 'trusted_proxy_header' | 'unverifiable_local_socket';
  canScanFromServer: boolean;
  scannedPortsCount: number;
  openPortsCount: number;
  closedPortsCount: number;
  filteredPortsCount: number;
  openPorts: number[];
  isExposingSensitivePorts: boolean | null;
  ports: PortProbeEntry[];
  messageFa: string;
  messageEn: string;
}

export interface AiAuditReport {
  riskScore: number | null;
  statusLevel: 'امن' | 'هشدار' | 'خطر نشت' | 'نامشخص';
  summaryFa: string;
  detailedAnalysisFa: string[];
  threatsFoundFa: string[];
  recommendationsFa: string[];
  optimalNodeSuggestion?: OptimalVpnNodeSuggestion;
  dnsRecommendations?: EncryptedDnsRecommendation[];
  aiAvailable: boolean;
  generatedAt?: string;
}

export interface FullNetworkTestReport {
  timestamp: string;
  ipDetails: IpDetails | null;
  dnsLeak: DnsLeakResult | null;
  webRtcLeak: WebRtcLeakResult | null;
  vpnProxy: VpnProxyResult | null;
  portLeak?: PortLeakResult | null;
  metrics: NetworkMetrics | null;
  aiAudit: AiAuditReport | null;
  optimalNodeSuggestion?: OptimalVpnNodeSuggestion;
  dnsRecommendations?: EncryptedDnsRecommendation[];
  overallStatus: TestStatus;
  privacyScore: number | null;
  isScoreCalculable: boolean;
}

