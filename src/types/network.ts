export type Language = 'fa' | 'en';

export type TestStatus = 'IDLE' | 'TESTING' | 'PASS' | 'WARNING' | 'LEAK_DETECTED' | 'INCONCLUSIVE';

export interface IpBlacklistDetails {
  isGoogleFlagged: boolean;
  isSpamhausFlagged: boolean;
  isAbuseIpFlagged: boolean;
  threatCategoryFa: string;
  threatCategoryEn: string;
}

export interface IpDetails {
  ip: string;
  version: 'IPv4' | 'IPv6';
  countryName: string;
  countryCode: string;
  city: string;
  region: string;
  isp: string;
  asn: string;
  org: string;
  lat: number;
  lon: number;
  timezone: string;
  
  usageType: 'Residential' | 'Commercial' | 'Datacenter' | 'Mobile';
  usageTypeFa: 'مسکونی (خانگی / همراه)' | 'تجاری (شرکتی / دیتاسنتر)' | 'مرکز داده (Datacenter)' | 'اپراتور همراه';
  connectionType: 'VPN / Proxy Active' | 'Direct Connection' | 'Tor Exit Node';
  connectionTypeFa: 'اتصال تونل VPN / پروکسی فعال' | 'اتصال مستقیم خانگی (ISP)' | 'گره خروجی تور (Tor)';
  isVpnOrProxyDetected: boolean;
  isDatacenter: boolean;
  
  fraudRiskScore: number;
  fraudStatusFa: 'پاک و بدون سابقه کلاهبرداری' | 'مشکوک (ریسک متوسط)' | 'فلگ‌شده در لیست سیاه (پرریسک)';
  fraudStatusEn: 'Clean (Low Risk)' | 'Suspicious (Medium Risk)' | 'Flagged Fraud (High Risk)';
  blacklistDetails: IpBlacklistDetails;
  userIntentAnalysisFa: string;
}

export interface DnsResolver {
  id: string;
  name: string;
  primaryIp: string;
  location: string;
  status: string;
  responseTimeMs: number;
  isEncryptedDoH: boolean;
}

export interface DnsLeakResult {
  status: TestStatus;
  detectedResolversCount: number;
  resolvers: DnsResolver[];
  isLeaking: boolean;
  messageFa: string;
  messageEn: string;
}

export interface WebRtcCandidate {
  ip: string;
  type: 'host' | 'srflx' | 'relay';
  protocol: string;
  port: number;
  isLocalLanIp: boolean;
}

export interface WebRtcLeakResult {
  status: TestStatus;
  isSupported: boolean;
  localIps: string[];
  publicCandidates: string[];
  isLeakingRealIp: boolean;
  candidates: WebRtcCandidate[];
  messageFa: string;
  messageEn: string;
}

export interface VpnProtocolDetails {
  name: string;
  code: 'wireguard' | 'openvpn' | 'l2tp' | 'v2ray' | 'direct';
  encryptionNameFa: string;
  estimatedMtu: number;
  obfuscationStatusFa: string;
  descriptionFa: string;
}

export interface VpnProxyResult {
  status: TestStatus;
  score: number;
  isDatacenterIp: boolean;
  isTorNode: boolean;
  isKnownProxy: boolean;
  mismatchDnsCountry: boolean;
  encryptionStrength: 'عالی (ChaCha20 / AES-256)' | 'قوی (AES-256-GCM)' | 'متوسط (L2TP/IPsec)' | 'پایین / ضعیف';
  protocolType: string;
  protocolDetails: VpnProtocolDetails;
  messageFa: string;
  messageEn: string;
}

export interface OptimalVpnNodeSuggestion {
  recommendedCountryNameFa: string;
  recommendedCountryCode: string;
  recommendedCityFa: string;
  estimatedPingMs: number;
  privacyRatingFa: 'عالی (قوانین حریم خصوصی GDPR)' | 'بسیار خوب' | 'متوسط';
  recommendationReasonFa: string;
  recommendedProtocolsFa: string[];
}

export interface EncryptedDnsRecommendation {
  id: string;
  nameFa: string;
  provider: string;
  dohUrl: string;
  primaryIp: string;
  secondaryIp: string;
  estimatedPingMs: number;
  unfilteredStatusFa: string;
  featuresFa: string[];
}

export interface NetworkMetrics {
  pingMs: number;
  jitterMs: number;
  downloadMbps: number;
  packetLossPercent: number;
  pingSamples: number[];
  stabilityScore: number;
  stabilityStatusFa: 'پایدار و عالی' | 'دارای نوسان جزئی' | 'ناپایدار (Jitter بالا)';
  testingPing: boolean;
  testingSpeed: boolean;
}

export interface AiAuditReport {
  riskScore: number;
  statusLevel: 'امن' | 'هشدار' | 'خطر نشت';
  summaryFa: string;
  detailedAnalysisFa: string[];
  threatsFoundFa: string[];
  recommendationsFa: string[];
  optimalNodeSuggestion?: OptimalVpnNodeSuggestion;
  dnsRecommendations?: EncryptedDnsRecommendation[];
  aiAvailable: boolean;
}

export interface FullNetworkTestReport {
  timestamp: string;
  ipDetails: IpDetails | null;
  dnsLeak: DnsLeakResult | null;
  webRtcLeak: WebRtcLeakResult | null;
  vpnProxy: VpnProxyResult | null;
  metrics: NetworkMetrics | null;
  aiAudit: AiAuditReport | null;
  optimalNodeSuggestion?: OptimalVpnNodeSuggestion;
  dnsRecommendations?: EncryptedDnsRecommendation[];
  overallStatus: TestStatus;
  privacyScore: number;
}
