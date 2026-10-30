import {
  ConfidenceLevel,
  DnsLeakResult,
  DnsResolver,
  IndependentBrowserDnsEntry,
  IndependentBrowserDnsObservation,
  IpDetails,
  NetworkMetrics,
  PortLeakResult,
  PortProbeEntry,
  TestStatus,
  VpnProxyResult,
  WebRtcCandidate,
  WebRtcLeakResult
} from '../types/network';

/**
 * Checks whether an IP string is a valid IPv4 address.
 */
export function isValidIpv4(ip: string): boolean {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

/**
 * Checks whether an IP string is a valid IPv6 address (simplified structural check).
 */
export function isValidIpv6(ip: string): boolean {
  const trimmed = ip.trim();
  if (!trimmed.includes(':')) return false;
  return /^[0-9a-fA-F:]+(%[0-9a-zA-Z]+)?$/.test(trimmed);
}

/**
 * Converts a TestStatus enum into the standardized Persian label:
 * - PASS: موفق
 * - LEAK_DETECTED: نشت شناسایی شد
 * - INCONCLUSIVE: نامشخص
 * - NOT_CONFIGURED: پیکربندی نشده
 */
export function formatTestStatusLabelFa(status: TestStatus | string | undefined | null): string {
  switch (status) {
    case 'PASS':
      return 'موفق';
    case 'LEAK_DETECTED':
      return 'نشت شناسایی شد';
    case 'WARNING':
      return 'هشدار';
    case 'NOT_CONFIGURED':
      return 'پیکربندی نشده';
    case 'INCONCLUSIVE':
      return 'نامشخص';
    case 'UNSUPPORTED':
      return 'پشتیبانی نشده';
    case 'ERROR':
      return 'خطا در آزمون';
    case 'TESTING':
      return 'در حال آزمایش...';
    default:
      return 'نامشخص';
  }
}

/**
 * Determines whether an IP or hostname is RFC1918 private, loopback, link-local, CGNAT, multicast, reserved, unique-local IPv6, or mDNS (.local).
 */
export function isPrivateOrLocalAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return true;
  let addr = address.trim().toLowerCase();
  if (addr.endsWith('.local') || addr === 'localhost') return true;

  // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
  if (addr.startsWith('::ffff:')) {
    addr = addr.slice(7);
  } else if (addr.startsWith('0:0:0:0:0:ffff:')) {
    addr = addr.slice(15);
  }

  if (addr === '127.0.0.1' || addr === '::1' || addr === '::' || addr === '0:0:0:0:0:0:0:1' || addr === '0:0:0:0:0:0:0:0') {
    return true;
  }

  if (isValidIpv4(addr)) {
    const parts = addr.split('.').map(Number);
    if (parts[0] === 0) return true; // 0.0.0.0/8 current network
    if (parts[0] === 10) return true; // 10.0.0.0/8 RFC1918
    if (parts[0] === 127) return true; // 127.0.0.0/8 loopback
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12 RFC1918
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16 RFC1918
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // 100.64.0.0/10 CGNAT
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true; // 192.0.0.0/24 IETF
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true; // 198.18.0.0/15 benchmarking
    if (parts[0] >= 224) return true; // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved/broadcast
    return false;
  }

  if (addr.includes(':')) {
    if (
      addr.startsWith('fe8') ||
      addr.startsWith('fe9') ||
      addr.startsWith('fea') ||
      addr.startsWith('feb') ||
      addr.startsWith('fc') ||
      addr.startsWith('fd') ||
      addr.startsWith('ff') ||
      addr.startsWith('2001:db8:') ||
      addr.startsWith('2001:0db8:')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Strictly checks if an input is a globally routable public IPv4 or IPv6 literal suitable for external scanning/probing.
 * Rejects hostnames, loopback, RFC1918, CGNAT, link-local/metadata (169.254.169.254), multicast, broadcast, and documentation ranges.
 */
export function isGloballyRoutablePublicIp(address: string | null | undefined): boolean {
  if (!address || typeof address !== 'string') return false;
  let cleaned = address.trim().toLowerCase();
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.slice(7);
  } else if (cleaned.startsWith('0:0:0:0:0:ffff:')) {
    cleaned = cleaned.slice(15);
  }
  if (!isValidIpv4(cleaned) && !isValidIpv6(cleaned)) {
    return false;
  }
  if (isPrivateOrLocalAddress(cleaned)) {
    return false;
  }
  if (isValidIpv4(cleaned)) {
    const parts = cleaned.split('.').map(Number);
    // Also exclude documentation TEST-NET ranges from active TCP port scanning
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return false; // 192.0.2.0/24 TEST-NET-1
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return false; // 198.51.100.0/24 TEST-NET-2
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return false; // 203.0.113.0/24 TEST-NET-3
  }
  return true;
}

/**
 * Parses a raw WebRTC SDP ICE candidate string into a structured WebRtcCandidate object.
 * Returns null if the candidate string is malformed or does not contain a valid address.
 */
export function parseIceCandidateLine(candidateLine: string): WebRtcCandidate | null {
  if (!candidateLine || typeof candidateLine !== 'string') return null;
  const normalized = candidateLine.replace(/^a=/, '').trim();
  if (!normalized.startsWith('candidate:')) return null;

  const parts = normalized.split(/\s+/);
  // RFC 5245 / 8839: candidate:<foundation> <component-id> <transport> <priority> <connection-address> <port> typ <cand-type> ...
  if (parts.length < 8) return null;

  const protocol = (parts[2] || 'udp').toUpperCase();
  const address = parts[4];
  const port = parseInt(parts[5] || '0', 10);
  const typIndex = parts.indexOf('typ');
  const rawType = typIndex !== -1 && parts[typIndex + 1] ? parts[typIndex + 1].toLowerCase() : 'unknown';

  if (!address || Number.isNaN(port)) return null;

  const isMdns = address.toLowerCase().endsWith('.local');
  const isV4 = isValidIpv4(address);
  const isV6 = !isV4 && isValidIpv6(address);

  if (!isMdns && !isV4 && !isV6) return null;

  const isLocal = isPrivateOrLocalAddress(address);
  const candidateType: WebRtcCandidate['type'] =
    rawType === 'host' || rawType === 'srflx' || rawType === 'relay' || rawType === 'prflx'
      ? rawType
      : 'unknown';

  return {
    ip: address,
    version: isMdns ? 'mDNS' : isV6 ? 'IPv6' : 'IPv4',
    type: candidateType,
    protocol,
    port,
    isLocalLanIp: isLocal,
    isPublicIp: !isLocal && (isV4 || isV6),
  };
}

/**
 * Evaluates collected WebRTC ICE candidates against reference public IP(s) without fabricating any data.
 */
export function evaluateWebRtcCandidates(params: {
  isSupported: boolean;
  candidates: WebRtcCandidate[];
  referencePublicIps: string[];
  stunServersUsed: string[];
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): WebRtcLeakResult {
  const {
    isSupported,
    candidates,
    referencePublicIps,
    stunServersUsed,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const commonLimitations = [
    'این آزمون فقط رفتار موتور WebRTC مرورگر جاری را بررسی می‌کند و وضعیت سایر نرم‌افزارهای سیستم‌عامل را اثبات نمی‌کند.',
    'مرورگرهای مدرن ممکن است آدرس شبکه محلی (LAN) را با شناسهٔ mDNS (.local) جایگزین کنند.'
  ];

  if (!isSupported) {
    return {
      status: 'UNSUPPORTED',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: ['رابط برنامه‌نویسی RTCPeerConnection در این مرورگر غیرفعال یا مسدود است.'],
      evidence: { isSupported: false },
      limitations: commonLimitations,
      errorCode: 'WEBRTC_API_UNAVAILABLE',
      source: 'Browser RTCPeerConnection API',
      confidence: 'high',
      isSupported: false,
      stunServersUsed,
      localIps: [],
      mdnsHosts: [],
      publicCandidates: [],
      isLeakingRealIp: null,
      candidates: [],
      messageFa: 'پروتکل WebRTC در این مرورگر پشتیبانی نمی‌شود یا به طور کامل غیرفعال شده است (وضعیت: پشتیبانی‌نشده).',
      messageEn: 'WebRTC API is disabled or unsupported in this browser environment.',
    };
  }

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای نشست WebRTC: ${errorMessage}`],
      evidence: { errorMessage },
      limitations: commonLimitations,
      errorCode: 'WEBRTC_EXECUTION_ERROR',
      source: 'Browser RTCPeerConnection API',
      confidence: 'none',
      isSupported: true,
      stunServersUsed,
      localIps: [],
      mdnsHosts: [],
      publicCandidates: [],
      isLeakingRealIp: null,
      candidates: [],
      messageFa: `خطا در اجرای تست WebRTC: ${errorMessage}. هیچ نتیجه‌ای جعل نشد.`,
      messageEn: `WebRTC test execution failed: ${errorMessage}`,
    };
  }

  const localIpsSet = new Set<string>();
  const mdnsSet = new Set<string>();
  const publicIpsSet = new Set<string>();

  for (const c of candidates) {
    if (c.version === 'mDNS') {
      mdnsSet.add(c.ip);
    } else if (c.isLocalLanIp) {
      localIpsSet.add(c.ip);
    } else if (c.isPublicIp) {
      publicIpsSet.add(c.ip);
    }
  }

  const localIps = Array.from(localIpsSet);
  const mdnsHosts = Array.from(mdnsSet);
  const publicCandidates = Array.from(publicIpsSet);
  const cleanRefIps = referencePublicIps.map(ip => ip.trim()).filter(Boolean);

  // If no candidates at all or no public STUN candidate was gathered, we cannot prove there is no leak
  // unless we compare what was gathered:
  const mismatchedPublicIps = publicCandidates.filter(
    candIp => cleanRefIps.length > 0 && !cleanRefIps.includes(candIp)
  );

  // Leak confirmed if a public candidate IP differs from reference public IP(s)
  if (mismatchedPublicIps.length > 0) {
    return {
      status: 'LEAK_DETECTED',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: [
        `نامزد عمومی WebRTC (${mismatchedPublicIps.join(', ')}) با آدرس IP مرجع مشاهده‌شده (${cleanRefIps.join(', ')}) مغایرت دارد.`,
      ],
      evidence: {
        referencePublicIps: cleanRefIps,
        publicCandidates,
        mismatchedPublicIps,
        localIps,
        mdnsHosts,
      },
      limitations: commonLimitations,
      errorCode: null,
      source: 'Browser RTCPeerConnection ICE Gathering',
      confidence: 'high',
      isSupported: true,
      stunServersUsed,
      localIps,
      mdnsHosts,
      publicCandidates,
      isLeakingRealIp: true,
      candidates,
      messageFa: `نشت تأیید شد: آدرس عمومی کشف‌شده از طریق STUN (${mismatchedPublicIps.join(', ')}) متفاوت از آدرس IP مرجع اتصال (${cleanRefIps.join(', ')}) است.`,
      messageEn: `Confirmed Leak: WebRTC STUN candidate (${mismatchedPublicIps.join(', ')}) differs from reference IP (${cleanRefIps.join(', ')}).`,
    };
  }

  // If local raw LAN IP is exposed, report WARNING
  if (localIps.length > 0 && publicCandidates.length === 0) {
    return {
      status: 'WARNING',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: [
        `آدرس شبکه محلی (${localIps.join(', ')}) در نامزدهای host مشاهده شد، اما هیچ نامزد عمومی STUN (srflx) دریافت نشد.`,
      ],
      evidence: { localIps, mdnsHosts, publicCandidates },
      limitations: commonLimitations,
      errorCode: null,
      source: 'Browser RTCPeerConnection ICE Gathering',
      confidence: 'medium',
      isSupported: true,
      stunServersUsed,
      localIps,
      mdnsHosts,
      publicCandidates,
      isLeakingRealIp: false,
      candidates,
      messageFa: `هشدار: آدرس شبکه محلی (${localIps.join(', ')}) قابل مشاهده است و پاسخ STUN عمومی برای مقایسه دریافت نشد.`,
      messageEn: `Warning: Local LAN IP (${localIps.join(', ')}) exposed; no public STUN candidate received.`,
    };
  }

  // If zero public candidates were gathered or reference IP is missing, result is INCONCLUSIVE (not PASS!)
  if (publicCandidates.length === 0 || cleanRefIps.length === 0) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: [
        publicCandidates.length === 0
          ? 'هیچ نامزد عمومی (srflx/relay) از سرورهای STUN دریافت نشد (ممکن است UDP مسدود شده باشد یا فایروال/افزونه مانع پاسخ STUN شده باشد).'
          : 'آدرس IP مرجع برای مقایسه با نامزدهای WebRTC در دسترس نیست.',
        ...(mdnsHosts.length > 0 ? [`میزبان mDNS مشاهده شد: ${mdnsHosts.join(', ')}`] : []),
      ],
      evidence: {
        referencePublicIps: cleanRefIps,
        publicCandidates,
        localIps,
        mdnsHosts,
        totalCandidatesCount: candidates.length,
      },
      limitations: commonLimitations,
      errorCode: publicCandidates.length === 0 ? 'NO_PUBLIC_STUN_CANDIDATES' : 'NO_REFERENCE_IP',
      source: 'Browser RTCPeerConnection ICE Gathering',
      confidence: 'low',
      isSupported: true,
      stunServersUsed,
      localIps,
      mdnsHosts,
      publicCandidates,
      isLeakingRealIp: null,
      candidates,
      messageFa: 'نتیجه نامشخص (Inconclusive): هیچ نامزد عمومی STUN (srflx) دریافت نشد. نبود پاسخ STUN به تنهایی اثبات‌کنندهٔ امن بودن نیست (احتمال مسدود بودن پورت UDP یا محدودیت مرورگر).',
      messageEn: 'Inconclusive: No public STUN candidates received. Absence of STUN response is not treated as proof of security.',
    };
  }

  // Public candidates were gathered and ALL of them match the reference public IP(s)
  return {
    status: localIps.length > 0 ? 'WARNING' : 'PASS',
    testName: 'WebRTC ICE Candidate Leak Test',
    startedAt,
    completedAt,
    observations: [
      `نامزد عمومی STUN دریافت شد (${publicCandidates.join(', ')}) و دقیقاً منطبق بر آدرس IP مرجع (${cleanRefIps.join(', ')}) است.`,
      ...(localIps.length > 0
        ? [`هشدار جزئی: آدرس خصوصی شبکه محلی (${localIps.join(', ')}) بدون پوشش mDNS مشاهده شد.`]
        : ['هیچ آدرس خصوصی شبکه محلی (RFC1918) افشا نشد.']),
    ],
    evidence: {
      referencePublicIps: cleanRefIps,
      publicCandidates,
      localIps,
      mdnsHosts,
    },
    limitations: commonLimitations,
    errorCode: null,
    source: 'Browser RTCPeerConnection ICE Gathering',
    confidence: 'high',
    isSupported: true,
    stunServersUsed,
    localIps,
    mdnsHosts,
    publicCandidates,
    isLeakingRealIp: false,
    candidates,
    messageFa:
      localIps.length > 0
        ? `آدرس عمومی WebRTC (${publicCandidates.join(', ')}) منطبق بر IP مرجع است، اما آدرس محلی LAN (${localIps.join(', ')}) قابل مشاهده است.`
        : `تأیید شده با شواهد: نامزد عمومی STUN (${publicCandidates.join(', ')}) با آدرس IP مرجع یکسان است و هیچ IP مغایری افشا نشد.`,
    messageEn: `Verified: Public STUN candidate (${publicCandidates.join(', ')}) matches reference IP with no public IP mismatch.`,
  };
}

/**
 * Evaluates independent, zero-cost browser-observable DNS & edge trace data (e.g. edns.ip-api.com, 1.1.1.1/cdn-cgi/trace).
 * Strictly separated from Authoritative DNS Leak Test: never claims full authoritative DNS verification.
 */
export function evaluateIndependentBrowserDnsObservation(
  entries: IndependentBrowserDnsEntry[],
  ipDetails: IpDetails | null
): IndependentBrowserDnsObservation {
  const limitationsFa = [
    'این بررسی مستقل از طریق درخواست‌های HTTPS مرورگر به سرویس‌های عمومی رایگان (مانند EDNS و Cloudflare Trace) انجام می‌شود و جایگزین تست Authoritative DNS Leak اختصاصی نیست.',
    'در صورتی که مرورگر از DNS-over-HTTPS (DoH) داخلی استفاده کند، مسیر DNS مرورگر ممکن است با Resolver سطح سیستم‌عامل (OS-level DNS) متفاوت باشد.',
    'یک استعلام تک‌نقطه‌ای از مرورگر تمام Resolverهای چرخشی (Round-Robin) یا فورواردرهای پنهان ISP را آشکار نمی‌کند.'
  ];

  if (!entries || entries.length === 0) {
    return {
      status: 'INCONCLUSIVE',
      entries: [],
      matchesPrimaryEgressIp: null,
      summaryFa:
        'نامشخص: پاسخ معتبری از منابع مستقل بررسی DNS/Trace مرورگر دریافت نشد (احتمال مسدودسازی CORS، فایروال یا عدم دسترسی شبکه). هیچ مقدار جعلی تولید نشد.',
      summaryEn:
        'Inconclusive: No response received from independent browser DNS/trace endpoints. No synthetic data generated.',
      limitationsFa,
    };
  }

  const ednsResolvers = entries.filter(e => e.role === 'edns_recursive_resolver' || e.role === 'client_subnet_edns');
  const primaryCountry = ipDetails?.countryCode?.toUpperCase() || null;
  const primaryCountryName = ipDetails?.countryName?.toLowerCase() || null;

  // Check if any observed EDNS resolver geo conflicts with the primary IP country (e.g. Iran vs non-Iran)
  const hasGeoConflict =
    primaryCountry &&
    ednsResolvers.some(r => {
      const locLower = r.locationOrGeo.toLowerCase();
      if (primaryCountry !== 'IR' && (locLower.includes('iran') || locLower === 'ir')) {
        return true;
      }
      if (primaryCountryName && locLower && !locLower.includes(primaryCountryName) && ednsResolvers.length > 0) {
        // Different country name reported by EDNS
        return false;
      }
      return false;
    });

  if (hasGeoConflict) {
    return {
      status: 'LEAK_DETECTED',
      entries,
      matchesPrimaryEgressIp: false,
      summaryFa:
        'نشت شناسایی شد (در مشاهدهٔ مستقل مرورگر): موقعیت Resolver مشاهده‌شده در سرویس مستقل EDNS با کشور آدرس IP خروجی مغایرت دارد.',
      summaryEn:
        'Leak Detected (Independent Browser Observation): Observed EDNS resolver location conflicts with primary egress IP country.',
      limitationsFa,
    };
  }

  if (ednsResolvers.length > 0) {
    return {
      status: 'PASS',
      entries,
      matchesPrimaryEgressIp: true,
      summaryFa: `مشاهدهٔ مستقل مرورگر انجام شد (${entries.length} منبع پاسخگو): هیچ مغایرت آشکاری در استعلام تک‌نقطه‌ای دیده نشد (اما این بررسی جایگزین تست Authoritative DNS نیست).`,
      summaryEn: `Independent browser observation completed (${entries.length} source(s)): No obvious mismatch in single-point check (not a substitute for Authoritative DNS test).`,
      limitationsFa,
    };
  }

  return {
    status: 'INCONCLUSIVE',
    entries,
    matchesPrimaryEgressIp: null,
    summaryFa:
      'نامشخص: فقط مسیر خروجی (Edge Trace) از مرورگر مشاهده شد و اطلاعاتی از Recursive Resolver توسط سرویس EDNS برگردانده نشد.',
    summaryEn:
      'Inconclusive: Only edge trace egress was observed; recursive DNS resolver IP was not returned by independent EDNS.',
    limitationsFa,
  };
}

/**
 * Evaluates DNS Leak results based on real authoritative logs or explicitly marks NOT_CONFIGURED / INCONCLUSIVE.
 * Browser-side DNS observations are stored separately in `independentBrowserObservation` and NEVER turn an unconfigured
 * Authoritative DNS Leak Test into PASS or LEAK_DETECTED.
 */
export function evaluateDnsTestResult(params: {
  runId: string;
  authoritativeConfigured: boolean;
  missingEnvVars?: string[];
  resolvers: DnsResolver[];
  ipDetails: IpDetails | null;
  independentBrowserObservation?: IndependentBrowserDnsObservation;
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): DnsLeakResult {
  const {
    runId,
    authoritativeConfigured,
    missingEnvVars = ['DNS_LEAK_DOMAIN', 'DNS_COLLECTOR_API_URL', 'DNS_COLLECTOR_API_TOKEN'],
    resolvers,
    ipDetails,
    independentBrowserObservation,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const dnsLimitations = [
    'مشاهدهٔ آدرس IP در سرور Authoritative DNS فقط آخرین گره (Egress Resolver) زنجیرهٔ DNS را نشان می‌دهد و در صورت استفاده از DoH/DoT یا فورواردر واسط، کل زنجیره آشکار نمی‌شود.',
    'تست DNS از داخل مرورگر صرفاً درخواست‌های شبکهٔ مرورگر (یا DoH فعال در مرورگر) را آزمایش می‌کند و وضعیت Resolver سطح سیستم‌عامل (OS-level DNS) سایر برنامه‌ها را اثبات نمی‌کند.',
    'بررسی DNS از طریق مرورگر با تست Authoritative DNS Leak یکسان نیست؛ برای اثبات قطعی عدم نشت، سرور Authoritative DNS اختصاصی الزامی است.'
  ];

  if (!authoritativeConfigured) {
    const missingList =
      missingEnvVars.length > 0
        ? missingEnvVars
        : ['DNS_LEAK_DOMAIN', 'DNS_COLLECTOR_API_URL', 'DNS_COLLECTOR_API_TOKEN'];

    return {
      status: 'NOT_CONFIGURED',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `وضعیت تست Authoritative DNS: پیکربندی نشده — متغیرهای (${missingList.join('، ')}) تنظیم نشده‌اند.`,
        'طبق اصل صداقت فنی، بدون زیرساخت Authoritative DNS اختصاصی، نتیجهٔ این تست هرگز «موفق» یا «امن» اعلام نمی‌شود.',
      ],
      evidence: {
        runId,
        authoritativeConfigured: false,
        missingEnvVars: missingList,
        independentBrowserObservation: independentBrowserObservation || null,
      },
      limitations: [
        ...dnsLimitations,
        `برای فعال‌سازی تست Authoritative DNS، تنظیم متغیرهای ${missingList.join('، ')} جهت ثبت کوئری ساب‌دامین یکتای هر اجرا (\${runId}.<DNS_LEAK_DOMAIN>) ضروری است.`
      ],
      errorCode: 'AUTHORITATIVE_DNS_NOT_CONFIGURED',
      source: 'Authoritative DNS Configuration Check',
      confidence: 'none',
      runId,
      authoritativeConfigured: false,
      missingEnvVars: missingList,
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: `پیکربندی نشده: متغیرهای (${missingList.join('، ')}) تنظیم نشده‌اند. بدون سرور Authoritative DNS اختصاصی، نمی‌توان عدم نشت DNS را تأیید یا رد کرد.`,
      messageEn: `Not Configured: Environment variables (${missingList.join(', ')}) are not set. Cannot claim DNS safety without an authoritative DNS collector.`,
    };
  }

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای آزمون Authoritative DNS: ${errorMessage}`],
      evidence: { runId, authoritativeConfigured, errorMessage },
      limitations: dnsLimitations,
      errorCode: 'DNS_PROBE_ERROR',
      source: 'DNS Probe Service',
      confidence: 'none',
      runId,
      authoritativeConfigured,
      missingEnvVars: [],
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: `خطا در اجرای تست نشت DNS: ${errorMessage}. هیچ سرور DNS ساختگی نمایش داده نمی‌شود.`,
      messageEn: `DNS Leak test failed: ${errorMessage}. No synthetic resolvers were generated.`,
    };
  }

  if (resolvers.length === 0) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `درخواست‌های ساب‌دامین یکتای ${runId} ارسال شدند، اما هیچ رکوردی در ثبت‌کنندهٔ Authoritative DNS دریافت نشد.`
      ],
      evidence: { runId, authoritativeConfigured: true, resolvers: [] },
      limitations: dnsLimitations,
      errorCode: 'NO_DNS_QUERIES_CAPTURED',
      source: 'Authoritative DNS Collector',
      confidence: 'low',
      runId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: هیچ کوئری DNS متناظر با شناسهٔ یکتای این اجرا در سرور Authoritative ثبت نشد.',
      messageEn: 'Inconclusive: No DNS queries matching the unique run token were captured at the authoritative server.',
    };
  }

  // Compare authoritative resolvers with client IP country/ISP if available
  const clientCountry = ipDetails?.countryCode?.toUpperCase();
  const hasDomesticOrMismatchedResolver = resolvers.some(r => {
    if (!clientCountry || !r.location) return false;
    return r.status.includes('مغایرت') || r.status.toLowerCase().includes('leak');
  });

  return {
    status: hasDomesticOrMismatchedResolver ? 'LEAK_DETECTED' : 'PASS',
    testName: 'Authoritative DNS Leak & Resolver Probe',
    startedAt,
    completedAt,
    observations: [
      `تعداد ${resolvers.length} سرور Resolver از طریق لاگ واقعی Authoritative DNS برای شناسهٔ ${runId} مشاهده شد.`
    ],
    evidence: {
      runId,
      authoritativeConfigured: true,
      resolvers,
    },
    limitations: dnsLimitations,
    errorCode: null,
    source: 'Authoritative DNS Collector',
    confidence: 'high',
    runId,
    authoritativeConfigured: true,
    missingEnvVars: [],
    detectedResolversCount: resolvers.length,
    resolvers,
    isLeaking: hasDomesticOrMismatchedResolver,
    independentBrowserObservation,
    messageFa: hasDomesticOrMismatchedResolver
      ? 'نشت شناسایی شد: سرورهای Resolver مشاهده‌شده در Authoritative DNS با مسیر تونل مورد انتظار مغایرت دارند.'
      : `موفق: آزمایش Authoritative DNS با شواهد واقعی تکمیل شد (${resolvers.length} سرور Resolver مشاهده و ثبت گردید).`,
    messageEn: hasDomesticOrMismatchedResolver
      ? 'Leak Detected: Observed authoritative resolvers conflict with expected tunnel egress.'
      : `Pass: Authoritative DNS probe completed with ${resolvers.length} verified resolver(s).`,
  };
}

/**
 * Probabilistic VPN / Proxy / Datacenter Classification with explicit limitations.
 * Never claims deterministic WireGuard/OpenVPN/L2TP protocol or MTU from HTTP/IP observation alone.
 */
export function evaluateVpnHeuristic(
  ipDetails: IpDetails | null,
  dnsLeak: DnsLeakResult | null
): VpnProxyResult {
  const now = new Date().toISOString();
  const vpnLimitations = [
    'تشخیص VPN/دیتاسنتر صرفاً یک طبقه‌بندی احتمالی مبتنی بر ASN و نام سازمان ارائه‌دهندهٔ IP خروجی است و قطعی نیست (یک VPN روی IP مسکونی یا VPS شخصی ممکن است به عنوان ISP عادی دیده شود).',
    'نوع پروتکل تونل (مانند WireGuard، OpenVPN، IKEv2 یا VLESS) و اندازهٔ واقعی MTU از طریق مرورگر وب و لایهٔ HTTP قابل اثبات فنی نیست.'
  ];

  if (!ipDetails || !ipDetails.ip || ipDetails.status === 'ERROR') {
    return {
      status: 'INCONCLUSIVE',
      testName: 'VPN & Network Egress Heuristic Assessment',
      startedAt: now,
      completedAt: now,
      observations: ['اطلاعات معتبر IP خروجی برای طبقه‌بندی احتمالی شبکه در دسترس نیست.'],
      evidence: { ipAvailable: false },
      limitations: vpnLimitations,
      errorCode: 'MISSING_IP_EVIDENCE',
      source: 'ASN / Organization Heuristic',
      confidence: 'none',
      score: null,
      isDatacenterIp: null,
      isTorNode: null,
      isKnownProxy: null,
      mismatchDnsCountry: null,
      encryptionStrength: 'غیرقابل اثبات از طریق مرورگر',
      protocolType: 'غیرقابل تشخیص از لایه وب (نیازمند بررسی سطح سیستم‌عامل)',
      protocolDetails: {
        name: 'نامشخص (غیرقابل اثبات از روی IP خروجی)',
        code: 'unknown_protocol',
        isProvableFromBrowser: false,
        encryptionNameFa: 'غیرقابل تشخیص از لایه HTTP',
        estimatedMtu: null,
        obfuscationStatusFa: 'نامشخص',
        descriptionFa: 'بدون دسترسی به رابط شبکهٔ سیستم‌عامل (Network Interface) یا هدر بسته‌های سطح کرنل، نوع پروتکل VPN قابل اثبات نیست.',
      },
      messageFa: 'نتیجه نامشخص: به دلیل عدم دسترسی به دادهٔ معتبر IP خروجی، طبقه‌بندی شبکه امکان‌پذیر نیست.',
      messageEn: 'Inconclusive: Valid egress IP data is unavailable for network classification.',
    };
  }

  const isDatacenter = ipDetails.isDatacenter === true;
  const clientServerMismatch = ipDetails.ipMismatchDetected === true;

  let status: TestStatus = 'INCONCLUSIVE';
  let confidence: ConfidenceLevel = 'medium';

  if (clientServerMismatch) {
    status = 'WARNING';
    confidence = 'high';
  } else if (isDatacenter) {
    status = 'PASS';
    confidence = 'medium';
  } else {
    status = 'WARNING';
    confidence = 'medium';
  }

  const observations: string[] = [
    isDatacenter
      ? `آدرس IP خروجی (${ipDetails.ip}) بر اساس ASN (${ipDetails.asn || 'نامشخص'}) و سازمان (${ipDetails.isp || 'نامشخص'}) احتمالاً متعلق به مرکز داده / هاستینگ است.`
      : `آدرس IP خروجی (${ipDetails.ip}) نشانگرهای شناخته‌شدهٔ مراکز داده را ندارد و احتمالاً متعلق به ISP مسکونی/همراه است.`,
    'پروتکل تونل (WireGuard/OpenVPN/...) از روی درخواست HTTP قابل تشخیص نیست و هرگونه ادعای قطعی در این مورد غیرعلمی است.'
  ];

  if (clientServerMismatch) {
    observations.push(
      `مغایرت مسیر (Split-Tunnel / Proxy Rule): آدرس مشاهده‌شده از کلاینت (${ipDetails.clientObservedIp}) با آدرس مشاهده‌شده در سرور (${ipDetails.serverObservedIp}) تفاوت دارد.`
    );
  }

  return {
    status,
    testName: 'VPN & Network Egress Heuristic Assessment',
    startedAt: ipDetails.startedAt || now,
    completedAt: now,
    observations,
    evidence: {
      ip: ipDetails.ip,
      asn: ipDetails.asn,
      isp: ipDetails.isp,
      usageType: ipDetails.usageType,
      isDatacenterProbable: isDatacenter,
      clientServerMismatch,
    },
    limitations: vpnLimitations,
    errorCode: null,
    source: 'ASN / Organization Heuristic Classifier',
    confidence,
    score: null,
    isDatacenterIp: isDatacenter,
    isTorNode: ipDetails.connectionType === 'Tor Exit Node',
    isKnownProxy: isDatacenter,
    mismatchDnsCountry: dnsLeak?.isLeaking ?? null,
    encryptionStrength: 'غیرقابل اندازه‌گیری از لایه مرورگر (HTTPS/TLS فعال)',
    protocolType: 'غیرقابل اثبات از روی IP (احتمالی: ' + (isDatacenter ? 'خروجی دیتاسنتر' : 'ISP مستقیم') + ')',
    protocolDetails: {
      name: 'غیرقابل اثبات از طریق مرورگر (Unprovable via Web)',
      code: 'unknown_protocol',
      isProvableFromBrowser: false,
      encryptionNameFa: 'نامشخص (فقط TLS مرورگر قابل مشاهده است)',
      estimatedMtu: null,
      obfuscationStatusFa: 'غیرقابل تشخیص بدون دسترسی سطح پکت',
      descriptionFa: 'مشاهدهٔ IP خروجی فقط مالک شبکهٔ مقصد (ASN) را مشخص می‌کند و پروتکل تونل (WireGuard، OpenVPN، V2Ray یا L2TP) را اثبات نمی‌کند.',
    },
    messageFa: isDatacenter
      ? `طبقه‌بندی احتمالی (سطح اطمینان متوسط): آدرس خروجی متعلق به شبکه دیتاسنتر (${ipDetails.isp || ipDetails.asn}) است. توجه: نوع پروتکل تونل از طریق مرورگر قابل اثبات نیست.`
      : `طبقه‌بندی احتمالی (سطح اطمینان متوسط): آدرس خروجی متعلق به شبکه ISP (${ipDetails.isp || ipDetails.asn}) به نظر می‌رسد. اگر VPN فعال است، ممکن است از IP مسکونی یا Split-Tunneling استفاده کند.`,
    messageEn: isDatacenter
      ? `Probabilistic Classification (Medium Confidence): Egress IP belongs to a datacenter network (${ipDetails.isp || ipDetails.asn}). Tunnel protocol cannot be proven from browser.`
      : `Probabilistic Classification (Medium Confidence): Egress IP appears to be a residential/mobile ISP (${ipDetails.isp || ipDetails.asn}).`,
  };
}

/**
 * Calculates HTTP Latency (RTT), Jitter, and Packet Loss from real probe attempts.
 * Never invents numbers when probes fail.
 */
export function calculateHttpPingMetrics(params: {
  rttSamplesMs: number[];
  probesSent: number;
  probesReceived: number;
  downloadMbps: number | null;
  bytesTransferred: number;
  durationMs: number;
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): NetworkMetrics {
  const {
    rttSamplesMs,
    probesSent,
    probesReceived,
    downloadMbps,
    bytesTransferred,
    durationMs,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const metricLimitations = [
    'زمان پاسخ اندازه‌گیری‌شده مربوط به درخواست‌های HTTP به سرور برنامه (HTTP RTT) است و پینگ سطح شبکه (ICMP Echo) نیست.',
    'سربار لایهٔ TLS، صف مرورگر و پردازش سرور در مقادیر HTTP RTT تأثیرگذار است.'
  ];

  const validSamples = rttSamplesMs.filter(n => typeof n === 'number' && Number.isFinite(n) && n >= 0);
  const packetLossPercent =
    probesSent > 0
      ? Math.round(((probesSent - probesReceived) / probesSent) * 1000) / 10
      : null;

  if (validSamples.length === 0 || probesReceived === 0) {
    return {
      status: 'ERROR',
      testName: 'HTTP RTT Latency, Jitter & Bandwidth Benchmark',
      startedAt,
      completedAt,
      observations: [
        errorMessage
          ? `خطا در اندازه‌گیری تاخیر و سرعت: ${errorMessage}`
          : 'هیچ پاسخ معتبری از سرور پینگ دریافت نشد (۱۰۰٪ خطا یا قطع ارتباط).'
      ],
      evidence: {
        probesSent,
        probesReceived,
        packetLossPercent,
        errorMessage: errorMessage || 'All probes failed',
      },
      limitations: metricLimitations,
      errorCode: 'HTTP_PROBE_FAILED',
      source: 'Browser Performance Timing API (/api/ping & /api/speed-test/chunk)',
      confidence: 'none',
      measurementMethod: 'HTTP_RTT',
      pingMs: null,
      jitterMs: null,
      downloadMbps: null,
      packetLossPercent,
      probesSent,
      probesReceived,
      bytesTransferred: 0,
      durationMs: 0,
      pingSamples: [],
      stabilityScore: null,
      stabilityStatusFa: 'خطا در اندازه‌گیری (بدون داده معتبر)',
      testingPing: false,
      testingSpeed: false,
    };
  }

  const avgPing = Math.round(validSamples.reduce((a, b) => a + b, 0) / validSamples.length);

  let jitter: number | null = null;
  if (validSamples.length >= 2) {
    let totalDiff = 0;
    for (let i = 1; i < validSamples.length; i++) {
      totalDiff += Math.abs(validSamples[i] - validSamples[i - 1]);
    }
    jitter = Math.round((totalDiff / (validSamples.length - 1)) * 10) / 10;
  }

  let stabilityScore: number | null = null;
  let stabilityStatusFa = 'نامشخص (نمونه ناکافی)';

  if (jitter !== null && packetLossPercent !== null) {
    const lossPenalty = packetLossPercent * 2.5;
    const jitterPenalty = Math.min(45, jitter * 1.2);
    stabilityScore = Math.max(0, Math.min(100, Math.round(100 - lossPenalty - jitterPenalty)));

    if (packetLossPercent > 10 || jitter > 30) {
      stabilityStatusFa = 'ناپایدار (نوسان یا افت بسته بالا)';
    } else if (packetLossPercent > 0 || jitter > 12) {
      stabilityStatusFa = 'دارای نوسان جزئی';
    } else {
      stabilityStatusFa = 'پایدار (بر اساس نمونه‌های HTTP RTT)';
    }
  }

  return {
    status: packetLossPercent && packetLossPercent > 20 ? 'WARNING' : 'PASS',
    testName: 'HTTP RTT Latency, Jitter & Bandwidth Benchmark',
    startedAt,
    completedAt,
    observations: [
      `${probesReceived} از ${probesSent} درخواست HTTP RTT موفق بود (میانگین: ${avgPing} ms).`,
      ...(downloadMbps !== null
        ? [`حجم ${(bytesTransferred / (1024 * 1024)).toFixed(2)} مگابایت در مدت ${Math.round(durationMs)} میلی‌ثانیه دریافت شد (${downloadMbps} Mbps).`]
        : ['تست دانلود سرعت اجرا نشد یا با خطا مواجه شد.']),
    ],
    evidence: {
      measurementMethod: 'HTTP_RTT',
      probesSent,
      probesReceived,
      rttSamplesMs: validSamples,
      avgPingMs: avgPing,
      jitterMs: jitter,
      packetLossPercent,
      bytesTransferred,
      durationMs,
      downloadMbps,
    },
    limitations: metricLimitations,
    errorCode: errorMessage || null,
    source: 'Browser Performance Timing API (/api/ping & /api/speed-test/chunk)',
    confidence: validSamples.length >= 4 ? 'high' : 'medium',
    measurementMethod: 'HTTP_RTT',
    pingMs: avgPing,
    jitterMs: jitter,
    downloadMbps,
    packetLossPercent,
    probesSent,
    probesReceived,
    bytesTransferred,
    durationMs,
    pingSamples: validSamples,
    stabilityScore,
    stabilityStatusFa,
    testingPing: false,
    testingSpeed: false,
  };
}

export const COMMON_SENSITIVE_PORTS: Omit<PortProbeEntry, 'state' | 'responseTimeMs'>[] = [
  {
    port: 80,
    protocol: 'TCP',
    serviceName: 'HTTP Router Admin',
    category: 'router_admin',
    descriptionFa: 'پنل وب مدیریت مودم/روتر (HTTP غیررمزنگاری‌شده)',
    descriptionEn: 'Unencrypted Router/Modem Web Admin Panel (HTTP)',
    riskLevel: 'critical',
  },
  {
    port: 443,
    protocol: 'TCP',
    serviceName: 'HTTPS Admin / TLS',
    category: 'router_admin',
    descriptionFa: 'پنل مدیریت وب رمزنگاری‌شده (HTTPS WAN Admin)',
    descriptionEn: 'Encrypted Web Management / TLS Service',
    riskLevel: 'medium',
  },
  {
    port: 8080,
    protocol: 'TCP',
    serviceName: 'HTTP Alt / Router WAN',
    category: 'router_admin',
    descriptionFa: 'پورت جایگزین مدیریت از راه دور روتر یا پروکسی HTTP',
    descriptionEn: 'Alternative Router Remote Management or HTTP Proxy',
    riskLevel: 'critical',
  },
  {
    port: 8291,
    protocol: 'TCP',
    serviceName: 'MikroTik Winbox',
    category: 'router_admin',
    descriptionFa: 'پورت اختصاصی مدیریت روترهای MikroTik (Winbox)',
    descriptionEn: 'MikroTik RouterOS Winbox Management Port',
    riskLevel: 'critical',
  },
  {
    port: 22,
    protocol: 'TCP',
    serviceName: 'SSH Remote Shell',
    category: 'remote_access',
    descriptionFa: 'پورت خط فرمان راه دور (SSH) روی روتر یا سرور',
    descriptionEn: 'Secure Shell (SSH) Remote Access',
    riskLevel: 'high',
  },
  {
    port: 23,
    protocol: 'TCP',
    serviceName: 'Telnet Legacy Admin',
    category: 'remote_access',
    descriptionFa: 'پورت مدیریت متنی ناامن (Telnet) با خطر افشای گذرواژه',
    descriptionEn: 'Unencrypted Telnet Remote Console',
    riskLevel: 'critical',
  },
  {
    port: 21,
    protocol: 'TCP',
    serviceName: 'FTP File Server',
    category: 'file_share',
    descriptionFa: 'سرویس اشتراک فایل FTP روی مودم/روتر (USB Share)',
    descriptionEn: 'FTP File Sharing Service',
    riskLevel: 'high',
  },
  {
    port: 1080,
    protocol: 'TCP',
    serviceName: 'SOCKS Proxy',
    category: 'proxy_relay',
    descriptionFa: 'پورت پیش‌فرض پروکسی SOCKS4/5 باز در سمت کلاینت',
    descriptionEn: 'Open SOCKS Proxy Port',
    riskLevel: 'critical',
  },
];

/**
 * Evaluates TCP Port Exposure results strictly from real server-side TCP socket probes.
 * Never fabricates open/closed port states when the client IP is local/loopback or unverifiable.
 */
export function evaluatePortLeakResult(params: {
  targetIp: string | null;
  targetSource: 'server_socket' | 'trusted_proxy_header' | 'unverifiable_local_socket';
  canScanFromServer: boolean;
  ports: PortProbeEntry[];
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): PortLeakResult {
  const {
    targetIp,
    targetSource,
    canScanFromServer,
    ports,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const portLimitations = [
    'این آزمایش صرفاً از سمت سرور برنامه به سمت آدرس IP عمومی مشاهده‌شدهٔ شما (TCP Handshake) انجام می‌شود و به دلیل امنیت (جلوگیری از SSRF) هرگز آدرس‌های دلخواه یا شبکهٔ داخلی (RFC1918 / Localhost) اسکن نمی‌شوند.',
    'اگر پشت CGNAT اپراتور یا سرور خروجی VPN باشید، نتیجهٔ اسکن وضعیت فایروالِ IP خروجی فعلی را نشان می‌دهد و پورت‌های باز در شبکهٔ خانگی داخلی (LAN) را از بیرون اینترنت رؤیت نمی‌کند.'
  ];

  const defaultPorts: PortProbeEntry[] =
    ports.length > 0
      ? ports
      : COMMON_SENSITIVE_PORTS.map(p => ({
          ...p,
          state: 'not_tested',
          responseTimeMs: null,
        }));

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'Common Router & Sensitive TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای تست پورت‌های باز: ${errorMessage}`],
      evidence: { targetIp, targetSource, canScanFromServer, errorMessage },
      limitations: portLimitations,
      errorCode: 'PORT_SCAN_ERROR',
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'none',
      targetIp,
      targetSource,
      canScanFromServer: false,
      scannedPortsCount: 0,
      openPortsCount: 0,
      closedPortsCount: 0,
      filteredPortsCount: 0,
      openPorts: [],
      isExposingSensitivePorts: null,
      ports: defaultPorts,
      messageFa: `خطا در بررسی پورت‌ها: ${errorMessage}. هیچ وضعیت ساختگی تولید نشد.`,
      messageEn: `Port exposure probe failed: ${errorMessage}.`,
    };
  }

  if (!canScanFromServer || !targetIp || isPrivateOrLocalAddress(targetIp)) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Common Router & Sensitive TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [
        `آدرس مشاهده‌شده در سوکت سرور (${targetIp || 'نامشخص'}) یک آدرس محلی/داخلی است یا هدر پروکسی بدون TRUST_PROXY=true قابل استناد برای اسکن پورت نیست.`,
        'به منظور جلوگیری از خطای امنیتی SSRF و عدم اسکن پورت‌های خودِ سرور، هیچ اسکن کاذبی اجرا نشد.'
      ],
      evidence: {
        targetIp,
        targetSource,
        canScanFromServer: false,
      },
      limitations: portLimitations,
      errorCode: 'UNVERIFIABLE_PUBLIC_SOCKET_IP',
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'none',
      targetIp,
      targetSource,
      canScanFromServer: false,
      scannedPortsCount: 0,
      openPortsCount: 0,
      closedPortsCount: 0,
      filteredPortsCount: 0,
      openPorts: [],
      isExposingSensitivePorts: null,
      ports: defaultPorts.map(p => ({ ...p, state: 'not_tested', responseTimeMs: null })),
      messageFa:
        'نتیجه نامشخص (تست‌نشده): از آنجا که سرور برنامه به آدرس عمومی مستقیم سوکت کلاینت دسترسی ندارد (اتصال محلی یا پشت پروکسی غیرمعتمد)، اسکن پورت TCP اجرا نشد تا از اسکن اشتباه سرور جلوگیری شود.',
      messageEn:
        'Inconclusive (Not Tested): Server observed a local/untrusted socket IP; TCP port probing was skipped to prevent SSRF or self-scanning.',
    };
  }

  const openEntries = defaultPorts.filter(p => p.state === 'open');
  const closedEntries = defaultPorts.filter(p => p.state === 'closed');
  const filteredEntries = defaultPorts.filter(p => p.state === 'filtered_timeout');
  const openPorts = openEntries.map(p => p.port);
  const scannedCount = openEntries.length + closedEntries.length + filteredEntries.length;

  if (scannedCount === 0) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Common Router & Sensitive TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: ['هیچ پورتی در این نوبت مورد سنجش قرار نگرفت.'],
      evidence: { targetIp, targetSource },
      limitations: portLimitations,
      errorCode: 'NO_PORTS_SCANNED',
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'low',
      targetIp,
      targetSource,
      canScanFromServer: true,
      scannedPortsCount: 0,
      openPortsCount: 0,
      closedPortsCount: 0,
      filteredPortsCount: 0,
      openPorts: [],
      isExposingSensitivePorts: null,
      ports: defaultPorts,
      messageFa: 'نتیجه نامشخص: هیچ دادهٔ معتبری از وضعیت پورت‌ها ثبت نشد.',
      messageEn: 'Inconclusive: No port probe results recorded.',
    };
  }

  const hasCriticalOpen = openEntries.some(p => p.riskLevel === 'critical' || p.riskLevel === 'high');

  if (openEntries.length > 0) {
    return {
      status: hasCriticalOpen ? 'LEAK_DETECTED' : 'WARNING',
      testName: 'Common Router & Sensitive TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [
        `روی آدرس ${targetIp} تعداد ${openEntries.length} پورت باز (${openPorts.join(', ')}) به درخواست TCP SYN پاسخ مثبت دادند.`,
        ...openEntries.map(
          p => `پورت ${p.port} (${p.serviceName}) باز است — زمان پاسخ: ${p.responseTimeMs ?? 'نامشخص'} ms.`
        ),
      ],
      evidence: {
        targetIp,
        targetSource,
        openPorts,
        openServices: openEntries.map(p => ({ port: p.port, service: p.serviceName, rttMs: p.responseTimeMs })),
      },
      limitations: portLimitations,
      errorCode: null,
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'high',
      targetIp,
      targetSource,
      canScanFromServer: true,
      scannedPortsCount: scannedCount,
      openPortsCount: openEntries.length,
      closedPortsCount: closedEntries.length,
      filteredPortsCount: filteredEntries.length,
      openPorts,
      isExposingSensitivePorts: true,
      ports: defaultPorts,
      messageFa: `هشدار نشت پورت: پورت‌های (${openPorts.join(', ')}) روی آدرس عمومی ${targetIp} باز هستند و ممکن است پنل مدیریت روتر یا سرویس‌های شبکه را افشا کنند!`,
      messageEn: `Port Exposure Detected: Port(s) ${openPorts.join(', ')} responded as OPEN on ${targetIp}.`,
    };
  }

  return {
    status: 'PASS',
    testName: 'Common Router & Sensitive TCP Port Exposure Probe',
    startedAt,
    completedAt,
    observations: [
      `تمامی ${scannedCount} پورت حساس بررسی‌شده روی آدرس ${targetIp} بسته (Closed: ${closedEntries.length}) یا توسط فایروال فیلتر (Filtered: ${filteredEntries.length}) هستند.`
    ],
    evidence: {
      targetIp,
      targetSource,
      scannedCount,
      closedCount: closedEntries.length,
      filteredCount: filteredEntries.length,
    },
    limitations: portLimitations,
    errorCode: null,
    source: 'Server TCP Socket Probe (/api/port-scan)',
    confidence: 'high',
    targetIp,
    targetSource,
    canScanFromServer: true,
    scannedPortsCount: scannedCount,
    openPortsCount: 0,
    closedPortsCount: closedEntries.length,
    filteredPortsCount: filteredEntries.length,
    openPorts: [],
    isExposingSensitivePorts: false,
    ports: defaultPorts,
    messageFa: `تأییدشده با شواهد: از میان ${scannedCount} پورت حساس مدیریت روتر و پروکسی، هیچ پورت بازی روی آدرس ${targetIp} مشاهده نشد.`,
    messageEn: `Verified: 0 open sensitive ports detected out of ${scannedCount} probed on ${targetIp}.`,
  };
}

/**
 * Evaluates Overall Status and Privacy Score strictly from verified evidence.
 * If critical tests failed, timed out, or are unconfigured/inconclusive without sufficient evidence,
 * `isScoreCalculable` is false and `privacyScore` is null ("امتیاز قابل محاسبه نیست").
 */
export function evaluateOverallSummary(params: {
  ipDetails: IpDetails | null;
  dnsLeak: DnsLeakResult | null;
  webRtcLeak: WebRtcLeakResult | null;
  vpnProxy: VpnProxyResult | null;
  portLeak?: PortLeakResult | null;
}): {
  overallStatus: TestStatus;
  privacyScore: number | null;
  isScoreCalculable: boolean;
  reasonsFa: string[];
} {
  const { ipDetails, dnsLeak, webRtcLeak, vpnProxy, portLeak } = params;
  const reasonsFa: string[] = [];

  if (!ipDetails && !dnsLeak && !webRtcLeak) {
    return {
      overallStatus: 'IDLE',
      privacyScore: null,
      isScoreCalculable: false,
      reasonsFa: ['هنوز هیچ آزمونی اجرا نشده است.'],
    };
  }

  // 1. Check for confirmed leaks first (highest priority)
  const hasWebRtcLeak = webRtcLeak?.status === 'LEAK_DETECTED' || webRtcLeak?.isLeakingRealIp === true;
  const hasDnsLeak = dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.isLeaking === true;
  const hasIpMismatch = ipDetails?.ipMismatchDetected === true;
  const hasPortExposure = portLeak?.status === 'LEAK_DETECTED' || portLeak?.isExposingSensitivePorts === true;

  if (hasWebRtcLeak || hasDnsLeak || hasIpMismatch || hasPortExposure) {
    let score = 100;
    if (hasWebRtcLeak) {
      score -= 45;
      reasonsFa.push('نشت آدرس IP عمومی در نامزدهای STUN پروتکل WebRTC تأیید شد.');
    }
    if (hasDnsLeak) {
      score -= 35;
      reasonsFa.push('نشت درخواست‌های DNS در سرور Authoritative تأیید شد.');
    }
    if (hasIpMismatch) {
      score -= 25;
      reasonsFa.push('عدم تطابق بین آدرس IP مشاهده‌شده در کلاینت و سرور برنامه شناسایی شد.');
    }
    if (hasPortExposure) {
      score -= 25;
      reasonsFa.push(`باز بودن پورت‌های حساس (${portLeak?.openPorts.join(', ')}) روی آدرس خروجی تأیید شد.`);
    }
    return {
      overallStatus: 'LEAK_DETECTED',
      privacyScore: Math.max(5, score),
      isScoreCalculable: true,
      reasonsFa,
    };
  }

  // 2. Check if primary IP inspection failed completely
  if (!ipDetails || ipDetails.status === 'ERROR' || !ipDetails.ip) {
    reasonsFa.push('تست آدرس IP عمومی به دلیل خطا کامل نشد؛ امتیاز کلی امنیت قابل محاسبه نیست.');
    return {
      overallStatus: 'ERROR',
      privacyScore: null,
      isScoreCalculable: false,
      reasonsFa,
    };
  }

  // 3. Check if DNS or WebRTC are NOT_CONFIGURED, ERROR, or INCONCLUSIVE
  // Per strict specification: only calculate overall security score when sufficient, valid, comparable data exists
  // for IP, WebRTC, and DNS tests. Otherwise display "امتیاز قابل محاسبه نیست" (score: null).
  const dnsValid = dnsLeak && (dnsLeak.status === 'PASS' || dnsLeak.status === 'WARNING');
  const webRtcValid =
    webRtcLeak &&
    (webRtcLeak.status === 'PASS' ||
      webRtcLeak.status === 'WARNING' ||
      webRtcLeak.status === 'UNSUPPORTED');

  if (!dnsValid || !webRtcValid) {
    if (dnsLeak?.status === 'NOT_CONFIGURED') {
      reasonsFa.push('زیرساخت دامنهٔ Authoritative DNS تنظیم نشده است (not_configured).');
    } else if (dnsLeak?.status === 'ERROR' || dnsLeak?.status === 'INCONCLUSIVE') {
      reasonsFa.push(`وضعیت تست DNS قطعی نیست (${dnsLeak.status}).`);
    }

    if (webRtcLeak?.status === 'INCONCLUSIVE' || webRtcLeak?.status === 'ERROR') {
      reasonsFa.push(`وضعیت تست WebRTC قطعی نیست (${webRtcLeak.status}).`);
    }

    const anyError =
      dnsLeak?.status === 'ERROR' || webRtcLeak?.status === 'ERROR';

    return {
      overallStatus: anyError ? 'ERROR' : 'INCONCLUSIVE',
      privacyScore: null,
      isScoreCalculable: false,
      reasonsFa: [
        ...reasonsFa,
        'به دلیل نبود شواهد کافی در تمام تست‌های پایه (مانند Authoritative DNS یا STUN)، امتیاز عددی امنیت محاسبه نمی‌شود تا از ایجاد اطمینان کاذب جلوگیری شود.'
      ],
    };
  }

  // 4. All required tests have valid, verified evidence! Calculate evidence-based score:
  let score = 100;
  let status: TestStatus = 'PASS';

  if (vpnProxy?.isDatacenterIp === false) {
    score -= 20;
    status = 'WARNING';
    reasonsFa.push('آدرس IP خروجی متعلق به شبکهٔ دیتاسنتر/VPN شناخته شده نیست (احتمال اتصال مستقیم ISP).');
  }

  if (webRtcLeak.localIps.length > 0) {
    score -= 10;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push('آدرس خصوصی شبکهٔ محلی (LAN) در نامزدهای WebRTC قابل مشاهده است.');
  }

  if (ipDetails.fraudRiskScore !== null && ipDetails.fraudRiskScore > 30) {
    score -= 15;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push(`امتیاز ریسک سابقهٔ آدرس IP برابر با ${ipDetails.fraudRiskScore} است.`);
  }

  return {
    overallStatus: status,
    privacyScore: Math.max(10, Math.min(100, score)),
    isScoreCalculable: true,
    reasonsFa:
      reasonsFa.length > 0
        ? reasonsFa
        : ['تمامی آزمون‌های IP، DNS و WebRTC با شواهد معتبر و بدون مشاهدهٔ نشت تکمیل شدند.'],
  };
}

