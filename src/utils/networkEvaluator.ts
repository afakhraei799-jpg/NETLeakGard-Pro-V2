import {
  ConfidenceLevel,
  DnsLeakResult,
  DnsResolver,
  IpDetails,
  NetworkMetrics,
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
 * Determines whether an IP or hostname is RFC1918 private, loopback, link-local, unique-local IPv6, or mDNS (.local).
 */
export function isPrivateOrLocalAddress(address: string): boolean {
  const addr = address.trim().toLowerCase();
  if (addr.endsWith('.local')) return true;
  if (addr === '127.0.0.1' || addr === '::1' || addr === 'localhost') return true;

  if (isValidIpv4(addr)) {
    const parts = addr.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // CGNAT
    return false;
  }

  if (addr.includes(':')) {
    if (addr.startsWith('fe80:') || addr.startsWith('fc') || addr.startsWith('fd') || addr === '::1') {
      return true;
    }
  }

  return false;
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
 * Evaluates DNS Leak results based on real authoritative logs or explicitly marks NOT_CONFIGURED / INCONCLUSIVE.
 */
export function evaluateDnsTestResult(params: {
  runId: string;
  authoritativeConfigured: boolean;
  resolvers: DnsResolver[];
  ipDetails: IpDetails | null;
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): DnsLeakResult {
  const {
    runId,
    authoritativeConfigured,
    resolvers,
    ipDetails,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const dnsLimitations = [
    'مشاهدهٔ آدرس IP در سرور Authoritative DNS فقط آخرین گره (Egress Resolver) زنجیرهٔ DNS را نشان می‌دهد و در صورت استفاده از DoH/DoT یا فورواردر واسط، کل زنجیره آشکار نمی‌شود.',
    'تست DNS از داخل مرورگر صرفاً درخواست‌های شبکهٔ مرورگر (یا DoH فعال در مرورگر) را آزمایش می‌کند و وضعیت Resolver سطح سیستم‌عامل (OS-level DNS) سایر برنامه‌ها را اثبات نمی‌کند.'
  ];

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای آزمون DNS: ${errorMessage}`],
      evidence: { runId, authoritativeConfigured, errorMessage },
      limitations: dnsLimitations,
      errorCode: 'DNS_PROBE_ERROR',
      source: 'DNS Probe Service',
      confidence: 'none',
      runId,
      authoritativeConfigured,
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      messageFa: `خطا در اجرای تست نشت DNS: ${errorMessage}. هیچ سرور DNS ساختگی نمایش داده نمی‌شود.`,
      messageEn: `DNS Leak test failed: ${errorMessage}. No synthetic resolvers were generated.`,
    };
  }

  if (!authoritativeConfigured) {
    return {
      status: 'NOT_CONFIGURED',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `شناسه یکتای رمزنگارانه آزمون (${runId}) تولید شد، اما دامنهٔ Authoritative DNS اختصاصی (DNS_LEAK_DOMAIN) و سرویس ثبت لاگ (DNS_COLLECTOR_API_URL) در متغیرهای محیطی سرور تنظیم نشده‌اند.`,
        ...(resolvers.length > 0
          ? [`مشاهدهٔ کمکی از مسیر Trace/Server (${resolvers.length} مورد) ثبت شد، اما جایگزین لاگ Authoritative DNS کلاینت نیست.`]
          : []),
      ],
      evidence: {
        runId,
        authoritativeConfigured: false,
        auxiliaryObservationsCount: resolvers.length,
        resolvers,
      },
      limitations: [
        ...dnsLimitations,
        'برای اثبات قطعی نشت DNS کلاینت، نیاز به دامنهٔ تحت کنترل و سرور Authoritative DNS است تا کوئریِ ساب‌دامین یکتای هر اجرا (${runId}.<DNS_LEAK_DOMAIN>) را در سمت سرور نام ثبت کند.'
      ],
      errorCode: 'AUTHORITATIVE_DNS_NOT_CONFIGURED',
      source: 'Server Configuration & Auxiliary Trace',
      confidence: 'low',
      runId,
      authoritativeConfigured: false,
      detectedResolversCount: resolvers.length,
      resolvers,
      isLeaking: null,
      messageFa: 'زیرساخت Authoritative DNS تنظیم نشده است (not_configured): بدون دامنهٔ اختصاصی و ثبت‌کنندهٔ کوئری Authoritative، نمی‌توان Resolver نهایی کلاینت را با قطعیت اثبات کرد.',
      messageEn: 'Not Configured: Authoritative DNS collector domain (DNS_LEAK_DOMAIN) is required to verify client recursive resolvers.',
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
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      messageFa: 'نتیجه نامشخص: هیچ کوئری DNS متناظر با شناسهٔ یکتای این اجرا در سرور Authoritative ثبت نشد.',
      messageEn: 'Inconclusive: No DNS queries matching the unique run token were captured at the authoritative server.',
    };
  }

  // Compare authoritative resolvers with client IP country/ISP if available
  const clientCountry = ipDetails?.countryCode?.toUpperCase();
  const hasDomesticOrMismatchedResolver = resolvers.some(r => {
    if (!clientCountry || !r.location) return false;
    // If user is using a VPN (e.g. DE) but DNS resolver is in IR, or if client is direct ISP
    return r.status.includes('مغایرت') || r.status.toLowerCase().includes('leak');
  });

  return {
    status: hasDomesticOrMismatchedResolver ? 'LEAK_DETECTED' : 'PASS',
    testName: 'Authoritative DNS Leak & Resolver Probe',
    startedAt,
    completedAt,
    observations: [
      `تعداد ${resolvers.length} سرور Resolver از طریق لاگ واقعی برای شناسهٔ ${runId} مشاهده شد.`
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
    detectedResolversCount: resolvers.length,
    resolvers,
    isLeaking: hasDomesticOrMismatchedResolver,
    messageFa: hasDomesticOrMismatchedResolver
      ? 'نشت DNS تأیید شد: سرورهای Resolver مشاهده‌شده در Authoritative DNS با مسیر تونل مورد انتظار مغایرت دارند.'
      : `آزمایش Authoritative DNS کامل شد: ${resolvers.length} سرور Resolver مشاهده و ثبت گردید.`,
    messageEn: hasDomesticOrMismatchedResolver
      ? 'Confirmed DNS Leak: Observed authoritative resolvers conflict with expected tunnel egress.'
      : `Authoritative DNS probe completed: ${resolvers.length} resolver(s) observed.`,
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
}): {
  overallStatus: TestStatus;
  privacyScore: number | null;
  isScoreCalculable: boolean;
  reasonsFa: string[];
} {
  const { ipDetails, dnsLeak, webRtcLeak, vpnProxy } = params;
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

  if (hasWebRtcLeak || hasDnsLeak || hasIpMismatch) {
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
