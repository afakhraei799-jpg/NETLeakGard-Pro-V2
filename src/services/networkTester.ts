import {
  IpDetails,
  DnsLeakResult,
  WebRtcLeakResult,
  VpnProxyResult,
  OptimalVpnNodeSuggestion,
  EncryptedDnsRecommendation,
  NetworkMetrics,
  AiAuditReport,
  ObservedIpSource,
  WebRtcCandidate
} from '../types/network';
import {
  isValidIpv4,
  isValidIpv6,
  isPrivateOrLocalAddress,
  parseIceCandidateLine,
  evaluateWebRtcCandidates,
  evaluateDnsTestResult,
  evaluateVpnHeuristic,
  calculateHttpPingMetrics
} from '../utils/networkEvaluator';

function generateCryptoRunId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  }
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Static reference list of well-known Encrypted DoH resolvers (labeled clearly as reference configuration, not live measurements).
 */
export function generateEncryptedDnsRecommendations(
  _ipDetails: IpDetails | null
): EncryptedDnsRecommendation[] {
  return [
    {
      id: 'cloudflare',
      nameFa: 'Cloudflare DoH (سرویس مرجع جهانی)',
      provider: 'Cloudflare Inc',
      dohUrl: 'https://cloudflare-dns.com/dns-query',
      primaryIp: '1.1.1.1',
      secondaryIp: '1.0.0.1',
      estimatedPingMs: null,
      unfilteredStatusFa: 'پشتیبانی از DNS-over-HTTPS استاندارد (RFC 8484)',
      featuresFa: ['رمزنگاری ترافیک DNS بین مرورگر و Resolver', 'پشتیبانی از QNAME Minimization'],
    },
    {
      id: 'quad9',
      nameFa: 'Quad9 DoH (بنیاد غیرانتفاعی سوئیس)',
      provider: 'Quad9 Foundation',
      dohUrl: 'https://dns.quad9.net/dns-query',
      primaryIp: '9.9.9.9',
      secondaryIp: '149.112.112.112',
      estimatedPingMs: null,
      unfilteredStatusFa: 'مسدودسازی دامنه‌های مخرب شناخته‌شده + پشتیبانی از DoH/DoT',
      featuresFa: ['مستقر در سوئیس', 'پشتیبانی از DNSSEC'],
    },
    {
      id: 'controld',
      nameFa: 'Control D Unfiltered DoH',
      provider: 'Control D Inc',
      dohUrl: 'https://freedns.controld.com/p0',
      primaryIp: '76.76.2.0',
      secondaryIp: '76.76.10.0',
      estimatedPingMs: null,
      unfilteredStatusFa: 'سرور DoH بدون فیلتر',
      featuresFa: ['پشتیبانی از DoH و DoT'],
    },
    {
      id: 'google',
      nameFa: 'Google Public DNS DoH',
      provider: 'Google LLC',
      dohUrl: 'https://dns.google/dns-query',
      primaryIp: '8.8.8.8',
      secondaryIp: '8.8.4.4',
      estimatedPingMs: null,
      unfilteredStatusFa: 'پایداری بالا در شبکه Anycast جهانی + DNSSEC',
      featuresFa: ['پشتیبانی از RFC 8484 DoH', 'پشتیبانی از DoT'],
    },
  ];
}

/**
 * Generates Heuristic Regional VPN Node Suggestion (explicitly labeled as heuristic, without fake ping guarantees).
 */
export function generateOptimalVpnNodeSuggestion(
  ipDetails: IpDetails | null,
  _currentPingMs: number | null = null
): OptimalVpnNodeSuggestion {
  const countryCode = (ipDetails?.countryCode || '').toUpperCase();

  if (['IR', 'AE', 'TR', 'QA', 'KW', 'OM', 'IQ', 'SA'].includes(countryCode)) {
    return {
      recommendedCountryNameFa: 'آلمان (Germany - پیشنهاد جغرافیایی)',
      recommendedCountryCode: 'DE',
      recommendedCityFa: 'فرانکفورت (IXP DE-CIX)',
      estimatedPingMs: null,
      privacyRatingFa: 'قلمرو قوانین حفاظت داده اتحادیه اروپا (GDPR)',
      recommendationReasonFa:
        'پیشنهاد مبتنی بر توپولوژی کلی شبکه (و نه اندازه‌گیری مستقیم به سرور VPN): مرکز تبادل ترافیک فرانکفورت (DE-CIX) معمولاً کوتاه‌ترین مسیر ترانزیت اروپایی برای شبکه‌های غرب آسیا و خاورمیانه را دارد.',
      recommendedProtocolsFa: ['WireGuard', 'OpenVPN'],
      isHeuristicSuggestion: true,
    };
  }

  return {
    recommendedCountryNameFa: 'سوئیس یا هلند (پیشنهاد عمومی)',
    recommendedCountryCode: 'CH',
    recommendedCityFa: 'زوریخ / آمستردام',
    estimatedPingMs: null,
    privacyRatingFa: 'قوانین حریم خصوصی سخت‌گیرانه',
    recommendationReasonFa:
      'این پیشنهاد صرفاً بر اساس نزدیکی جغرافیایی تقریبی و زیرساخت دیتاسنتری ارائه شده است؛ پینگ واقعی به مسیر BGP ارائه‌دهندهٔ اینترنت شما بستگی دارد.',
    recommendedProtocolsFa: ['WireGuard', 'OpenVPN'],
    isHeuristicSuggestion: true,
  };
}

/**
 * 1. Fetch & Cross-Verify Client-Observed Public IP vs Server-Observed IP
 * Never returns hardcoded fallback IPs ('185.190.140.1') or fake Clean blacklist badges.
 */
export async function fetchIpDetails(): Promise<IpDetails> {
  const startedAt = new Date().toISOString();
  const ipSources: ObservedIpSource[] = [];
  const observations: string[] = [];

  // Step 1A: Probe Client-Direct Public IP from independent HTTPS service #1 (ipify)
  try {
    const t0 = performance.now();
    const res1 = await fetch('https://api64.ipify.org?format=json', {
      cache: 'no-store',
      signal: AbortSignal.timeout(4000),
    });
    if (res1.ok) {
      const j1 = await res1.json();
      if (j1?.ip && (isValidIpv4(j1.ip) || isValidIpv6(j1.ip))) {
        ipSources.push({
          sourceName: 'api64.ipify.org (Client Direct)',
          ip: j1.ip.trim(),
          version: isValidIpv6(j1.ip) ? 'IPv6' : 'IPv4',
          observedFrom: 'client_direct',
          responseTimeMs: Math.round(performance.now() - t0),
        });
      }
    }
  } catch {
    // Recorded in observations below if needed
  }

  // Step 1B: Probe Client-Direct Public IP from independent HTTPS service #2 (ipwho.is)
  let clientGeoFallback: any = null;
  try {
    const t1 = performance.now();
    const res2 = await fetch('https://ipwho.is/', {
      cache: 'no-store',
      signal: AbortSignal.timeout(4000),
    });
    if (res2.ok) {
      const j2 = await res2.json();
      if (j2?.success !== false && j2?.ip && (isValidIpv4(j2.ip) || isValidIpv6(j2.ip))) {
        clientGeoFallback = j2;
        ipSources.push({
          sourceName: 'ipwho.is (Client Direct)',
          ip: j2.ip.trim(),
          version: isValidIpv6(j2.ip) ? 'IPv6' : 'IPv4',
          observedFrom: 'client_direct',
          responseTimeMs: Math.round(performance.now() - t1),
        });
      }
    }
  } catch {
    // Continue to server check
  }

  const clientObservedIp = ipSources.length > 0 ? ipSources[0].ip : null;

  // Step 1C: Query Backend `/api/ip-info` (passing validated clientObservedIp if discovered)
  try {
    const query = clientObservedIp ? `?clientIp=${encodeURIComponent(clientObservedIp)}` : '';
    const tServer = performance.now();
    const serverRes = await fetch(`/api/ip-info${query}`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });

    if (serverRes.ok) {
      const payload = await serverRes.json();
      if (payload.success && payload.data) {
        const srvData: IpDetails = payload.data;

        if (srvData.serverObservedIp && !isPrivateOrLocalAddress(srvData.serverObservedIp)) {
          ipSources.push({
            sourceName: srvData.proxyHeaderTrusted
              ? 'App Server (Trusted Proxy Header)'
              : 'App Server (Direct Socket)',
            ip: srvData.serverObservedIp,
            version: isValidIpv6(srvData.serverObservedIp) ? 'IPv6' : 'IPv4',
            observedFrom: srvData.proxyHeaderTrusted ? 'server_trusted_header' : 'server_socket',
            responseTimeMs: Math.round(performance.now() - tServer),
          });
        }

        // Compare all public IPs observed across independent client & server sources
        const uniquePublicIps = Array.from(
          new Set(ipSources.map(s => s.ip).filter(ip => !isPrivateOrLocalAddress(ip)))
        );
        const ipMismatchDetected = uniquePublicIps.length > 1;

        if (clientObservedIp) {
          observations.push(`آدرس IP مشاهده‌شده مستقیم از مرورگر کلاینت: ${clientObservedIp}`);
        }
        if (srvData.serverObservedIp) {
          observations.push(
            `آدرس IP مشاهده‌شده توسط سرور برنامه: ${srvData.serverObservedIp} (${
              srvData.proxyHeaderTrusted ? 'هدر پروکسی تاییدشده' : 'سوکت مستقیم'
            })`
          );
        }
        if (ipMismatchDetected) {
          observations.push(
            `هشدار مغایرت مسیر IP: منابع مستقل آدرس‌های متفاوتی (${uniquePublicIps.join(' ≠ ')}) گزارش کردند (احتمال Split-Tunneling یا پروکسی بخشی از ترافیک).`
          );
        }

        return {
          ...srvData,
          status: ipMismatchDetected ? 'LEAK_DETECTED' : srvData.status,
          clientObservedIp: clientObservedIp || srvData.clientObservedIp,
          ipSources,
          ipMismatchDetected,
          observations: [...observations, ...(srvData.observations || [])],
          evidence: {
            ...(srvData.evidence || {}),
            clientDirectSources: ipSources,
            uniquePublicIps,
            ipMismatchDetected,
          },
        };
      }
    }
  } catch (e: any) {
    observations.push(`خطا در ارتباط با API سرور (/api/ip-info): ${e?.message || 'Network Error'}`);
  }

  // If server failed, but client-direct GeoIP succeeded, build honest result from client-direct observation
  if (clientObservedIp) {
    const completedAt = new Date().toISOString();
    const uniquePublicIps = Array.from(new Set(ipSources.map(s => s.ip)));
    const ipMismatchDetected = uniquePublicIps.length > 1;

    return {
      status: ipMismatchDetected ? 'LEAK_DETECTED' : 'PASS',
      testName: 'Public IP & GeoIP Inspection',
      startedAt,
      completedAt,
      observations: [
        `آدرس IP از طریق استعلام مستقیم مرورگر دریافت شد: ${clientObservedIp}`,
        'سرور برنامه پاسخ معتبری برنگرداند؛ مقایسهٔ سرور و کلاینت انجام نشد.',
      ],
      evidence: {
        clientDirectSources: ipSources,
        uniquePublicIps,
      },
      limitations: [
        'موقعیت جغرافیایی صرفاً تخمین پایگاه دادهٔ GeoIP است و مکان دقیق دستگاه نیست.',
        'به دلیل عدم پاسخ سرور، تنها دیدگاه سمت کلاینت ثبت شده است.'
      ],
      errorCode: null,
      source: ipSources.map(s => s.sourceName).join(', '),
      confidence: 'medium',
      ip: clientObservedIp,
      clientObservedIp,
      serverObservedIp: null,
      serverSocketIp: null,
      forwardedHeaderIp: null,
      proxyHeaderTrusted: false,
      ipSources,
      ipMismatchDetected,
      version: isValidIpv6(clientObservedIp) ? 'IPv6' : 'IPv4',
      countryName: clientGeoFallback?.country || null,
      countryCode: clientGeoFallback?.country_code || null,
      city: clientGeoFallback?.city || null,
      region: clientGeoFallback?.region || null,
      isp: clientGeoFallback?.connection?.isp || null,
      asn: clientGeoFallback?.connection?.asn ? `AS${clientGeoFallback.connection.asn}` : null,
      org: clientGeoFallback?.connection?.org || null,
      lat: typeof clientGeoFallback?.latitude === 'number' ? clientGeoFallback.latitude : null,
      lon: typeof clientGeoFallback?.longitude === 'number' ? clientGeoFallback.longitude : null,
      timezone: clientGeoFallback?.timezone?.id || null,
      isGeoEstimated: true,
      usageType: 'Unknown',
      usageTypeFa: 'نامشخص (سرویس طبقه‌بندی سرور در دسترس نبود)',
      connectionType: 'Unknown',
      connectionTypeFa: 'نامشخص',
      isVpnOrProxyDetected: null,
      isDatacenter: null,
      fraudRiskScore: null,
      riskFactorsFa: ['سرویس بررسی اعتبار IP در دسترس نبود؛ هیچ امتیاز ریسک جعلی تولید نشد.'],
      fraudStatusFa: 'بررسی‌نشده (عدم دسترسی به سرویس استعلام)',
      fraudStatusEn: 'Unverified',
      blacklistDetails: {
        googleSafeBrowsingStatus: 'not_configured',
        spamhausDnsblStatus: 'not_configured',
        abuseIpDbStatus: 'not_configured',
        abuseConfidenceScore: null,
        isGoogleFlagged: null,
        isSpamhausFlagged: null,
        isAbuseIpFlagged: null,
        verifiedSourcesCount: 0,
        threatCategoryFa: 'بررسی‌نشده (بدون ادعای پاک بودن)',
        threatCategoryEn: 'Unverified',
      },
      userIntentAnalysisFa: 'به دلیل عدم دسترسی کامل به متادیتا، تحلیل نوع کاربری شبکه انجام نشد.',
    };
  }

  // Complete failure: return explicit ERROR status without any fake IP or location
  const completedAt = new Date().toISOString();
  return {
    status: 'ERROR',
    testName: 'Public IP & GeoIP Inspection',
    startedAt,
    completedAt,
    observations: [
      'تمامی تلاش‌ها برای دریافت آدرس IP عمومی (هم از سمت کلاینت و هم از سمت سرور) با خطا یا Timeout مواجه شدند.',
      'طبق سیاست صحت داده، هیچ آدرس IP، کشور یا ISP پیش‌فرضی جایگزین نشد.'
    ],
    evidence: { ipSources: [], observations },
    limitations: ['عدم دسترسی به سرویس‌های شناسایی IP.'],
    errorCode: 'ALL_IP_SOURCES_FAILED',
    source: 'None (Network Error)',
    confidence: 'none',
    ip: null,
    clientObservedIp: null,
    serverObservedIp: null,
    serverSocketIp: null,
    forwardedHeaderIp: null,
    proxyHeaderTrusted: false,
    ipSources: [],
    ipMismatchDetected: false,
    version: 'Unknown',
    countryName: null,
    countryCode: null,
    city: null,
    region: null,
    isp: null,
    asn: null,
    org: null,
    lat: null,
    lon: null,
    timezone: null,
    isGeoEstimated: false,
    usageType: 'Unknown',
    usageTypeFa: 'نامشخص (خطا در دریافت IP)',
    connectionType: 'Unknown',
    connectionTypeFa: 'نامشخص (خطا در دریافت IP)',
    isVpnOrProxyDetected: null,
    isDatacenter: null,
    fraudRiskScore: null,
    riskFactorsFa: ['خطا در دریافت آدرس IP عمومی.'],
    fraudStatusFa: 'نامشخص (خطا در دریافت IP)',
    fraudStatusEn: 'Error (IP lookup failed)',
    blacklistDetails: {
      googleSafeBrowsingStatus: 'error',
      spamhausDnsblStatus: 'error',
      abuseIpDbStatus: 'error',
      abuseConfidenceScore: null,
      isGoogleFlagged: null,
      isSpamhausFlagged: null,
      isAbuseIpFlagged: null,
      verifiedSourcesCount: 0,
      threatCategoryFa: 'خطا در استعلام',
      threatCategoryEn: 'Lookup Error',
    },
    userIntentAnalysisFa: 'به علت خطای شبکه و عدم دریافت IP معتبر، تحلیلی ثبت نشد.',
  };
}

/**
 * 2. Perform Authoritative DNS Leak Test
 * Uses unique cryptographic per-run token. Never returns fake resolvers or random latencies.
 */
export async function performDnsLeakTest(ipDetails: IpDetails | null): Promise<DnsLeakResult> {
  const startedAt = new Date().toISOString();
  const runId = generateCryptoRunId();

  try {
    const res = await fetch(`/api/dns-leak-probe?runId=${encodeURIComponent(runId)}`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      return evaluateDnsTestResult({
        runId,
        authoritativeConfigured: Boolean(errBody?.authoritativeConfigured),
        resolvers: [],
        ipDetails,
        startedAt,
        completedAt: new Date().toISOString(),
        errorMessage: errBody?.error || `HTTP ${res.status}`,
      });
    }

    const json = await res.json();
    const authoritativeConfigured = Boolean(json.authoritativeConfigured);
    const dnsLeakDomain = json.dnsLeakDomain as string | null;

    // If an authoritative DNS domain IS configured, trigger 3 unique cache-bypassing subqueries from the browser
    if (authoritativeConfigured && dnsLeakDomain) {
      const probeUrls = [1, 2, 3].map(
        i => `https://p${i}-${runId}.${dnsLeakDomain}/?nocache=${Date.now()}_${i}`
      );
      await Promise.allSettled(
        probeUrls.map(u =>
          fetch(u, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(2500) })
        )
      );

      // Re-fetch captured authoritative DNS logs for this runId
      const collectRes = await fetch(`/api/dns-leak-probe?runId=${encodeURIComponent(runId)}`, {
        cache: 'no-store',
        signal: AbortSignal.timeout(5000),
      });
      if (collectRes.ok) {
        const collectJson = await collectRes.json();
        return evaluateDnsTestResult({
          runId,
          authoritativeConfigured: true,
          resolvers: Array.isArray(collectJson.resolvers) ? collectJson.resolvers : [],
          ipDetails,
          startedAt,
          completedAt: new Date().toISOString(),
        });
      }
    }

    return evaluateDnsTestResult({
      runId,
      authoritativeConfigured,
      resolvers: Array.isArray(json.resolvers) ? json.resolvers : [],
      ipDetails,
      startedAt,
      completedAt: new Date().toISOString(),
    });
  } catch (e: any) {
    return evaluateDnsTestResult({
      runId,
      authoritativeConfigured: false,
      resolvers: [],
      ipDetails,
      startedAt,
      completedAt: new Date().toISOString(),
      errorMessage: e?.message || 'خطای شبکه در ارتباط با سرویس تست DNS',
    });
  }
}

/**
 * 3. Real Browser WebRTC ICE Candidates Leak Test
 * Never injects fake local IPs ('192.168.1.105') and never reports PASS when 0 STUN candidates are gathered.
 */
export async function performWebRtcLeakTest(
  referenceIpOrDetails: string | IpDetails | null
): Promise<WebRtcLeakResult> {
  const startedAt = new Date().toISOString();
  const stunServersUsed = [
    'stun:stun.l.google.com:19302',
    'stun:stun1.l.google.com:19302',
    'stun:stun.cloudflare.com:3478',
  ];

  const referencePublicIps: string[] = [];
  if (typeof referenceIpOrDetails === 'string' && referenceIpOrDetails.trim()) {
    referencePublicIps.push(referenceIpOrDetails.trim());
  } else if (referenceIpOrDetails && typeof referenceIpOrDetails === 'object') {
    if (referenceIpOrDetails.ip) referencePublicIps.push(referenceIpOrDetails.ip);
    if (referenceIpOrDetails.clientObservedIp) referencePublicIps.push(referenceIpOrDetails.clientObservedIp);
    if (referenceIpOrDetails.serverObservedIp) referencePublicIps.push(referenceIpOrDetails.serverObservedIp);
  }

  return new Promise(resolve => {
    if (typeof window === 'undefined' || typeof window.RTCPeerConnection === 'undefined') {
      resolve(
        evaluateWebRtcCandidates({
          isSupported: false,
          candidates: [],
          referencePublicIps,
          stunServersUsed,
          startedAt,
          completedAt: new Date().toISOString(),
        })
      );
      return;
    }

    const candidatesList: WebRtcCandidate[] = [];
    const seenKeys = new Set<string>();
    let finished = false;

    let pc: RTCPeerConnection | null = null;
    try {
      pc = new RTCPeerConnection({
        iceServers: stunServersUsed.map(url => ({ urls: url })),
      });
    } catch (err: any) {
      resolve(
        evaluateWebRtcCandidates({
          isSupported: true,
          candidates: [],
          referencePublicIps,
          stunServersUsed,
          startedAt,
          completedAt: new Date().toISOString(),
          errorMessage: err?.message || 'Failed to construct RTCPeerConnection',
        })
      );
      return;
    }

    const finishTest = (errorMessage?: string) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);
      try {
        pc?.close();
      } catch {
        // Ignore close error
      }
      pc = null;

      resolve(
        evaluateWebRtcCandidates({
          isSupported: true,
          candidates: candidatesList,
          referencePublicIps,
          stunServersUsed,
          startedAt,
          completedAt: new Date().toISOString(),
          errorMessage,
        })
      );
    };

    const timeoutId = setTimeout(() => {
      finishTest();
    }, 3500);

    try {
      pc.createDataChannel('netleakgard_webrtc_probe');
      pc.onicecandidate = event => {
        if (!event || !event.candidate) {
          finishTest();
          return;
        }
        const parsed = parseIceCandidateLine(event.candidate.candidate);
        if (parsed) {
          const key = `${parsed.type}:${parsed.protocol}:${parsed.ip}:${parsed.port}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            candidatesList.push(parsed);
          }
        }
      };
      pc.onicecandidateerror = () => {
        // ICE candidate error on individual STUN server; wait for gathering complete or timeout
      };

      pc.createOffer()
        .then(offer => pc?.setLocalDescription(offer))
        .catch((err: any) => {
          finishTest(err?.message || 'RTCPeerConnection createOffer failed');
        });
    } catch (err: any) {
      finishTest(err?.message || 'WebRTC execution exception');
    }
  });
}

/**
 * 4. Probabilistic VPN & Network Egress Assessment
 */
export function performVpnAnalysis(
  ipDetails: IpDetails | null,
  dnsLeak: DnsLeakResult | null
): VpnProxyResult {
  return evaluateVpnHeuristic(ipDetails, dnsLeak);
}

/**
 * 5. Real HTTP RTT Latency, Jitter, Packet Loss & Bounded Download Speed Measurement
 * Never fabricates random ping numbers or fake download speeds on failure.
 */
export async function measurePingAndSpeed(signal?: AbortSignal): Promise<NetworkMetrics> {
  const startedAt = new Date().toISOString();
  const rttSamplesMs: number[] = [];
  const totalProbes = 6;
  let probesSent = 0;
  let probesReceived = 0;
  let lastError: string | undefined;

  for (let i = 0; i < totalProbes; i++) {
    if (signal?.aborted) {
      lastError = 'آزمایش توسط کاربر لغو شد.';
      break;
    }
    probesSent += 1;
    const t0 = performance.now();
    try {
      const resp = await fetch(`/api/ping?seq=${i}&t=${Date.now()}`, {
        cache: 'no-store',
        signal: signal || AbortSignal.timeout(3000),
      });
      if (resp.ok) {
        const rtt = Math.round((performance.now() - t0) * 10) / 10;
        rttSamplesMs.push(rtt);
        probesReceived += 1;
      } else {
        lastError = `HTTP ${resp.status} on /api/ping`;
      }
    } catch (e: any) {
      lastError = e?.message || 'Ping probe timeout';
    }
  }

  let downloadMbps: number | null = null;
  let bytesTransferred = 0;
  let durationMs = 0;

  if (probesReceived > 0 && !signal?.aborted) {
    try {
      const chunkBytes = 512 * 1024; // 512 KB bounded test payload
      const dlStart = performance.now();
      const speedResp = await fetch(`/api/speed-test/chunk?bytes=${chunkBytes}&t=${Date.now()}`, {
        cache: 'no-store',
        signal: signal || AbortSignal.timeout(8000),
      });
      if (speedResp.ok) {
        const buf = await speedResp.arrayBuffer();
        durationMs = performance.now() - dlStart;
        bytesTransferred = buf.byteLength;
        if (durationMs > 0 && bytesTransferred > 0) {
          const bits = bytesTransferred * 8;
          downloadMbps = Math.round(((bits / (durationMs / 1000)) / 1_000_000) * 100) / 100;
        }
      } else {
        lastError = `Speed test HTTP ${speedResp.status}`;
      }
    } catch (e: any) {
      lastError = e?.message || 'Speed test failed';
    }
  }

  return calculateHttpPingMetrics({
    rttSamplesMs,
    probesSent,
    probesReceived,
    downloadMbps,
    bytesTransferred,
    durationMs,
    startedAt,
    completedAt: new Date().toISOString(),
    errorMessage: lastError,
  });
}

/**
 * 6. Gemini AI Security Audit Query (Strictly grounded in real observations)
 */
export async function fetchAiAudit(networkData: any): Promise<AiAuditReport> {
  const nodeSuggestion = generateOptimalVpnNodeSuggestion(
    networkData?.ipDetails || null,
    networkData?.pingMs ?? null
  );
  const dnsRecs = generateEncryptedDnsRecommendations(networkData?.ipDetails || null);

  try {
    const res = await fetch('/api/gemini-audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ networkData }),
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) {
      const json = await res.json();
      if (json.success && json.audit) {
        return {
          ...json.audit,
          optimalNodeSuggestion: nodeSuggestion,
          dnsRecommendations: dnsRecs,
        };
      }
    }
  } catch {
    // Handled below without fabricating fake positive security claims
  }

  return {
    riskScore: null,
    statusLevel: 'نامشخص',
    summaryFa:
      'سرویس تحلیل هوش مصنوعی پاسخ نداد یا تنظیم نشده است. نتایج زیر مستقیماً از مشاهدات واقعی تست‌های شبکه استخراج شده‌اند.',
    detailedAnalysisFa: [
      networkData?.ip
        ? `آدرس IP مشاهده‌شده: ${networkData.ip} (${networkData.usageTypeFa || 'نامشخص'})`
        : 'آدرس IP عمومی دریافت نشد (خطای شبکه).',
      `وضعیت تست DNS: ${networkData?.dnsLeakStatus || 'تنظیم‌نشده (not_configured)'}`,
      `وضعیت تست WebRTC: ${networkData?.webRtcLeakStatus || 'نامشخص'}`,
    ],
    threatsFoundFa: [],
    recommendationsFa: [
      'برای اثبات قطعی عدم نشت DNS، دامنهٔ Authoritative DNS اختصاصی (DNS_LEAK_DOMAIN) باید روی سرور تنظیم شود.',
      'توجه داشته باشید که تست‌های داخل مرورگر، وضعیت تمام ترافیک سطح سیستم‌عامل را اثبات نمی‌کنند.'
    ],
    optimalNodeSuggestion: nodeSuggestion,
    dnsRecommendations: dnsRecs,
    aiAvailable: false,
  };
}
