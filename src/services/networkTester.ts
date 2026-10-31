import {
  IpDetails,
  DnsLeakResult,
  IndependentBrowserDnsEntry,
  IndependentBrowserDnsObservation,
  WebRtcLeakResult,
  VpnProxyResult,
  PortLeakResult,
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
  formatTestStatusLabelFa,
  parseIceCandidateLine,
  evaluateWebRtcCandidates,
  evaluateDnsTestResult,
  evaluateIndependentBrowserDnsObservation,
  evaluateVpnHeuristic,
  calculateHttpPingMetrics,
  evaluatePortLeakResult,
  evaluateObservedIpSources,
  buildDnsLeakProbeQname
} from '../utils/networkEvaluator';

/**
 * Creates an AbortSignal that aborts either when the internal timeout expires OR when the caller's signal aborts.
 * Ensures caller cancellations (e.g. re-running test) abort in-flight fetch requests immediately.
 */
export function createTimeoutAndAbortSignal(
  timeoutMs: number,
  callerSignal?: AbortSignal
): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException('Request timeout', 'TimeoutError'));
  }, timeoutMs);

  const onCallerAbort = () => {
    clearTimeout(timer);
    controller.abort(callerSignal?.reason);
  };

  if (callerSignal) {
    if (callerSignal.aborted) {
      clearTimeout(timer);
      controller.abort(callerSignal.reason);
    } else {
      callerSignal.addEventListener('abort', onCallerAbort, { once: true });
    }
  }

  const cleanup = () => {
    clearTimeout(timer);
    if (callerSignal) {
      callerSignal.removeEventListener('abort', onCallerAbort);
    }
  };

  return { signal: controller.signal, cleanup };
}

/**
 * Combines an internal timeout with an optional caller AbortSignal so both user cancellation
 * and per-request timeouts abort in-flight network requests cleanly.
 */
export function createBoundedSignal(timeoutMs: number, externalSignal?: AbortSignal): AbortSignal {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  if (!externalSignal) {
    return timeoutSignal;
  }
  if (typeof AbortSignal.any === 'function') {
    return AbortSignal.any([externalSignal, timeoutSignal]);
  }
  return createTimeoutAndAbortSignal(timeoutMs, externalSignal).signal;
}

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
export async function fetchIpDetails(signal?: AbortSignal): Promise<IpDetails> {
  const startedAt = new Date().toISOString();
  const ipSources: ObservedIpSource[] = [];
  const observations: string[] = [];

  // Step 1A: Probe Client-Direct Public IP from independent HTTPS service #1 (ipify)
  try {
    const t0 = performance.now();
    const res1 = await fetch('https://api64.ipify.org?format=json', {
      cache: 'no-store',
      signal: createBoundedSignal(4000, signal),
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
          observedAt: new Date().toISOString(),
        });
      }
    } else {
      observations.push(`سرویس api64.ipify.org وضعیت HTTP ${res1.status} برگرداند.`);
    }
  } catch (err: any) {
    observations.push(`عدم دریافت پاسخ از api64.ipify.org: ${err?.message || 'Timeout/Blocked'}`);
  }

  // Step 1B: Probe Client-Direct Public IP from independent HTTPS service #2 (ipwho.is)
  let clientGeoFallback: any = null;
  try {
    const t1 = performance.now();
    const res2 = await fetch('https://ipwho.is/', {
      cache: 'no-store',
      signal: createBoundedSignal(4000, signal),
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
          observedAt: new Date().toISOString(),
        });
      }
    } else {
      observations.push(`سرویس ipwho.is (مستقیم مرورگر) وضعیت HTTP ${res2.status} برگرداند.`);
    }
  } catch (err: any) {
    observations.push(`عدم دریافت پاسخ از ipwho.is (مستقیم مرورگر): ${err?.message || 'Timeout/Blocked'}`);
  }

  const clientObservedIp = ipSources.length > 0 ? ipSources[0].ip : null;

  // Step 1C: Query Backend `/api/ip-info` (passing validated clientObservedIp if discovered)
  try {
    const query = clientObservedIp ? `?clientIp=${encodeURIComponent(clientObservedIp)}` : '';
    const tServer = performance.now();
    const serverRes = await fetch(`/api/ip-info${query}`, {
      cache: 'no-store',
      signal: createBoundedSignal(6000, signal),
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
            observedAt: new Date().toISOString(),
          });
        }

        // Compare public IPs within the same address family (IPv4 vs IPv4, IPv6 vs IPv6)
        const sourceEval = evaluateObservedIpSources(ipSources);
        const { uniquePublicIps, uniqueIpv4s, uniqueIpv6s, ipMismatchDetected, isDualStackObserved } = sourceEval;

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
        if (isDualStackObserved && !ipMismatchDetected) {
          observations.push(
            `اتصال دوپشته (Dual-Stack IPv4/IPv6) مشاهده شد: IPv4 (${uniqueIpv4s.join(', ')}) و IPv6 (${uniqueIpv6s.join(', ')}). تفاوت خانوادهٔ آدرس به‌تنهایی نشت تلقی نمی‌شود.`
          );
        }
        if (ipMismatchDetected) {
          observations.push(
            `هشدار مغایرت مسیر IP در یک خانوادهٔ آدرس: منابع مستقل آدرس‌های متفاوتی (${uniquePublicIps.join(' ≠ ')}) گزارش کردند (احتمال Split-Tunneling یا پروکسی بخشی از ترافیک).`
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
            uniqueIpv4s,
            uniqueIpv6s,
            isDualStackObserved,
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
    const sourceEval = evaluateObservedIpSources(ipSources);
    const { uniquePublicIps, uniqueIpv4s, uniqueIpv6s, ipMismatchDetected, isDualStackObserved } = sourceEval;

    return {
      status: ipMismatchDetected ? 'LEAK_DETECTED' : 'PASS',
      testName: 'Public IP & GeoIP Inspection',
      startedAt,
      completedAt,
      observations: [
        ...observations,
        `آدرس IP از طریق استعلام مستقیم مرورگر دریافت شد: ${clientObservedIp}`,
        'سرور برنامه پاسخ معتبری برنگرداند؛ مقایسهٔ سرور و کلاینت انجام نشد.',
      ],
      evidence: {
        clientDirectSources: ipSources,
        uniquePublicIps,
        uniqueIpv4s,
        uniqueIpv6s,
        isDualStackObserved,
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
 * 2A. Independent Zero-Cost Browser DNS & Edge Trace Observation
 * Queries public endpoints (edns.ip-api.com & 1.1.1.1/cdn-cgi/trace) directly from the browser.
 * Note: HTTP URL query parameters do NOT force DNS cache bypass; this auxiliary check is strictly
 * informational (status is always INCONCLUSIVE or WARNING) and is never used as proof of PASS for Authoritative DNS.
 */
async function probeIndependentBrowserDnsObservation(
  ipDetails: IpDetails | null,
  signal?: AbortSignal
): Promise<IndependentBrowserDnsObservation> {
  const entries: IndependentBrowserDnsEntry[] = [];

  await Promise.allSettled([
    (async () => {
      const t0 = performance.now();
      const resp = await fetch('https://edns.ip-api.com/json', {
        cache: 'no-store',
        signal: createBoundedSignal(4000, signal),
      });
      if (!resp.ok) return;
      const data = await resp.json();
      const rtt = Math.max(1, Math.round(performance.now() - t0));
      if (data?.dns?.ip && (isValidIpv4(String(data.dns.ip)) || isValidIpv6(String(data.dns.ip)))) {
        entries.push({
          sourceName: 'ip-api EDNS Recursive Resolver',
          observedIp: String(data.dns.ip),
          locationOrGeo: String(data.dns.geo || 'نامشخص'),
          role: 'edns_recursive_resolver',
          responseTimeMs: rtt,
        });
      }
      if (data?.edns?.ip && (isValidIpv4(String(data.edns.ip)) || isValidIpv6(String(data.edns.ip)))) {
        entries.push({
          sourceName: 'EDNS Client Subnet (ECS)',
          observedIp: String(data.edns.ip),
          locationOrGeo: String(data.edns.geo || 'نامشخص'),
          role: 'client_subnet_edns',
          responseTimeMs: rtt,
        });
      }
    })(),
    (async () => {
      const t0 = performance.now();
      const resp = await fetch('https://1.1.1.1/cdn-cgi/trace', {
        cache: 'no-store',
        signal: createBoundedSignal(3500, signal),
      });
      if (!resp.ok) return;
      const text = await resp.text();
      const rtt = Math.max(1, Math.round(performance.now() - t0));
      const map: Record<string, string> = {};
      for (const line of text.split('\n')) {
        const idx = line.indexOf('=');
        if (idx > 0) {
          map[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
        }
      }
      if (map.ip && (isValidIpv4(map.ip) || isValidIpv6(map.ip))) {
        entries.push({
          sourceName: `Cloudflare Edge Trace (${map.colo || 'Anycast'})`,
          observedIp: map.ip,
          locationOrGeo: `${map.loc || 'نامشخص'}${map.warp && map.warp !== 'off' ? ` (WARP: ${map.warp})` : ''}`,
          role: 'edge_trace_egress',
          responseTimeMs: rtt,
        });
      }
    })(),
  ]);

  return evaluateIndependentBrowserDnsObservation(entries, ipDetails);
}

/**
 * 2. Perform Authoritative DNS Leak Test + Independent Zero-Cost Browser DNS Comparison
 * Uses unique cryptographic per-run token and canonical QNAME labels (`p<N>.<runId>.<domain>`).
 * Never treats HTTP URL query parameters (`?nocache=...`) as DNS freshness evidence, and never returns fake resolvers.
 */
export async function performDnsLeakTest(
  ipDetails: IpDetails | null,
  signal?: AbortSignal
): Promise<DnsLeakResult> {
  const startedAt = new Date().toISOString();
  const runId = generateCryptoRunId();

  const independentPromise = probeIndependentBrowserDnsObservation(ipDetails, signal);

  try {
    const [res, independentBrowserObservation] = await Promise.all([
      fetch(`/api/dns-leak-probe?runId=${encodeURIComponent(runId)}`, {
        cache: 'no-store',
        signal: createBoundedSignal(6000, signal),
      }),
      independentPromise,
    ]);

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      return evaluateDnsTestResult({
        runId,
        authoritativeConfigured: Boolean(errBody?.authoritativeConfigured),
        missingEnvVars: Array.isArray(errBody?.missingEnvVars) ? errBody.missingEnvVars : undefined,
         resolvers: [],
        ipDetails,
        independentBrowserObservation,
        startedAt,
        completedAt: new Date().toISOString(),
        errorMessage: errBody?.error || `HTTP ${res.status}`,
      });
    }

    const json = await res.json();
    const authoritativeConfigured = Boolean(json.authoritativeConfigured);
    const missingEnvVars = Array.isArray(json.missingEnvVars) ? json.missingEnvVars : undefined;
    const dnsLeakDomain = json.dnsLeakDomain as string | null;

    // If an authoritative DNS domain IS configured, trigger 3 unique subdomain lookups using canonical `p<N>.<runId>.<domain>` QNAMEs.
    // Note: DNS cache bypass relies strictly on the unique per-run hostname labels (`p1.<runId>.<domain>`), NOT on HTTP path/query parameters.
    // Sending these browser requests only initiates hostname resolution; if no verified UDP/53 evidence is collected, status remains INCONCLUSIVE.
    if (authoritativeConfigured && dnsLeakDomain) {
      const probeQnames = [1, 2, 3]
        .map(i => buildDnsLeakProbeQname(i, runId, dnsLeakDomain))
        .filter((q): q is string => q !== null);

      if (probeQnames.length === 0) {
        return evaluateDnsTestResult({
          runId,
          authoritativeConfigured: true,
          dnsLeakDomain,
          missingEnvVars: [],
          resolvers: [],
          ipDetails,
          independentBrowserObservation,
          startedAt,
          completedAt: new Date().toISOString(),
          errorMessage: 'دامنهٔ تست DNS یا شناسهٔ اجرا با قالب استاندارد برچسب‌های RFC 1035 سازگار نیست.',
        });
      }

      const probeUrls = probeQnames.map(qname => `https://${qname}/`);
      await Promise.allSettled(
        probeUrls.map(u =>
          fetch(u, { mode: 'no-cors', cache: 'no-store', signal: createBoundedSignal(2500, signal) })
        )
      );

      // Bounded polling (up to 3 attempts, 400ms apart) so asynchronous DNS log ingestion completes without unbounded waiting
      let capturedResolvers: any[] = [];
      const maxPollAttempts = 3;
      for (let attempt = 0; attempt < maxPollAttempts; attempt++) {
        if (signal?.aborted) break;
        if (attempt > 0) {
          await new Promise(r => setTimeout(r, 400));
        }
        const collectRes = await fetch(`/api/dns-leak-probe?runId=${encodeURIComponent(runId)}`, {
          cache: 'no-store',
          signal: createBoundedSignal(4500, signal),
        });
        if (collectRes.ok) {
          const collectJson = await collectRes.json();
          if (Array.isArray(collectJson.resolvers) && collectJson.resolvers.length > 0) {
            capturedResolvers = collectJson.resolvers;
            break;
          }
        }
      }

      return evaluateDnsTestResult({
        runId,
        authoritativeConfigured: true,
        dnsLeakDomain,
        missingEnvVars: [],
        resolvers: capturedResolvers,
        ipDetails,
        independentBrowserObservation,
        startedAt,
        completedAt: new Date().toISOString(),
      });
    }

    return evaluateDnsTestResult({
      runId,
      authoritativeConfigured,
      dnsLeakDomain,
      missingEnvVars,
      resolvers: Array.isArray(json.resolvers) ? json.resolvers : [],
      ipDetails,
      independentBrowserObservation,
      startedAt,
      completedAt: new Date().toISOString(),
    });
  } catch (e: any) {
    const independentBrowserObservation = await independentPromise.catch(() =>
      evaluateIndependentBrowserDnsObservation([], ipDetails)
    );
    return evaluateDnsTestResult({
      runId,
      authoritativeConfigured: false,
      resolvers: [],
      ipDetails,
      independentBrowserObservation,
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
  referenceIpOrDetails: string | IpDetails | null,
  signal?: AbortSignal
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
    if (Array.isArray(referenceIpOrDetails.ipSources)) {
      for (const src of referenceIpOrDetails.ipSources) {
        if (src?.ip) referencePublicIps.push(src.ip);
      }
    }
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

    if (signal?.aborted) {
      resolve(
        evaluateWebRtcCandidates({
          isSupported: true,
          candidates: [],
          referencePublicIps,
          stunServersUsed,
          startedAt,
          completedAt: new Date().toISOString(),
          errorMessage: 'WebRTC test aborted',
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

    const onExternalAbort = () => {
      finishTest('WebRTC test aborted');
    };

    const finishTest = (errorMessage?: string) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);
      signal?.removeEventListener('abort', onExternalAbort);
      try {
        if (pc) {
          pc.onicecandidate = null;
          pc.onicecandidateerror = null;
          pc.close();
        }
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

    signal?.addEventListener('abort', onExternalAbort, { once: true });

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
 * 4.5 Real TCP Port Exposure & Router Admin Port Test
 * Queries /api/port-scan (which only scans a verified public socket IP to prevent SSRF)
 * and evaluates results without fabricating open/closed states.
 */
export async function performPortLeakTest(signal?: AbortSignal): Promise<PortLeakResult> {
  const startedAt = new Date().toISOString();
  try {
    const resp = await fetch(`/api/port-scan?t=${Date.now()}`, {
      cache: 'no-store',
      signal: createBoundedSignal(7500, signal),
    });

    if (!resp.ok) {
      const errJson = await resp.json().catch(() => ({}));
      return evaluatePortLeakResult({
        targetIp: null,
        targetSource: 'unverifiable_local_socket',
        canScanFromServer: false,
        ports: [],
        startedAt,
        completedAt: new Date().toISOString(),
        errorMessage: errJson?.error || `HTTP ${resp.status}`,
      });
    }

    const json = await resp.json();
    return evaluatePortLeakResult({
      targetIp: json.targetIp || null,
      targetSource: json.targetSource || 'unverifiable_local_socket',
      canScanFromServer: Boolean(json.canScanFromServer),
      ports: Array.isArray(json.ports) ? json.ports : [],
      startedAt: json.startedAt || startedAt,
      completedAt: json.completedAt || new Date().toISOString(),
    });
  } catch (e: any) {
    return evaluatePortLeakResult({
      targetIp: null,
      targetSource: 'unverifiable_local_socket',
      canScanFromServer: false,
      ports: [],
      startedAt,
      completedAt: new Date().toISOString(),
      errorMessage: e?.message || 'خطا در ارتباط با سرویس بررسی پورت‌ها',
    });
  }
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
        signal: createBoundedSignal(3000, signal),
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
        signal: createBoundedSignal(8000, signal),
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
export async function fetchAiAudit(networkData: any, signal?: AbortSignal): Promise<AiAuditReport> {
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
      signal: createBoundedSignal(9000, signal),
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

  const dnsStatusFa = formatTestStatusLabelFa(networkData?.dnsLeakStatus || 'NOT_CONFIGURED');
  const webRtcStatusFa = formatTestStatusLabelFa(networkData?.webRtcLeakStatus || 'INCONCLUSIVE');
  const portStatusFa = networkData?.portLeakStatus
    ? formatTestStatusLabelFa(networkData.portLeakStatus)
    : null;

  return {
    riskScore: null,
    statusLevel: 'نامشخص',
    summaryFa:
      'سرویس تحلیل هوش مصنوعی پاسخ نداد یا تنظیم نشده است. نتایج زیر مستقیماً از مشاهدات واقعی تست‌های شبکه استخراج شده‌اند.',
    detailedAnalysisFa: [
      networkData?.ip
        ? `آدرس IP مشاهده‌شده: ${networkData.ip} (${networkData.usageTypeFa || 'نامشخص'})`
        : 'آدرس IP عمومی دریافت نشد (خطای شبکه).',
      `وضعیت تست Authoritative DNS: ${dnsStatusFa}`,
      `وضعیت تست WebRTC: ${webRtcStatusFa}`,
      ...(portStatusFa ? [`وضعیت بررسی پورت‌های حساس روتر: ${portStatusFa}`] : []),
    ],
    threatsFoundFa: [],
    recommendationsFa: [
      'برای اثبات قطعی عدم نشت DNS، متغیرهای DNS_LEAK_DOMAIN، DNS_COLLECTOR_API_URL و DNS_COLLECTOR_API_TOKEN باید روی سرور تنظیم شوند.',
      'توجه داشته باشید که تست‌های داخل مرورگر، وضعیت تمام ترافیک سطح سیستم‌عامل را اثبات نمی‌کنند.'
    ],
    optimalNodeSuggestion: nodeSuggestion,
    dnsRecommendations: dnsRecs,
    aiAvailable: false,
  };
}
