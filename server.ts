import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import net from 'node:net';
import crypto from 'node:crypto';
import dns from 'node:dns';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '64kb' }));

// Simple in-memory rate limiter per remote socket IP to prevent abuse
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
function rateLimit(maxRequests: number, windowMs: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const key = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    entry.count += 1;
    if (entry.count > maxRequests) {
      return res.status(429).json({
        success: false,
        errorCode: 'RATE_LIMIT_EXCEEDED',
        error: 'تعداد درخواست‌ها بیش از حد مجاز است. لطفاً چند ثانیه صبر کنید.'
      });
    }
    return next();
  };
}

// Helper for Gemini AI initialization
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({ apiKey });
}

function normalizeIp(rawIp: string | undefined | null): string | null {
  if (!rawIp) return null;
  let cleaned = rawIp.trim();
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.slice(7);
  }
  return net.isIP(cleaned) ? cleaned : null;
}

function isPublicRoutableIp(ip: string): boolean {
  if (!net.isIP(ip)) return false;
  if (ip === '127.0.0.1' || ip === '::1') return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return false;
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1] || '0', 10);
    if (second >= 16 && second <= 31) return false;
  }
  if (ip.toLowerCase().startsWith('fe80:') || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) {
    return false;
  }
  return true;
}

// 1. Endpoint: Evidence-based Client & Server IP Inspection, GeoIP Estimation & Real Reputation Check
app.get('/api/ip-info', rateLimit(30, 60_000), async (req, res) => {
  const startedAt = new Date().toISOString();
  try {
    const trustProxy = process.env.TRUST_PROXY === 'true';
    const rawSocketIp = normalizeIp(req.socket.remoteAddress);
    const rawForwarded = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      (req.headers['cf-connecting-ip'] as string)?.trim() ||
      null;
    const forwardedHeaderIp = normalizeIp(rawForwarded);

    // Only accept X-Forwarded-For / CF-Connecting-IP if TRUST_PROXY=true
    const serverObservedIp = trustProxy && forwardedHeaderIp ? forwardedHeaderIp : rawSocketIp;

    // Optional client-reported public IP (strictly validated with net.isIP to prevent SSRF)
    const queryClientIp = typeof req.query.clientIp === 'string' ? normalizeIp(req.query.clientIp) : null;
    const targetLookupIp =
      (queryClientIp && isPublicRoutableIp(queryClientIp) ? queryClientIp : null) ||
      (serverObservedIp && isPublicRoutableIp(serverObservedIp) ? serverObservedIp : null);

    let geoData: {
      ip: string;
      country_name: string | null;
      country_code: string | null;
      region: string | null;
      city: string | null;
      isp: string | null;
      asn: string | null;
      org: string | null;
      latitude: number | null;
      longitude: number | null;
      timezone: string | null;
      sourceName: string;
    } | null = null;

    const lookupErrors: string[] = [];

    // Primary GeoIP lookup: ipwho.is (supports HTTPS, no key required for basic GeoIP)
    try {
      const endpoint = targetLookupIp
        ? `https://ipwho.is/${encodeURIComponent(targetLookupIp)}`
        : 'https://ipwho.is/';
      const resp = await fetch(endpoint, {
        headers: { 'Accept': 'application/json', 'User-Agent': 'NETLeakGard-Auditor/2.0' },
        signal: AbortSignal.timeout(4500),
      });
      if (resp.ok) {
        const raw = await resp.json();
        if (raw && raw.success !== false && raw.ip && net.isIP(raw.ip)) {
          geoData = {
            ip: raw.ip,
            country_name: raw.country || null,
            country_code: raw.country_code || null,
            region: raw.region || null,
            city: raw.city || null,
            isp: raw.connection?.isp || raw.isp || null,
            asn: raw.connection?.asn ? `AS${raw.connection.asn}` : null,
            org: raw.connection?.org || raw.org || null,
            latitude: typeof raw.latitude === 'number' ? raw.latitude : null,
            longitude: typeof raw.longitude === 'number' ? raw.longitude : null,
            timezone: raw.timezone?.id || null,
            sourceName: 'ipwho.is HTTPS GeoIP',
          };
        } else {
          lookupErrors.push(`ipwho.is: ${raw?.message || 'invalid payload'}`);
        }
      } else {
        lookupErrors.push(`ipwho.is HTTP ${resp.status}`);
      }
    } catch (e: any) {
      lookupErrors.push(`ipwho.is error: ${e?.message || 'timeout'}`);
    }

    // Secondary independent GeoIP lookup if primary failed: ipapi.co
    if (!geoData) {
      try {
        const endpoint2 = targetLookupIp
          ? `https://ipapi.co/${encodeURIComponent(targetLookupIp)}/json/`
          : 'https://ipapi.co/json/';
        const resp2 = await fetch(endpoint2, {
          headers: { 'Accept': 'application/json', 'User-Agent': 'NETLeakGard-Auditor/2.0' },
          signal: AbortSignal.timeout(4500),
        });
        if (resp2.ok) {
          const raw2 = await resp2.json();
          if (raw2 && !raw2.error && raw2.ip && net.isIP(raw2.ip)) {
            geoData = {
              ip: raw2.ip,
              country_name: raw2.country_name || null,
              country_code: raw2.country_code || null,
              region: raw2.region || null,
              city: raw2.city || null,
              isp: raw2.org || null,
              asn: raw2.asn || null,
              org: raw2.org || null,
              latitude: typeof raw2.latitude === 'number' ? raw2.latitude : null,
              longitude: typeof raw2.longitude === 'number' ? raw2.longitude : null,
              timezone: raw2.timezone || null,
              sourceName: 'ipapi.co HTTPS GeoIP',
            };
          } else {
            lookupErrors.push(`ipapi.co: ${raw2?.reason || 'error payload'}`);
          }
        } else {
          lookupErrors.push(`ipapi.co HTTP ${resp2.status}`);
        }
      } catch (e: any) {
        lookupErrors.push(`ipapi.co error: ${e?.message || 'timeout'}`);
      }
    }

    const resolvedIp = geoData?.ip || targetLookupIp || null;

    if (!resolvedIp) {
      return res.status(200).json({
        success: false,
        errorCode: 'IP_LOOKUP_FAILED',
        startedAt,
        completedAt: new Date().toISOString(),
        serverSocketIp: rawSocketIp,
        forwardedHeaderIp,
        proxyHeaderTrusted: trustProxy,
        lookupErrors,
        error: 'امکان دریافت آدرس IP عمومی معتبر از سرویس‌های مرجع فراهم نشد. هیچ آدرس IP یا موقعیت ساختگی جایگزین نگردید.'
      });
    }

    // Heuristic ASN/Org classification (explicitly probabilistic)
    const ispLower = (geoData?.isp || '').toLowerCase();
    const orgLower = (geoData?.org || '').toLowerCase();
    const asLower = (geoData?.asn || '').toLowerCase();

    const hostingKeywords = [
      'datacenter', 'hosting', 'cloud', 'digitalocean', 'hetzner', 'linode',
      'aws', 'amazon', 'azure', 'google cloud', 'ovh', 'contabo', 'vultr', 'm247',
      'choopa', 'leaseweb', 'akamai', 'cloudflare', 'fastly', 'datapacket', 'hostinger'
    ];
    const mobileKeywords = ['mobile', 'cellular', 'mci', 'irancell', 'rightel', '4g', '5g', 'lte', 'vodafone', 't-mobile'];

    const hasGeoMetadata = Boolean(geoData?.isp || geoData?.org || geoData?.asn);
    const isHostingProbable = hasGeoMetadata
      ? hostingKeywords.some(k => ispLower.includes(k) || orgLower.includes(k) || asLower.includes(k))
      : null;
    const isMobileProbable = hasGeoMetadata
      ? mobileKeywords.some(k => ispLower.includes(k) || orgLower.includes(k))
      : false;

    let usageType: 'Residential' | 'Commercial' | 'Datacenter' | 'Mobile' | 'Unknown' = 'Unknown';
    let usageTypeFa = 'نامشخص (عدم دسترسی به متادیتای ASN)';

    if (hasGeoMetadata) {
      if (isHostingProbable) {
        usageType = 'Datacenter';
        usageTypeFa = 'احتمالاً مرکز داده / هاستینگ (بر پایهٔ نام ASN)';
      } else if (isMobileProbable) {
        usageType = 'Mobile';
        usageTypeFa = 'احتمالاً اپراتور تلفن همراه (بر پایهٔ نام ISP)';
      } else {
        usageType = 'Residential';
        usageTypeFa = 'احتمالاً ISP مسکونی / تجاری (بدون نشانهٔ دیتاسنتر در نام ASN)';
      }
    }

    // Real Reputation Check: AbuseIPDB (only if ABUSEIPDB_API_KEY is configured)
    let abuseIpDbStatus: 'clean' | 'flagged' | 'not_configured' | 'error' = 'not_configured';
    let abuseConfidenceScore: number | null = null;
    let isAbuseIpFlagged: boolean | null = null;

    const abuseKey = process.env.ABUSEIPDB_API_KEY;
    if (abuseKey && abuseKey.trim() !== '' && isPublicRoutableIp(resolvedIp)) {
      try {
        const abuseResp = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(resolvedIp)}&maxAgeInDays=90`,
          {
            headers: {
              'Key': abuseKey.trim(),
              'Accept': 'application/json',
            },
            signal: AbortSignal.timeout(4000),
          }
        );
        if (abuseResp.ok) {
          const abuseJson = await abuseResp.json();
          const score = abuseJson?.data?.abuseConfidenceScore;
          if (typeof score === 'number') {
            abuseConfidenceScore = score;
            isAbuseIpFlagged = score >= 25;
            abuseIpDbStatus = isAbuseIpFlagged ? 'flagged' : 'clean';
          }
        } else {
          abuseIpDbStatus = 'error';
        }
      } catch {
        abuseIpDbStatus = 'error';
      }
    }

    const googleSafeBrowsingStatus: 'not_configured' = 'not_configured';
    const spamhausDnsblStatus: 'not_configured' = 'not_configured';

    // Risk score is ONLY calculated if a real reputation source (AbuseIPDB) returned data
    const verifiedSourcesCount = abuseIpDbStatus === 'clean' || abuseIpDbStatus === 'flagged' ? 1 : 0;
    const riskFactorsFa: string[] = [];
    let fraudRiskScore: number | null = null;
    let fraudStatusFa = 'بررسی‌نشده (کلید API پایگاه‌های Blacklist تنظیم نشده است)';
    let fraudStatusEn = 'Unverified (Blacklist API keys not configured)';

    if (abuseConfidenceScore !== null) {
      fraudRiskScore = abuseConfidenceScore;
      riskFactorsFa.push(`امتیاز گزارش‌های AbuseIPDB در ۹۰ روز گذشته: ${abuseConfidenceScore}%`);
      if (isHostingProbable) {
        riskFactorsFa.push('آدرس IP متعلق به محدودهٔ دیتاسنتر / هاستینگ است.');
      }
      if (fraudRiskScore >= 50) {
        fraudStatusFa = `پرریسک (امتیاز AbuseIPDB: ${fraudRiskScore}%)`;
        fraudStatusEn = `High Risk (AbuseIPDB: ${fraudRiskScore}%)`;
      } else if (fraudRiskScore >= 20) {
        fraudStatusFa = `ریسک متوسط (امتیاز AbuseIPDB: ${fraudRiskScore}%)`;
        fraudStatusEn = `Medium Risk (AbuseIPDB: ${fraudRiskScore}%)`;
      } else {
        fraudStatusFa = `بدون گزارش تخلف در AbuseIPDB (${fraudRiskScore}%) — سایر فهرست‌ها بررسی نشده‌اند`;
        fraudStatusEn = `Zero/Low AbuseIPDB Score (${fraudRiskScore}%)`;
      }
    } else {
      riskFactorsFa.push(
        'کلید ABUSEIPDB_API_KEY در سرور تنظیم نشده است؛ هیچ وضعیت جعلی «پاک» برای Google یا Spamhaus یا AbuseIPDB تولید نمی‌شود.'
      );
    }

    const completedAt = new Date().toISOString();

    return res.json({
      success: true,
      data: {
        status: geoData ? 'PASS' : 'INCONCLUSIVE',
        testName: 'Public IP & GeoIP Inspection',
        startedAt,
        completedAt,
        observations: [
          `آدرس IP مورد بررسی: ${resolvedIp}`,
          trustProxy
            ? `هدر پروکسی مورد اعتماد فعال است (TRUST_PROXY=true).`
            : `هدر X-Forwarded-For به دلیل غیرفعال بودن TRUST_PROXY به عنوان منبع قطعی پذیرفته نشد.`,
          geoData
            ? `متادیتای جغرافیایی از سرویس ${geoData.sourceName} دریافت شد (تخمین پایگاه داده GeoIP).`
            : 'متادیتای GeoIP دریافت نشد.',
        ],
        evidence: {
          resolvedIp,
          serverSocketIp: rawSocketIp,
          forwardedHeaderIp,
          proxyHeaderTrusted: trustProxy,
          geoSource: geoData?.sourceName || null,
          lookupErrors,
        },
        limitations: [
          'موقعیت جغرافیایی (کشور و شهر) صرفاً تخمین پایگاه دادهٔ GeoIP است و مکان فیزیکی یا GPS دستگاه نیست.',
          'مشاهدهٔ آدرس IP در مرورگر اثبات نمی‌کند که تمام نرم‌افزارهای سیستم‌عامل از همین مسیر شبکه عبور می‌کنند.'
        ],
        errorCode: geoData ? null : 'PARTIAL_GEOIP_DATA',
        source: geoData?.sourceName || 'Server Socket Inspection',
        confidence: geoData ? 'high' : 'low',

        ip: resolvedIp,
        clientObservedIp: queryClientIp,
        serverObservedIp,
        serverSocketIp: rawSocketIp,
        forwardedHeaderIp,
        proxyHeaderTrusted: trustProxy,
        ipSources: [],
        ipMismatchDetected: false,
        version: resolvedIp.includes(':') ? 'IPv6' : 'IPv4',
        countryName: geoData?.country_name || null,
        countryCode: geoData?.country_code || null,
        city: geoData?.city || null,
        region: geoData?.region || null,
        isp: geoData?.isp || null,
        asn: geoData?.asn || null,
        org: geoData?.org || null,
        lat: geoData?.latitude ?? null,
        lon: geoData?.longitude ?? null,
        timezone: geoData?.timezone || null,
        isGeoEstimated: true,

        usageType,
        usageTypeFa,
        connectionType:
          isHostingProbable === null
            ? 'Unknown'
            : isHostingProbable
              ? 'VPN / Proxy Probable'
              : 'Direct Connection Probable',
        connectionTypeFa:
          isHostingProbable === null
            ? 'نامشخص'
            : isHostingProbable
              ? 'احتمالاً خروجی دیتاسنتر / VPN (بر اساس ASN)'
              : 'احتمالاً اتصال مستقیم ISP (بدون نشانهٔ دیتاسنتر)',
        isVpnOrProxyDetected: isHostingProbable,
        isDatacenter: isHostingProbable,

        fraudRiskScore,
        riskFactorsFa,
        fraudStatusFa,
        fraudStatusEn,
        blacklistDetails: {
          googleSafeBrowsingStatus,
          spamhausDnsblStatus,
          abuseIpDbStatus,
          abuseConfidenceScore,
          isGoogleFlagged: null,
          isSpamhausFlagged: null,
          isAbuseIpFlagged,
          verifiedSourcesCount,
          threatCategoryFa:
            verifiedSourcesCount > 0
              ? `بررسی‌شده در ${verifiedSourcesCount} منبع معتبر`
              : 'عدم پیکربندی کلید API سرویس‌های Blacklist (بدون ادعای پاک بودن)',
          threatCategoryEn:
            verifiedSourcesCount > 0
              ? `Verified against ${verifiedSourcesCount} source(s)`
              : 'Blacklist APIs Not Configured',
        },
        userIntentAnalysisFa: hasGeoMetadata
          ? `طبقه‌بندی احتمالی بر اساس متادیتای ASN (${geoData?.asn || 'نامشخص'}): ${usageTypeFa}.`
          : 'اطلاعات ASN برای تحلیل نوع شبکه در دسترس نیست.',
      },
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      errorCode: 'INTERNAL_IP_INFO_ERROR',
      error: 'خطا در بررسی اطلاعات آدرس IP در سرور.'
    });
  }
});

// 2. Endpoint: Real Authoritative DNS Leak Session & Collector Query (Zero Fake Resolvers)
app.get('/api/dns-leak-probe', rateLimit(30, 60_000), async (req, res) => {
  const startedAt = new Date().toISOString();
  const runId =
    typeof req.query.runId === 'string' && /^[a-zA-Z0-9-]{8,64}$/.test(req.query.runId)
      ? req.query.runId
      : crypto.randomUUID();

  const dnsLeakDomain = (process.env.DNS_LEAK_DOMAIN || '').trim();
  const collectorApiUrl = (process.env.DNS_COLLECTOR_API_URL || '').trim();
  const collectorToken = (process.env.DNS_COLLECTOR_API_TOKEN || '').trim();

  const authoritativeConfigured = Boolean(dnsLeakDomain && collectorApiUrl);

  try {
    if (!authoritativeConfigured) {
      // Do NOT return fake Cloudflare/Google/Quad9/OpenDNS resolvers or Math.random() latencies!
      // Report server OS configured resolvers strictly as server-side metadata, and mark authoritativeConfigured: false.
      const serverSystemDns = dns.getServers();
      return res.json({
        success: true,
        runId,
        startedAt,
        completedAt: new Date().toISOString(),
        authoritativeConfigured: false,
        dnsLeakDomain: null,
        serverSystemResolvers: serverSystemDns,
        resolvers: [],
        messageFa:
          'دامنهٔ Authoritative DNS (متغیر محیطی DNS_LEAK_DOMAIN) و وب‌هوک جمع‌آوری لاگ (DNS_COLLECTOR_API_URL) تنظیم نشده‌اند. هیچ سرور DNS ساختگی تولید نشد.',
      });
    }

    // When DNS_LEAK_DOMAIN and DNS_COLLECTOR_API_URL are configured:
    // Query the authoritative DNS collector for queries matching runId
    const url = new URL(collectorApiUrl);
    url.searchParams.set('runId', runId);

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (collectorToken) {
      headers['Authorization'] = `Bearer ${collectorToken}`;
    }

    const collectorResp = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(5000),
    });

    if (!collectorResp.ok) {
      return res.status(502).json({
        success: false,
        runId,
        authoritativeConfigured: true,
        errorCode: `COLLECTOR_HTTP_${collectorResp.status}`,
        error: `سرویس ثبت‌کنندهٔ Authoritative DNS کد وضعیت ${collectorResp.status} را برگرداند.`,
      });
    }

    const collectorData = await collectorResp.json();
    const observedResolvers = Array.isArray(collectorData?.resolvers)
      ? collectorData.resolvers.map((r: any, idx: number) => ({
          id: String(r.id || `auth-${idx}`),
          name: String(r.name || r.isp || 'Observed Recursive Resolver'),
          primaryIp: String(r.ip || r.primaryIp || 'نامشخص'),
          asn: r.asn ? String(r.asn) : undefined,
          location: String(r.location || r.country || 'نامشخص'),
          status: String(r.status || 'مشاهده‌شده در Authoritative DNS'),
          responseTimeMs: typeof r.responseTimeMs === 'number' ? r.responseTimeMs : null,
          isEncryptedDoH: typeof r.isEncryptedDoH === 'boolean' ? r.isEncryptedDoH : null,
          observationMethod: 'authoritative_dns_log',
        }))
      : [];

    return res.json({
      success: true,
      runId,
      startedAt,
      completedAt: new Date().toISOString(),
      authoritativeConfigured: true,
      dnsLeakDomain,
      resolvers: observedResolvers,
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      runId,
      authoritativeConfigured,
      errorCode: 'DNS_COLLECTOR_FETCH_FAILED',
      error: `خطا در ارتباط با سرویس Authoritative DNS: ${err?.message || 'Unknown error'}`,
    });
  }
});

// 3. Endpoint: HTTP RTT Latency Probe & Bounded Speed Chunk
app.get('/api/ping', rateLimit(120, 60_000), (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.json({ pong: true, serverTimestamp: Date.now() });
});

app.get('/api/speed-test/chunk', rateLimit(20, 60_000), (req, res) => {
  // Bounded payload: default 512 KB, max 2 MB to prevent bandwidth exhaustion
  const requestedBytes = typeof req.query.bytes === 'string' ? parseInt(req.query.bytes, 10) : 512 * 1024;
  const chunkSize = Math.max(64 * 1024, Math.min(2 * 1024 * 1024, Number.isFinite(requestedBytes) ? requestedBytes : 512 * 1024));
  const buffer = Buffer.alloc(chunkSize, 0x78);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', chunkSize.toString());
  res.send(buffer);
});

// 4. Endpoint: Gemini AI Security & Privacy Audit (in Persian, strictly grounded in real evidence)
app.post('/api/gemini-audit', rateLimit(15, 60_000), async (req, res) => {
  try {
    const gemini = getGeminiClient();
    const { networkData } = req.body || {};

    if (!networkData || typeof networkData !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'داده‌های ورودی برای تحلیل ارسال نشده است.'
      });
    }

    if (!gemini) {
      return res.json({
        success: true,
        aiAvailable: false,
        audit: {
          riskScore: null,
          statusLevel: 'نامشخص',
          summaryFa:
            'کلید GEMINI_API_KEY در محیط سرور تنظیم نشده است. گزارش زیر صرفاً بر اساس قواعد قطعی و شواهد جمع‌آوری‌شده از تست‌ها تولید شده است.',
          detailedAnalysisFa: [
            networkData.ip
              ? `آدرس IP عمومی مشاهده‌شده: ${networkData.ip} (${networkData.usageTypeFa || 'نامشخص'})`
              : 'آدرس IP عمومی به دلیل خطا قابل مشاهده نبود.',
            `وضعیت تست DNS: ${networkData.dnsLeakStatus || 'تنظیم‌نشده (not_configured)'}`,
            `وضعیت تست WebRTC: ${networkData.webRtcLeakStatus || 'نامشخص'}`,
          ],
          threatsFoundFa: [],
          recommendationsFa: [
            'برای اجرای تست کامل Authoritative DNS، دامنهٔ اختصاصی DNS_LEAK_DOMAIN را در سرور پیکربندی کنید.',
            'در صورت استفاده از VPN، قابلیت Kill Switch سطح سیستم‌عامل را فعال نگه دارید.'
          ],
          aiAvailable: false,
        }
      });
    }

    const prompt = `
شما یک ممیز ارشد امنیت شبکه هستید. بر اساس داده‌های واقعی زیر (بدون هیچ‌گونه حدس غیرمستند یا ادعای امنیت صددرصدی)، یک گزارش فنی به زبان فارسی به صورت JSON تولید کنید:
${JSON.stringify(networkData, null, 2)}

قوانین مهم:
- اگر تست DNS در وضعیت not_configured یا نامشخص است، صریحاً اعلام کنید که بدون Authoritative DNS نمی‌توان عدم نشت DNS را اثبات کرد.
- هرگز ادعا نکنید پروتکل تونل VPN (مانند WireGuard یا OpenVPN) از طریق مرورگر اثبات شده است.

فرمت خروجی JSON:
{
  "riskScore": number | null,
  "statusLevel": "امن" | "هشدار" | "خطر نشت" | "نامشخص",
  "summaryFa": "خلاصه دقیق و مبتنی بر شواهد به فارسی",
  "detailedAnalysisFa": ["مورد ۱", "مورد ۲", "مورد ۳"],
  "threatsFoundFa": ["مورد تهدید در صورت وجود"],
  "recommendationsFa": ["توصیه فنی ۱", "توصیه فنی ۲"]
}
`;

    const response = await gemini.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      }
    });

    const responseText = response.text || '';
    const parsedData = JSON.parse(responseText);

    return res.json({
      success: true,
      aiAvailable: true,
      audit: {
        ...parsedData,
        aiAvailable: true,
        generatedAt: new Date().toISOString(),
      }
    });
  } catch (err: any) {
    return res.status(200).json({
      success: false,
      aiAvailable: false,
      errorCode: 'AI_AUDIT_ERROR',
      error: `خطا در اجرای تحلیل هوش مصنوعی: ${err?.message || 'Service error'}`
    });
  }
});

// Setup Vite middleware in dev mode
async function setupServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'custom'
    });
    app.use(vite.middlewares);

    app.use('*', async (req, res, next) => {
      const url = req.originalUrl;
      try {
        let template = await vite.transformIndexHtml(url, `
          <!doctype html>
          <html lang="fa" dir="rtl" class="dark">
            <head>
              <meta charset="UTF-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
              <meta name="theme-color" content="#020617" />
              <meta name="mobile-web-app-capable" content="yes" />
              <meta name="apple-mobile-web-app-capable" content="yes" />
              <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
              <meta name="apple-mobile-web-app-title" content="LeakGuard" />
              <meta name="application-name" content="LeakGuard" />
              <meta name="msapplication-TileColor" content="#020617" />
              <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
              <link rel="icon" type="image/svg+xml" href="/icon.svg" />
              <title>سامانه تست نشت شبکه و امنیت VPN | LeakGuard Persian</title>
              <meta name="description" content="ابزار جامع و بومی‌سازی شده سنجش نشت IP، DNS، WebRTC، تحلیل امنیت VPN و عیب‌یابی شبکه به زبان فارسی." />
              <link rel="preconnect" href="https://fonts.googleapis.com">
              <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
              <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
            </head>
            <body class="bg-slate-950 text-slate-100 font-sans antialiased selection:bg-cyan-500 selection:text-slate-950 min-h-screen overscroll-y-none">
              <div id="root"></div>
              <script type="module" src="/src/main.tsx"></script>
            </body>
          </html>
        `);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
      } catch (e: any) {
        vite.ssrFixStacktrace(e);
        next(e);
      }
    });
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`[LeakGuard Server] Running on http://localhost:${PORT}`);
  });
}

setupServer();
