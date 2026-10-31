import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import crypto from 'node:crypto';
import dns from 'node:dns';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import {
  COMMON_SENSITIVE_PORTS,
  canonicalizeIp,
  formatTestStatusLabelFa,
  isGloballyRoutablePublicIp,
  isPrivateOrLocalAddress,
  isSafeExternalUrl,
  isValidDnsObservationRecord,
  isValidDnsRunId,
  parseDnsLeakProbeQname,
  validateAiAuditPayload
} from './src/utils/networkEvaluator';

// In AI Studio Cloud Run preview, WebSockets are not maintained by the proxy.
// Set DISABLE_HMR = 'true' to disable HMR and prevent WebSocket connection errors in @vite/client.
process.env.DISABLE_HMR = 'true';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers middleware (compatible with AI Studio preview iframe)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  }
  next();
});

app.use(express.json({ limit: '64kb' }));

// Bounded in-memory rate limiter per route bucket & remote socket IP to prevent abuse and memory leaks
const MAX_RATE_LIMIT_ENTRIES = 5000;
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

function pruneRateLimitMap(now: number) {
  if (rateLimitMap.size < MAX_RATE_LIMIT_ENTRIES) return;
  for (const [k, v] of rateLimitMap.entries()) {
    if (now > v.resetAt) {
      rateLimitMap.delete(k);
    }
  }
  if (rateLimitMap.size >= MAX_RATE_LIMIT_ENTRIES) {
    const oldestKey = rateLimitMap.keys().next().value;
    if (oldestKey) rateLimitMap.delete(oldestKey);
  }
}

function rateLimit(maxRequests: number, windowMs: number, bucket = 'global') {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const socketAddr = canonicalizeIp(req.socket.remoteAddress) || req.socket.remoteAddress || 'unknown';
    const key = `${bucket}:${socketAddr}`;
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) {
      pruneRateLimitMap(now);
      rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    entry.count += 1;
    if (entry.count > maxRequests) {
      const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
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

export function normalizeIp(rawIp: string | undefined | null): string | null {
  if (!rawIp || typeof rawIp !== 'string') return null;
  const canonical = canonicalizeIp(rawIp);
  if (!canonical) return null;
  return net.isIP(canonical) ? canonical : null;
}

export function isPublicRoutableIp(ip: string | undefined | null): boolean {
  if (!ip) return false;
  const normalized = normalizeIp(ip);
  if (!normalized) return false;
  return net.isIP(normalized) !== 0 && isGloballyRoutablePublicIp(normalized);
}

/**
 * Extracts and validates client IP from socket and optional proxy headers.
 * - Proxy headers are ONLY trusted if TRUST_PROXY=true AND the immediate socket peer is a local/private reverse proxy.
 * - Uses the rightmost valid public IP in X-Forwarded-For to prevent client-prepended XFF spoofing.
 */
function extractVerifiedClientIpInfo(req: express.Request): {
  rawSocketIp: string | null;
  forwardedHeaderIp: string | null;
  proxyHeaderTrusted: boolean;
  serverObservedIp: string | null;
  canScanForwardedIp: boolean;
} {
  const rawSocketIp = normalizeIp(req.socket.remoteAddress);
  const trustProxyEnv = process.env.TRUST_PROXY === 'true';
  const socketIsLocalProxy = !rawSocketIp || isPrivateOrLocalAddress(rawSocketIp);
  const proxyHeaderTrusted = trustProxyEnv && socketIsLocalProxy;

  const xffRaw = typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'] : '';
  const cfRaw = typeof req.headers['cf-connecting-ip'] === 'string' ? req.headers['cf-connecting-ip'].trim() : '';

  const xffTokens = xffRaw
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);

  const validXffPublicIps: string[] = [];
  let allXffTokensValidIps = xffTokens.length > 0;
  for (const token of xffTokens) {
    const norm = normalizeIp(token);
    if (!norm) {
      allXffTokensValidIps = false;
      break;
    }
    if (isPublicRoutableIp(norm)) {
      validXffPublicIps.push(norm);
    }
  }

  // Select rightmost public IP from X-Forwarded-For (appended by trusted reverse proxy), or single CF-Connecting-IP
  let forwardedHeaderIp: string | null = null;
  if (allXffTokensValidIps && validXffPublicIps.length > 0) {
    forwardedHeaderIp = validXffPublicIps[validXffPublicIps.length - 1];
  } else if (cfRaw && !xffRaw) {
    const normCf = normalizeIp(cfRaw);
    if (normCf && isPublicRoutableIp(normCf)) {
      forwardedHeaderIp = normCf;
    }
  }

  const serverObservedIp = proxyHeaderTrusted && forwardedHeaderIp ? forwardedHeaderIp : rawSocketIp;

  // For active TCP port scanning, only allow scanning a forwarded header IP if XFF had at most 1 public IP (no multi-hop spoofing ambiguity)
  const canScanForwardedIp =
    proxyHeaderTrusted &&
    forwardedHeaderIp !== null &&
    allXffTokensValidIps &&
    validXffPublicIps.length === 1;

  return {
    rawSocketIp,
    forwardedHeaderIp,
    proxyHeaderTrusted,
    serverObservedIp,
    canScanForwardedIp,
  };
}

/**
 * Resolves a hostname via DNS and verifies that EVERY resolved A/AAAA address is a globally routable public IP.
 * Prevents SSRF to internal networks, cloud metadata (169.254.169.254), loopback, or reserved ranges.
 */
export async function resolveAndValidatePublicHost(hostname: string): Promise<{
  ok: boolean;
  address?: string;
  family?: 4 | 6;
  allAddresses?: string[];
  reason?: string;
}> {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim().toLowerCase().replace(/\.$/, '');
  if (!cleanHost) {
    return { ok: false, reason: 'نام میزبان خالی است.' };
  }

  const ipVersion = net.isIP(cleanHost);
  if (ipVersion === 4 || ipVersion === 6) {
    if (!isPublicRoutableIp(cleanHost)) {
      return { ok: false, reason: `آدرس IP مقصد (${cleanHost}) عمومی و قابل مسیریابی نیست.` };
    }
    const norm = normalizeIp(cleanHost)!;
    return {
      ok: true,
      address: norm,
      family: (net.isIP(norm) as 4 | 6) || 4,
      allAddresses: [norm],
    };
  }

  try {
    const records = await dns.promises.lookup(cleanHost, { all: true, verbatim: true });
    if (!Array.isArray(records) || records.length === 0) {
      return { ok: false, reason: 'هیچ رکورد DNS معتبری برای میزبان یافت نشد.' };
    }

    const validatedAddresses: string[] = [];
    let selectedAddress: string | undefined;
    let selectedFamily: 4 | 6 | undefined;

    for (const rec of records) {
      const norm = normalizeIp(rec.address);
      if (!norm || !isPublicRoutableIp(norm)) {
        return {
          ok: false,
          reason: `رکورد DNS میزبان (${cleanHost}) به یک آدرس غیرعمومی یا غیرمجاز (${rec.address}) اشاره می‌کند (محافظت در برابر SSRF / DNS Rebinding).`,
        };
      }
      validatedAddresses.push(norm);
      if (!selectedAddress) {
        selectedAddress = norm;
        selectedFamily = rec.family === 6 ? 6 : 4;
      }
    }

    if (!selectedAddress || !selectedFamily) {
      return { ok: false, reason: 'پاسخ DNS معتبر نبود.' };
    }

    return {
      ok: true,
      address: selectedAddress,
      family: selectedFamily,
      allAddresses: validatedAddresses,
    };
  } catch (err: any) {
    return {
      ok: false,
      reason: `خطا در استعلام DNS میزبان مقصد: ${err?.message || 'DNS lookup failed'}`,
    };
  }
}

/**
 * Performs an SSRF-safe and DNS-rebinding-safe HTTP/HTTPS GET request returning parsed JSON.
 * - Validates URL structure with `isSafeExternalUrl`.
 * - Resolves DNS once and verifies all returned IPs with `isPublicRoutableIp`.
 * - Pins the verified IP in the socket `lookup` callback so no second DNS resolution can rebind to 127.0.0.1 or 169.254.169.254.
 * - Never follows HTTP redirects (3xx responses are rejected).
 */
async function safeExternalFetchJson(
  rawUrl: string,
  options: {
    headers?: Record<string, string>;
    timeoutMs?: number;
    maxBytes?: number;
  } = {}
): Promise<{ ok: boolean; status: number; data?: any; error?: string }> {
  const urlCheck = isSafeExternalUrl(rawUrl);
  if (!urlCheck.valid || !urlCheck.url) {
    return { ok: false, status: 0, error: urlCheck.reason || 'Invalid external URL' };
  }

  const parsedUrl = urlCheck.url;
  const dnsCheck = await resolveAndValidatePublicHost(parsedUrl.hostname);
  if (!dnsCheck.ok || !dnsCheck.address || !dnsCheck.family) {
    return { ok: false, status: 0, error: dnsCheck.reason || 'DNS validation failed' };
  }

  const pinnedIp = dnsCheck.address;
  const pinnedFamily = dnsCheck.family;
  const timeoutMs = options.timeoutMs ?? 4500;
  const maxBytes = options.maxBytes ?? 256 * 1024;
  const isHttps = parsedUrl.protocol === 'https:';
  const requestModule = isHttps ? https : http;

  return new Promise(resolve => {
    let settled = false;
    const finish = (result: { ok: boolean; status: number; data?: any; error?: string }) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = requestModule.request(
      parsedUrl,
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'NETLeakGard-Auditor/2.0',
          ...(options.headers || {}),
        },
        timeout: timeoutMs,
        servername: parsedUrl.hostname.replace(/^\[|\]$/g, ''),
        lookup: (_hostname, _opts, cb) => {
          // Final guard against DNS rebinding: only connect to the pre-verified public IP
          if (!isPublicRoutableIp(pinnedIp)) {
            return cb(new Error('SSRF_PINNED_IP_REJECTED'), '', 4);
          }
          return cb(null, pinnedIp, pinnedFamily);
        },
      },
      res => {
        const statusCode = res.statusCode || 0;
        // Explicitly forbid HTTP redirects (3xx)
        if (statusCode >= 300 && statusCode < 400) {
          res.resume();
          return finish({
            ok: false,
            status: statusCode,
            error: `Redirect (${statusCode}) is forbidden for security reasons.`,
          });
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > maxBytes) {
            req.destroy(new Error('RESPONSE_TOO_LARGE'));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          if (settled) return;
          const bodyStr = Buffer.concat(chunks).toString('utf-8');
          if (statusCode < 200 || statusCode >= 300) {
            return finish({
              ok: false,
              status: statusCode,
              error: `HTTP ${statusCode}`,
            });
          }
          try {
            const parsedJson = JSON.parse(bodyStr);
            return finish({ ok: true, status: statusCode, data: parsedJson });
          } catch {
            return finish({ ok: false, status: statusCode, error: 'Invalid JSON response' });
          }
        });

        res.on('error', (err: any) => {
          finish({ ok: false, status: statusCode, error: err?.message || 'Stream error' });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error('REQUEST_TIMEOUT'));
      finish({ ok: false, status: 0, error: 'Request timeout' });
    });

    req.on('error', (err: any) => {
      finish({ ok: false, status: 0, error: err?.message || 'Request failed' });
    });

    req.end();
  });
}

// 1. Endpoint: Evidence-based Client & Server IP Inspection, GeoIP Estimation & Real Reputation Check
app.get('/api/ip-info', rateLimit(30, 60_000, 'ip-info'), async (req, res) => {
  const startedAt = new Date().toISOString();
  try {
    const {
      rawSocketIp,
      forwardedHeaderIp,
      proxyHeaderTrusted: trustProxy,
      serverObservedIp,
    } = extractVerifiedClientIpInfo(req);

    // Optional client-reported public IP (strictly validated with isPublicRoutableIp to prevent SSRF)
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

    // Primary GeoIP lookup: ipwho.is (SSRF & DNS-rebinding protected, redirects forbidden)
    try {
      const endpoint = targetLookupIp
        ? `https://ipwho.is/${encodeURIComponent(targetLookupIp)}`
        : 'https://ipwho.is/';
      const resp = await safeExternalFetchJson(endpoint, { timeoutMs: 4500 });
      if (resp.ok && resp.data) {
        const raw = resp.data;
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
        lookupErrors.push(`ipwho.is: ${resp.error || `HTTP ${resp.status}`}`);
      }
    } catch (e: any) {
      lookupErrors.push(`ipwho.is error: ${e?.message || 'timeout'}`);
    }

    // Secondary independent GeoIP lookup if primary failed: ipapi.co (SSRF & DNS-rebinding protected)
    if (!geoData) {
      try {
        const endpoint2 = targetLookupIp
          ? `https://ipapi.co/${encodeURIComponent(targetLookupIp)}/json/`
          : 'https://ipapi.co/json/';
        const resp2 = await safeExternalFetchJson(endpoint2, { timeoutMs: 4500 });
        if (resp2.ok && resp2.data) {
          const raw2 = resp2.data;
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
          lookupErrors.push(`ipapi.co: ${resp2.error || `HTTP ${resp2.status}`}`);
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
        const abuseResp = await safeExternalFetchJson(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(resolvedIp)}&maxAgeInDays=90`,
          {
            headers: {
              Key: abuseKey.trim(),
              Accept: 'application/json',
            },
            timeoutMs: 4000,
          }
        );
        if (abuseResp.ok && abuseResp.data) {
          const score = abuseResp.data?.data?.abuseConfidenceScore;
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

// 1.5 Endpoint: Configuration & Health Check (Zero secret exposure, never crashes on missing optional keys)
app.get('/api/health', (_req, res) => {
  const dnsLeakDomain = (process.env.DNS_LEAK_DOMAIN || '').trim();
  const collectorApiUrl = (process.env.DNS_COLLECTOR_API_URL || '').trim();
  const collectorToken = (process.env.DNS_COLLECTOR_API_TOKEN || '').trim();
  const missingDnsEnvVars: string[] = [];
  if (!dnsLeakDomain) missingDnsEnvVars.push('DNS_LEAK_DOMAIN');
  if (!collectorApiUrl) missingDnsEnvVars.push('DNS_COLLECTOR_API_URL');
  if (!collectorToken) missingDnsEnvVars.push('DNS_COLLECTOR_API_TOKEN');

  res.json({
    ok: true,
    timestamp: new Date().toISOString(),
    optionalIntegrations: {
      authoritativeDnsConfigured: missingDnsEnvVars.length === 0,
      missingDnsEnvVars,
      abuseIpDbConfigured: Boolean((process.env.ABUSEIPDB_API_KEY || '').trim()),
      googleSafeBrowsingConfigured: Boolean((process.env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim()),
      geminiConfigured: Boolean(getGeminiClient()),
    },
  });
});

// 2. Endpoint: Real Authoritative DNS Leak Session & Collector Query (Zero Fake Resolvers)
app.get('/api/dns-leak-probe', rateLimit(30, 60_000, 'dns-leak-probe'), async (req, res) => {
  const startedAt = new Date().toISOString();
  const runId =
    typeof req.query.runId === 'string' && isValidDnsRunId(req.query.runId)
      ? req.query.runId
      : crypto.randomUUID();

  const dnsLeakDomain = (process.env.DNS_LEAK_DOMAIN || '').trim();
  const collectorApiUrl = (process.env.DNS_COLLECTOR_API_URL || '').trim();
  const collectorToken = (process.env.DNS_COLLECTOR_API_TOKEN || '').trim();

  const missingEnvVars: string[] = [];
  if (!dnsLeakDomain) missingEnvVars.push('DNS_LEAK_DOMAIN');
  if (!collectorApiUrl) missingEnvVars.push('DNS_COLLECTOR_API_URL');
  if (!collectorToken) missingEnvVars.push('DNS_COLLECTOR_API_TOKEN');

  const authoritativeConfigured = missingEnvVars.length === 0;

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
        missingEnvVars,
        dnsLeakDomain: null,
        serverSystemResolvers: serverSystemDns,
        resolvers: [],
        messageFa:
          `وضعیت: پیکربندی نشده — متغیرهای محیطی (${missingEnvVars.join('، ')}) تنظیم نشده‌اند. بدون سرور Authoritative DNS اختصاصی، هیچ نتیجه‌ای به عنوان موفق یا امن جعل نمی‌شود.`,
      });
    }

    // When DNS_LEAK_DOMAIN, DNS_COLLECTOR_API_URL, and DNS_COLLECTOR_API_TOKEN are all configured:
    // Validate collectorApiUrl against SSRF & private/loopback targets
    const urlCheck = isSafeExternalUrl(collectorApiUrl);
    if (!urlCheck.valid || !urlCheck.url) {
      return res.status(400).json({
        success: false,
        runId,
        authoritativeConfigured: true,
        errorCode: 'UNSAFE_COLLECTOR_URL',
        error: `آدرس سرویس ثبت‌کنندهٔ DNS نامعتبر یا ناامن است: ${urlCheck.reason || 'Invalid URL'}`,
      });
    }

    const url = urlCheck.url;
    url.searchParams.set('runId', runId);

    // Also verify DNS resolution of collector host and execute anti-DNS-rebinding request
    const dnsHostCheck = await resolveAndValidatePublicHost(url.hostname);
    if (!dnsHostCheck.ok) {
      return res.status(400).json({
        success: false,
        runId,
        authoritativeConfigured: true,
        errorCode: 'UNSAFE_COLLECTOR_DNS_RESOLUTION',
        error: `خطای امنیتی در بررسی DNS سرویس ثبت‌کننده: ${dnsHostCheck.reason}`,
      });
    }

    const collectorResp = await safeExternalFetchJson(url.toString(), {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${collectorToken}`,
      },
      timeoutMs: 5000,
    });

    if (!collectorResp.ok) {
      const status = collectorResp.status || 502;
      return res.status(502).json({
        success: false,
        runId,
        authoritativeConfigured: true,
        errorCode: `COLLECTOR_HTTP_${status}`,
        error: `سرویس ثبت‌کنندهٔ Authoritative DNS پاسخ معتبری برنگرداند (${collectorResp.error || status}).`,
      });
    }

    const collectorData = collectorResp.data;
    const nowMs = Date.now();
    const seenCanonicalIps = new Set<string>();
    const observedResolvers: any[] = [];

    if (Array.isArray(collectorData?.resolvers)) {
      for (let idx = 0; idx < collectorData.resolvers.length; idx++) {
        const r = collectorData.resolvers[idx];
        if (!isValidDnsObservationRecord(r, runId, nowMs, dnsLeakDomain)) {
          continue;
        }
        const canonicalIp = canonicalizeIp(String(r.ip || r.primaryIp || ''));
        // Deduplicate by canonical IP so repeated queries (p1, p2, p3) from the same resolver are never counted as multiple witnesses
        if (!canonicalIp || seenCanonicalIps.has(canonicalIp)) {
          continue;
        }
        seenCanonicalIps.add(canonicalIp);

        const rawQname = typeof r.queryName === 'string' ? r.queryName : typeof r.qname === 'string' ? r.qname : '';
        const parsedQname = parseDnsLeakProbeQname(rawQname, dnsLeakDomain);
        if (!parsedQname.valid) {
          continue;
        }

        observedResolvers.push({
          id: String(r.id || `auth-${idx}`),
          name: String(r.name || r.isp || 'Observed Recursive Resolver'),
          primaryIp: canonicalIp,
          asn: r.asn ? String(r.asn) : undefined,
          isp: r.isp ? String(r.isp) : undefined,
          location: String(r.location || r.country || 'نامشخص'),
          countryCode: r.countryCode || r.country_code ? String(r.countryCode || r.country_code).toUpperCase() : undefined,
          runId,
          queryName: parsedQname.qname,
          observedAt: String(r.observedAt).trim(),
          status: String(r.status || 'مشاهده‌شده در Authoritative DNS'),
          responseTimeMs: typeof r.responseTimeMs === 'number' ? r.responseTimeMs : null,
          isEncryptedDoH: typeof r.isEncryptedDoH === 'boolean' ? r.isEncryptedDoH : null,
          observationMethod: 'authoritative_dns_log' as const,
        });
      }
    }

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
app.get('/api/ping', rateLimit(120, 60_000, 'ping'), (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.json({ pong: true, serverTimestamp: Date.now() });
});

app.get('/api/speed-test/chunk', rateLimit(20, 60_000, 'speed-chunk'), (req, res) => {
  // Bounded payload: default 512 KB, max 2 MB to prevent bandwidth exhaustion
  const requestedBytes = typeof req.query.bytes === 'string' ? parseInt(req.query.bytes, 10) : 512 * 1024;
  const chunkSize = Math.max(64 * 1024, Math.min(2 * 1024 * 1024, Number.isFinite(requestedBytes) ? requestedBytes : 512 * 1024));
  const buffer = Buffer.alloc(chunkSize, 0x78);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', chunkSize.toString());
  res.send(buffer);
});

// 3.5 Endpoint: Real TCP Port Exposure Probe against Verified Client Public IP (SSRF-safe)
const SENSITIVE_PORT_DEFINITIONS = COMMON_SENSITIVE_PORTS;

function probeSingleTcpPort(
  host: string,
  port: number,
  timeoutMs = 1200
): Promise<{ state: 'open' | 'closed' | 'filtered_timeout'; responseTimeMs: number | null }> {
  return new Promise(resolve => {
    const startMs = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const finalize = (state: 'open' | 'closed' | 'filtered_timeout', responseTimeMs: number | null) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // Ignore socket destroy error
      }
      resolve({ state, responseTimeMs });
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      finalize('open', Math.max(1, Date.now() - startMs));
    });

    socket.once('timeout', () => {
      finalize('filtered_timeout', null);
    });

    socket.once('error', (err: any) => {
      if (err && err.code === 'ECONNREFUSED') {
        finalize('closed', Math.max(1, Date.now() - startMs));
      } else {
        finalize('filtered_timeout', null);
      }
    });

    try {
      socket.connect(port, host);
    } catch {
      finalize('filtered_timeout', null);
    }
  });
}

app.get('/api/port-scan', rateLimit(15, 60_000, 'port-scan'), async (req, res) => {
  const startedAt = new Date().toISOString();
  try {
    // Explicitly reject any attempt to supply custom scan targets, hosts, ports, or redirect URLs via query params (SSRF prevention)
    const forbiddenOverrideParams = ['ip', 'host', 'target', 'port', 'ports', 'url', 'redirect', 'dest', 'address'];
    const attemptedOverrides = forbiddenOverrideParams.filter(key => req.query[key] !== undefined);
    if (attemptedOverrides.length > 0) {
      return res.status(400).json({
        success: false,
        startedAt,
        completedAt: new Date().toISOString(),
        errorCode: 'SSRF_TARGET_OVERRIDE_FORBIDDEN',
        error: `تعیین دستی آدرس هدف یا پورت از طریق پارامترهای درخواست (${attemptedOverrides.join(', ')}) به دلایل امنیتی (جلوگیری از SSRF) مسدود است. اسکن فقط روی سوکت عمومی تأییدشدهٔ کلاینت مجاز است.`,
      });
    }

    const {
      rawSocketIp,
      forwardedHeaderIp,
      canScanForwardedIp,
    } = extractVerifiedClientIpInfo(req);

    // Strictly determine verified client socket IP — NEVER scan arbitrary query-supplied or multi-hop spoofed XFF IPs (SSRF prevention)
    const candidateIp = canScanForwardedIp && forwardedHeaderIp ? forwardedHeaderIp : rawSocketIp;
    const isRoutablePublic = Boolean(candidateIp && isPublicRoutableIp(candidateIp));

    if (!candidateIp || !isRoutablePublic) {
      return res.json({
        success: true,
        startedAt,
        completedAt: new Date().toISOString(),
        targetIp: candidateIp,
        targetSource: 'unverifiable_local_socket',
        canScanFromServer: false,
        ports: SENSITIVE_PORT_DEFINITIONS.map(def => ({
          ...def,
          state: 'not_tested',
          responseTimeMs: null,
        })),
      });
    }

    const targetSource =
      canScanForwardedIp && forwardedHeaderIp ? 'trusted_proxy_header' : 'server_socket';

    const probeResults = await Promise.all(
      SENSITIVE_PORT_DEFINITIONS.map(async def => {
        const resProbe = await probeSingleTcpPort(candidateIp, def.port, 1200);
        return {
          ...def,
          state: resProbe.state,
          responseTimeMs: resProbe.responseTimeMs,
        };
      })
    );

    return res.json({
      success: true,
      startedAt,
      completedAt: new Date().toISOString(),
      targetIp: candidateIp,
      targetSource,
      canScanFromServer: true,
      ports: probeResults,
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      errorCode: 'PORT_SCAN_FAILED',
      error: `خطا در بررسی پورت‌ها: ${err?.message || 'Internal error'}`,
    });
  }
});

function buildRuleBasedAuditReport(networkData: any, fallbackSummaryFa: string) {
  const dnsStatusFa = formatTestStatusLabelFa(networkData?.dnsLeakStatus || 'NOT_CONFIGURED');
  const webRtcStatusFa = formatTestStatusLabelFa(networkData?.webRtcLeakStatus || 'INCONCLUSIVE');
  const portStatusFa = networkData?.portLeakStatus
    ? formatTestStatusLabelFa(networkData.portLeakStatus)
    : null;

  return {
    riskScore: null,
    statusLevel: 'نامشخص' as const,
    summaryFa: fallbackSummaryFa,
    detailedAnalysisFa: [
      networkData?.ip
        ? `آدرس IP عمومی مشاهده‌شده: ${networkData.ip} (${networkData.usageTypeFa || 'نامشخص'})`
        : 'آدرس IP عمومی به دلیل خطا قابل مشاهده نبود.',
      `وضعیت تست Authoritative DNS: ${dnsStatusFa}`,
      `وضعیت تست WebRTC: ${webRtcStatusFa}`,
      ...(portStatusFa ? [`وضعیت بررسی پورت‌های حساس روتر: ${portStatusFa}`] : []),
    ],
    threatsFoundFa: [],
    recommendationsFa: [
      'برای اجرای تست کامل Authoritative DNS، متغیرهای DNS_LEAK_DOMAIN، DNS_COLLECTOR_API_URL و DNS_COLLECTOR_API_TOKEN را در سرور پیکربندی کنید.',
      'توجه داشته باشید که تست‌های داخل مرورگر، وضعیت تمام ترافیک سطح سیستم‌عامل را اثبات نمی‌کنند.'
    ],
    aiAvailable: false,
    generatedAt: new Date().toISOString(),
  };
}

// 4. Endpoint: Gemini AI Security & Privacy Audit (in Persian, strictly grounded in real evidence)
app.post('/api/gemini-audit', rateLimit(15, 60_000, 'gemini-audit'), async (req, res) => {
  const { networkData } = req.body || {};

  if (!networkData || typeof networkData !== 'object' || Array.isArray(networkData)) {
    return res.status(400).json({
      success: false,
      errorCode: 'INVALID_AUDIT_PAYLOAD',
      error: 'داده‌های ورودی برای تحلیل ارسال نشده یا نامعتبر است.'
    });
  }

  const gemini = getGeminiClient();
  if (!gemini) {
    return res.json({
      success: true,
      aiAvailable: false,
      audit: buildRuleBasedAuditReport(
        networkData,
        'کلید GEMINI_API_KEY در محیط سرور تنظیم نشده است. گزارش زیر صرفاً بر اساس قواعد قطعی و شواهد جمع‌آوری‌شده از تست‌ها تولید شده است.'
      ),
    });
  }

  try {
    const prompt = `
شما یک ممیز ارشد امنیت شبکه هستید. بر اساس داده‌های واقعی زیر (بدون هیچ‌گونه حدس غیرمستند یا ادعای امنیت صددرصدی)، یک گزارش فنی به زبان فارسی به صورت JSON تولید کنید:
${JSON.stringify(networkData, null, 2)}

قوانین مهم:
- اگر تست DNS در وضعیت NOT_CONFIGURED (پیکربندی نشده) یا INCONCLUSIVE (نامشخص) است، صریحاً اعلام کنید که بدون Authoritative DNS نمی‌توان عدم نشت DNS را اثبات کرد.
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

    // Enforce a strict 4500ms server-side timeout so high-demand 503 retries never cause client net::ERR_ABORTED
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('GEMINI_TIMEOUT')), 4500);
    });

    const response = await Promise.race([
      gemini.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
        },
      }),
      timeoutPromise,
    ]);

    const responseText = response.text || '';
    const parsedData = JSON.parse(responseText);
    const schemaCheck = validateAiAuditPayload(parsedData);

    if (!schemaCheck.valid || !schemaCheck.audit) {
      return res.status(200).json({
        success: true,
        aiAvailable: false,
        audit: buildRuleBasedAuditReport(
          networkData,
          'خروجی سرویس هوش مصنوعی با ساختار استاندارد مطابقت نداشت؛ گزارش زیر بر اساس قواعد قطعی و شواهد واقعی تست‌ها تولید شده است.'
        ),
      });
    }

    return res.json({
      success: true,
      aiAvailable: true,
      audit: {
        ...schemaCheck.audit,
        aiAvailable: true,
        generatedAt: new Date().toISOString(),
      }
    });
  } catch {
    // Graceful, immediate fallback to deterministic rule-based report on 503 / timeout / quota errors
    return res.status(200).json({
      success: true,
      aiAvailable: false,
      audit: buildRuleBasedAuditReport(
        networkData,
        'سرویس تحلیل ابری در حال حاضر پاسخگو نبود؛ گزارش زیر مستقیماً بر اساس قواعد قطعی و شواهد واقعی تست‌های اجراشده استخراج شده است.'
      ),
    });
  }
});

// Setup Vite middleware in dev mode
async function setupServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'custom'
    });
    app.use(vite.middlewares);

    app.use('*', async (req, res, next) => {
      const url = req.originalUrl;
      try {
        const indexPath = path.resolve(process.cwd(), 'index.html');
        const rawHtml = fs.readFileSync(indexPath, 'utf-8');
        const template = await vite.transformIndexHtml(url, rawHtml);
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
