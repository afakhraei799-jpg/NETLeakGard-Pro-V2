/**
 * Cloudflare Worker & Static Assets Edge Runtime for NETLeakGuard Pro V2 (Zero-Cost Tier Compatible)
 *
 * CRITICAL ARCHITECTURAL & SECURITY NOTES:
 * 1. Why HTTP Workers Alone Cannot Replace UDP/53 Authoritative DNS:
 *    - A standard Cloudflare Worker (`fetch` handler) only receives HTTP/HTTPS requests on ports 80/443.
 *    - In an HTTP request, `CF-Connecting-IP` is the client browser's HTTP egress IP, NOT the IP of the
 *      Recursive DNS Resolver that queried the domain on UDP/TCP port 53.
 *    - Cloudflare's free authoritative DNS does not expose real-time recursive resolver logs (DNS Logpush
 *      is Enterprise-only), and Cloudflare Workers cannot bind raw inbound UDP/53 sockets as an NS server.
 *    - Therefore, `CF-Connecting-IP` from an HTTP request MUST NEVER be recorded as a DNS resolver IP.
 *
 * 2. How Real Authoritative DNS Leak Detection Works with This Worker:
 *    - An external Authoritative UDP/53 responder (such as `cloudflare/authoritative-dns-udp53.mjs` running
 *      on any free-tier UDP/53 host whose IP is set as the `NS` record for a dedicated subdomain like
 *      `leak.example.com`) receives the real UDP/53 query for `<label>.<runId>.<DNS_LEAK_DOMAIN>`.
 *    - That UDP/53 responder extracts the packet's source IP (the true Recursive DNS Resolver IP) and sends
 *      an authenticated `POST /api/dns-collector/ingest` request (with `Authorization: Bearer <DNS_COLLECTOR_API_TOKEN>`)
 *      to this Cloudflare Worker.
 *    - This Worker validates the token (supporting zero-downtime token rotation), `runId`, canonical `qname`
 *      (`p<N>.<runId>.<DNS_LEAK_DOMAIN>`), timestamp freshness window (`<= 5 min`), and public IP, and stores
 *      the deduplicated record in Cloudflare KV (`DNS_LOGS_KV`) under `dns:<runId>` with a 300-second TTL.
 *    - When the frontend calls `GET /api/dns-leak-probe?runId=<runId>`, this Worker reads `dns:<runId>` from KV
 *      and returns ONLY verified, non-expired `authoritative_dns_log` entries strictly matching that `runId` and `qname`.
 *
 * 3. KV Retention, Polling vs Cross-Run Isolation, and Consistency Limitations:
 *    - Cross-run reuse is strictly blocked because every record is bound to both its unique `runId` and `qname`
 *      (`p<N>.<runId>.<DNS_LEAK_DOMAIN>`), and KV keys are isolated by `dns:<runId>`.
 *    - To support the client's bounded sequential polling (up to 3 attempts, 400ms apart while `p1`..`p3` UDP packets arrive),
 *      KV records are retained until their 300-second TTL expires rather than deleted on first read; therefore,
 *      single-use (burn-after-reading) deletion for repeated reads of the *same* `runId` within the 5-minute TTL is NOT claimed.
 *    - Cloudflare Workers KV is an eventually consistent store across global colos and does not provide atomic
 *      read-modify-write (`get` + `put`) transactions; concurrent UDP/53 ingest calls for the same `runId` can
 *      experience write races unless backed by Durable Objects.
 *
 * 4. Default Safe State («پیکربندی نشده» / NOT_CONFIGURED):
 *    - Until `DNS_LEAK_DOMAIN`, `DNS_LOGS_KV`, `DNS_COLLECTOR_API_TOKEN`, and `DNS_UDP53_VERIFIED="true"`
 *      are all configured and verified, `/api/dns-leak-probe` returns `authoritativeConfigured: false`
 *      so the application strictly displays «پیکربندی نشده» (`NOT_CONFIGURED`).
 */

import {
  COMMON_SENSITIVE_PORTS,
  canonicalizeIp,
  isGloballyRoutablePublicIp,
  isValidDnsObservationRecord,
  isValidDnsRunId,
  parseDnsLeakProbeQname,
  validateAiAuditPayload
} from '../src/utils/networkEvaluator';

export interface KvNamespaceLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface AssetsFetcherLike {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  /** Dedicated subdomain delegated via NS record to the UDP/53 Authoritative Responder (e.g. "leak.example.com") */
  DNS_LEAK_DOMAIN?: string;
  /** Must be explicitly set to "true" ONLY after the UDP/53 Authoritative DNS responder is verified */
  DNS_UDP53_VERIFIED?: string;
  /** Primary Secret Bearer token for authenticating UDP/53 ingest and collector log queries (set via `wrangler secret put`) */
  DNS_COLLECTOR_API_TOKEN?: string;
  /** Optional previous token to allow zero-downtime secret rotation (`wrangler secret put DNS_COLLECTOR_API_TOKEN_PREVIOUS`) */
  DNS_COLLECTOR_API_TOKEN_PREVIOUS?: string;
  /** Optional separate ingest token; falls back to DNS_COLLECTOR_API_TOKEN if omitted */
  DNS_COLLECTOR_INGEST_TOKEN?: string;
  /** Optional server-side Gemini API key (set via `wrangler secret put GEMINI_API_KEY`) */
  GEMINI_API_KEY?: string;
  /** Optional AbuseIPDB key (set via `wrangler secret put ABUSEIPDB_API_KEY`) */
  ABUSEIPDB_API_KEY?: string;
  /** Cloudflare KV Namespace binding for short-lived DNS leak test logs */
  DNS_LOGS_KV?: KvNamespaceLike;
  /** Optional Cloudflare Workers Static Assets binding for serving the Vite `/dist` frontend */
  ASSETS?: AssetsFetcherLike;
}

const MAX_OBSERVATION_AGE_MS = 5 * 60 * 1000; // 5 minutes session freshness window
const MAX_FUTURE_SKEW_MS = 60 * 1000; // 1 minute clock skew tolerance
const MAX_JSON_BODY_BYTES = 32 * 1024; // 32 KB max request body size

// Bounded per-isolate rate limiter to protect Cloudflare Free Tier quotas
const EDGE_RATE_LIMIT_MAX_ENTRIES = 2000;
const edgeRateLimitMap = new Map<string, { count: number; resetAt: number }>();

function checkEdgeRateLimit(clientKey: string, bucket: string, maxRequests: number, windowMs: number): {
  allowed: boolean;
  retryAfterSec: number;
} {
  const now = Date.now();
  const key = `${bucket}:${clientKey}`;
  const existing = edgeRateLimitMap.get(key);
  if (!existing || now > existing.resetAt) {
    if (edgeRateLimitMap.size >= EDGE_RATE_LIMIT_MAX_ENTRIES) {
      for (const [k, v] of edgeRateLimitMap.entries()) {
        if (now > v.resetAt) edgeRateLimitMap.delete(k);
      }
      if (edgeRateLimitMap.size >= EDGE_RATE_LIMIT_MAX_ENTRIES) {
        const oldest = edgeRateLimitMap.keys().next().value;
        if (oldest) edgeRateLimitMap.delete(oldest);
      }
    }
    edgeRateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSec: 0 };
  }
  existing.count += 1;
  if (existing.count > maxRequests) {
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
    };
  }
  return { allowed: true, retryAfterSec: 0 };
}

/**
 * Constant-time string comparison to prevent timing side-channel attacks on Bearer tokens.
 * Never logs or returns secret values.
 */
export function timingSafeEqualStrings(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const bytesA = enc.encode(a);
  const bytesB = enc.encode(b);
  if (bytesA.length === 0 || bytesA.length !== bytesB.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < bytesA.length; i++) {
    diff |= bytesA[i] ^ bytesB[i];
  }
  return diff === 0;
}

/**
 * Verifies a Bearer token against active and optional previous (rotation) tokens using constant-time comparison.
 */
export function verifyBearerTokenWithRotation(
  providedToken: string | null,
  allowedTokens: Array<string | undefined | null>
): boolean {
  if (!providedToken) return false;
  const cleanCandidates = allowedTokens
    .map(t => (typeof t === 'string' ? t.trim() : ''))
    .filter(t => t.length > 0);
  if (cleanCandidates.length === 0) return false;

  let matched = false;
  for (const candidate of cleanCandidates) {
    if (timingSafeEqualStrings(providedToken, candidate)) {
      matched = true;
    }
  }
  return matched;
}

function extractBearerToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization') || request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice('Bearer '.length).trim();
  return token.length > 0 ? token : null;
}

async function readBoundedJsonBody(
  request: Request,
  maxBytes = MAX_JSON_BODY_BYTES
): Promise<{ ok: true; data: any } | { ok: false; status: number; errorCode: string; error: string }> {
  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader) {
    const contentLength = parseInt(contentLengthHeader, 10);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      return {
        ok: false,
        status: 413,
        errorCode: 'PAYLOAD_TOO_LARGE',
        error: `حجم بدنهٔ درخواست بیش از حد مجاز (${maxBytes} بایت) است.`,
      };
    }
  }

  try {
    // If request has a readable stream body, read in chunks up to maxBytes to prevent memory exhaustion
    if (request.body && typeof (request.body as any).getReader === 'function') {
      const reader = (request.body as ReadableStream<Uint8Array>).getReader();
      const chunks: Uint8Array[] = [];
      let totalBytes = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            await reader.cancel();
            return {
              ok: false,
              status: 413,
              errorCode: 'PAYLOAD_TOO_LARGE',
              error: `حجم بدنهٔ درخواست بیش از حد مجاز (${maxBytes} بایت) است.`,
            };
          }
          chunks.push(value);
        }
      }

      if (chunks.length === 0) {
        return { ok: true, data: {} };
      }

      const combined = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const rawText = new TextDecoder('utf-8').decode(combined);
      if (!rawText.trim()) {
        return { ok: true, data: {} };
      }
      return { ok: true, data: JSON.parse(rawText) };
    }

    // Fallback if request.body stream is not available
    const rawText = await request.text();
    if (new TextEncoder().encode(rawText).byteLength > maxBytes) {
      return {
        ok: false,
        status: 413,
        errorCode: 'PAYLOAD_TOO_LARGE',
        error: `حجم بدنهٔ درخواست بیش از حد مجاز (${maxBytes} بایت) است.`,
      };
    }
    if (!rawText.trim()) {
      return { ok: true, data: {} };
    }
    return { ok: true, data: JSON.parse(rawText) };
  } catch {
    return {
      ok: false,
      status: 400,
      errorCode: 'INVALID_JSON',
      error: 'ساختار JSON ارسالی نامعتبر است.',
    };
  }
}

function isAuthoritativeDnsFullyConfigured(env: Env): {
  configured: boolean;
  missingVars: string[];
  dnsLeakDomain: string | null;
} {
  const domain = (env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const token = (
    env.DNS_COLLECTOR_API_TOKEN ||
    env.DNS_COLLECTOR_INGEST_TOKEN ||
    env.DNS_COLLECTOR_API_TOKEN_PREVIOUS ||
    ''
  ).trim();
  const udp53Verified = (env.DNS_UDP53_VERIFIED || '').trim().toLowerCase() === 'true';
  const hasKv = Boolean(env.DNS_LOGS_KV && typeof env.DNS_LOGS_KV.get === 'function');

  const missingVars: string[] = [];
  if (!domain) missingVars.push('DNS_LEAK_DOMAIN');
  if (!hasKv) missingVars.push('DNS_LOGS_KV');
  if (!token) missingVars.push('DNS_COLLECTOR_API_TOKEN');
  if (!udp53Verified) missingVars.push('DNS_UDP53_VERIFIED=true');

  return {
    configured: missingVars.length === 0,
    missingVars,
    dnsLeakDomain: domain || null,
  };
}

function isFreshObservationTimestamp(isoTimestamp: unknown, nowMs = Date.now()): boolean {
  if (typeof isoTimestamp !== 'string' || !isoTimestamp.trim()) return false;
  const parsed = Date.parse(isoTimestamp);
  if (!Number.isFinite(parsed)) return false;
  const ageMs = nowMs - parsed;
  return ageMs <= MAX_OBSERVATION_AGE_MS && ageMs >= -MAX_FUTURE_SKEW_MS;
}

function sanitizeValidatedResolversForRun(
  rawRecords: unknown,
  expectedRunId: string,
  expectedDomain?: string | null
) {
  if (!Array.isArray(rawRecords) || !isValidDnsRunId(expectedRunId)) return [];
  const nowMs = Date.now();
  const seenIps = new Set<string>();
  const validResolvers: Array<{
    id: string;
    name: string;
    primaryIp: string;
    asn?: string;
    isp?: string;
    location: string;
    countryCode?: string;
    runId: string;
    queryName: string;
    observedAt: string;
    status: string;
    responseTimeMs: number | null;
    isEncryptedDoH: boolean | null;
    observationMethod: 'authoritative_dns_log';
  }> = [];

  for (let idx = 0; idx < rawRecords.length; idx++) {
    const item = rawRecords[idx] as Record<string, unknown> | null;
    if (!item || typeof item !== 'object') continue;

    // Strict validation using shared isValidDnsObservationRecord (enforces runId, QNAME p<N>.<runId>.<domain>, timestamp, and public IP)
    if (!isValidDnsObservationRecord(item, expectedRunId, nowMs, expectedDomain)) {
      continue;
    }

    const rawIp = typeof item.primaryIp === 'string' ? item.primaryIp : typeof item.ip === 'string' ? item.ip : '';
    const canonicalIp = canonicalizeIp(rawIp);
    // Deduplicate by canonical primaryIp so repeated UDP queries (p1, p2, p3 or retries) from the same resolver are never counted as multiple witnesses
    if (!canonicalIp || seenIps.has(canonicalIp)) continue;
    seenIps.add(canonicalIp);

    const rawQname =
      typeof item.queryName === 'string'
        ? item.queryName
        : typeof item.qname === 'string'
          ? item.qname
          : '';
    const parsedQname = parseDnsLeakProbeQname(rawQname, expectedDomain);
    if (!parsedQname.valid) continue;

    validResolvers.push({
      id: typeof item.id === 'string' && item.id ? item.id : `auth-${expectedRunId.slice(0, 8)}-${idx}`,
      name:
        typeof item.name === 'string' && item.name.trim()
          ? item.name.trim()
          : typeof item.isp === 'string' && item.isp.trim()
            ? item.isp.trim()
            : 'Observed Recursive Resolver',
      primaryIp: canonicalIp,
      asn: typeof item.asn === 'string' && item.asn.trim() ? item.asn.trim() : undefined,
      isp: typeof item.isp === 'string' && item.isp.trim() ? item.isp.trim() : undefined,
      location:
        typeof item.location === 'string' && item.location.trim()
          ? item.location.trim()
          : typeof item.country === 'string' && item.country.trim()
            ? item.country.trim()
            : 'نامشخص',
      countryCode:
        typeof item.countryCode === 'string' && item.countryCode.trim()
          ? item.countryCode.trim().toUpperCase()
          : undefined,
      runId: expectedRunId,
      queryName: parsedQname.qname,
      observedAt: String(item.observedAt).trim(),
      status: 'مشاهده‌شده در Authoritative DNS (UDP/53)',
      responseTimeMs: typeof item.responseTimeMs === 'number' && Number.isFinite(item.responseTimeMs) ? item.responseTimeMs : null,
      isEncryptedDoH: typeof item.isEncryptedDoH === 'boolean' ? item.isEncryptedDoH : null,
      observationMethod: 'authoritative_dns_log',
    });
  }

  return validResolvers;
}

function buildEdgeRuleBasedAuditReport(networkState: any) {
  const overallStatus = networkState?.overallStatus || 'INCONCLUSIVE';
  const detailedAnalysisFa: string[] = [];
  const threatsFoundFa: string[] = [];
  const recommendationsFa: string[] = [];

  if (overallStatus === 'LEAK_DETECTED') {
    threatsFoundFa.push('شواهد فنی نشت در یکی از لایه‌های شبکه (IP، WebRTC یا DNS) ثبت شده است.');
    detailedAnalysisFa.push('ناهماهنگی میان منابع شبکه یا افشای آدرس خارج از تونل مشاهده گردید.');
    recommendationsFa.push('تنظیمات Kill Switch، مسیریابی تمام ترافیک (Full-Tunnel) و مسدودسازی WebRTC را در کلاینت VPN بررسی کنید.');
  } else if (overallStatus === 'PASS') {
    detailedAnalysisFa.push('در تست‌های اجراشده، ناهماهنگی آشکاری میان آدرس‌های مشاهده‌شده ثبت نشد.');
    recommendationsFa.push('توجه داشته باشید که تست‌های مبتنی بر مرورگر فقط ترافیک قابل مشاهده از محیط مرورگر را می‌سنجند.');
  } else {
    detailedAnalysisFa.push(
      'برخی تست‌های پایه به دلیل عدم پیکربندی زیرساخت (مانند Authoritative DNS) یا محدودیت شبکه در وضعیت «نامشخص» یا «پیکربندی نشده» قرار دارند.'
    );
    recommendationsFa.push(
      'عدم مشاهدهٔ نشت در تست ناقص به معنای امن بودن اتصال نیست؛ برای تست کامل DNS نیازمند اتصال کلکتور Authoritative UDP/53 هستید.'
    );
  }

  const candidate = {
    riskScore:
      overallStatus === 'LEAK_DETECTED'
        ? 85
        : overallStatus === 'WARNING'
          ? 45
          : overallStatus === 'PASS'
            ? 10
            : null,
    statusLevel:
      overallStatus === 'LEAK_DETECTED'
        ? ('بحرانی' as const)
        : overallStatus === 'WARNING'
          ? ('هشدار' as const)
          : overallStatus === 'PASS'
            ? ('امن' as const)
            : ('نامشخص' as const),
    summaryFa:
      overallStatus === 'LEAK_DETECTED'
        ? 'هشدار امنیتی: ناهماهنگی یا نشت شبکه در شواهد فنی مشاهده شد.'
        : overallStatus === 'PASS'
          ? 'تست‌های پایه بدون ثبت شواهد نشت تکمیل شدند (با در نظر گرفتن محدودیت‌های ذاتی مرورگر).'
          : 'نتیجهٔ کلی قطعی نیست؛ یک یا چند تست الزامی نیازمند پیکربندی یا شواهد کامل‌تر هستند.',
    detailedAnalysisFa,
    threatsFoundFa,
    recommendationsFa,
  };

  const validated = validateAiAuditPayload(candidate);
  return validated.valid && validated.audit ? validated.audit : candidate;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const securityAndCorsHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Permitted-Cross-Domain-Policies': 'none',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: securityAndCorsHeaders });
    }

    const clientRateKey = canonicalizeIp(request.headers.get('CF-Connecting-IP')) || 'edge-anon';

    // 1. Health & Configuration Status Endpoint (Never exposes secret tokens)
    if (url.pathname === '/api/health' && request.method === 'GET') {
      const dnsStatus = isAuthoritativeDnsFullyConfigured(env);
      return Response.json(
        {
          ok: true,
          runtime: 'cloudflare-workers',
          timestamp: new Date().toISOString(),
          optionalIntegrations: {
            authoritativeDnsConfigured: dnsStatus.configured,
            missingDnsEnvVars: dnsStatus.missingVars,
            tokenRotationEnabled: Boolean((env.DNS_COLLECTOR_API_TOKEN_PREVIOUS || '').trim()),
            abuseIpDbConfigured: Boolean((env.ABUSEIPDB_API_KEY || '').trim()),
            googleSafeBrowsingConfigured: false,
            geminiConfigured: Boolean((env.GEMINI_API_KEY || '').trim()),
          },
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 2. HTTP RTT Latency Probe
    if (url.pathname === '/api/ping' && request.method === 'GET') {
      return Response.json(
        { pong: true, serverTimestamp: Date.now() },
        { headers: securityAndCorsHeaders }
      );
    }

    // 3. Bounded Speed Test Payload Chunk (64 KB to 1 MB)
    if (url.pathname === '/api/speed-test/chunk' && request.method === 'GET') {
      const rate = checkEdgeRateLimit(clientRateKey, 'speed-chunk', 25, 60_000);
      if (!rate.allowed) {
        return Response.json(
          { success: false, errorCode: 'RATE_LIMIT_EXCEEDED', error: 'تعداد درخواست‌های تست سرعت بیش از حد مجاز است.' },
          { status: 429, headers: { ...securityAndCorsHeaders, 'Retry-After': String(rate.retryAfterSec) } }
        );
      }
      const requested = parseInt(url.searchParams.get('bytes') || '524288', 10);
      const size = Math.max(65536, Math.min(1048576, Number.isFinite(requested) ? requested : 524288));
      const payload = new Uint8Array(size);
      return new Response(payload, {
        headers: {
          ...securityAndCorsHeaders,
          'Content-Type': 'application/octet-stream',
          'Content-Length': String(size),
        },
      });
    }

    // 4. Cloudflare Edge Verified IP & ASN Inspection
    if (url.pathname === '/api/ip-info' && request.method === 'GET') {
      const rate = checkEdgeRateLimit(clientRateKey, 'ip-info', 40, 60_000);
      if (!rate.allowed) {
        return Response.json(
          { success: false, errorCode: 'RATE_LIMIT_EXCEEDED', error: 'تعداد درخواست‌ها بیش از حد مجاز است.' },
          { status: 429, headers: { ...securityAndCorsHeaders, 'Retry-After': String(rate.retryAfterSec) } }
        );
      }

      const cf = (request as any).cf || {};
      const rawCfIp = request.headers.get('CF-Connecting-IP') || '';
      const clientIp = canonicalizeIp(rawCfIp);
      const isPublic = clientIp ? isGloballyRoutablePublicIp(clientIp) : false;
      const now = new Date().toISOString();

      const rawQueryClientIp = url.searchParams.get('clientIp') || '';
      const queryClientIp = canonicalizeIp(rawQueryClientIp);

      const ispText = typeof cf.asOrganization === 'string' && cf.asOrganization.trim() ? cf.asOrganization.trim() : null;
      const asnText = cf.asn ? `AS${cf.asn}` : null;
      const hostingKeywords = [
        'datacenter', 'hosting', 'cloud', 'digitalocean', 'hetzner', 'linode',
        'aws', 'amazon', 'azure', 'google cloud', 'ovh', 'contabo', 'vultr', 'm247',
        'choopa', 'leaseweb', 'akamai', 'cloudflare', 'fastly', 'datapacket', 'hostinger'
      ];
      const ispLower = (ispText || '').toLowerCase();
      const hasGeoMetadata = Boolean(ispText || asnText);
      const isHostingProbable = hasGeoMetadata
        ? hostingKeywords.some(k => ispLower.includes(k))
        : null;

      const latNum = cf.latitude !== undefined && cf.latitude !== null ? Number(cf.latitude) : null;
      const lonNum = cf.longitude !== undefined && cf.longitude !== null ? Number(cf.longitude) : null;
      const validLat = latNum !== null && Number.isFinite(latNum) && latNum >= -90 && latNum <= 90 ? latNum : null;
      const validLon = lonNum !== null && Number.isFinite(lonNum) && lonNum >= -180 && lonNum <= 180 ? lonNum : null;

      return Response.json(
        {
          success: Boolean(clientIp && isPublic),
          data: {
            status: clientIp && isPublic ? (hasGeoMetadata ? 'PASS' : 'INCONCLUSIVE') : 'ERROR',
            testName: 'Cloudflare Edge IP Inspection',
            startedAt: now,
            completedAt: now,
            observations: clientIp
              ? [`آدرس IP تاییدشده توسط هدر Cloudflare Edge: ${clientIp}`]
              : ['هدر CF-Connecting-IP یافت نشد.'],
            evidence: {
              cfConnectingIp: clientIp,
              asn: asnText,
              asOrganization: ispText,
              colo: cf.colo || null,
            },
            limitations: [
              'موقعیت جغرافیایی بر اساس پایگاه دادهٔ Edge کلادفلر تخمین زده شده است و موقعیت دقیق GPS نیست.'
            ],
            errorCode: clientIp && isPublic ? null : 'MISSING_CF_IP',
            source: 'Cloudflare Edge (request.cf)',
            confidence: clientIp && isPublic ? 'high' : 'none',
            ip: clientIp,
            clientObservedIp: queryClientIp,
            serverObservedIp: clientIp,
            serverSocketIp: clientIp,
            forwardedHeaderIp: clientIp,
            proxyHeaderTrusted: true,
            ipSources: [],
            ipMismatchDetected: false,
            version: clientIp?.includes(':') ? 'IPv6' : 'IPv4',
            countryName: cf.country || null,
            countryCode: cf.country || null,
            city: cf.city || null,
            region: cf.region || null,
            isp: ispText,
            asn: asnText,
            org: ispText,
            lat: validLat,
            lon: validLon,
            timezone: cf.timezone || null,
            isGeoEstimated: true,
            usageType: isHostingProbable === null ? 'Unknown' : isHostingProbable ? 'Datacenter' : 'Residential',
            usageTypeFa:
              isHostingProbable === null
                ? 'نامشخص (عدم دسترسی به متادیتای ASN)'
                : isHostingProbable
                  ? 'احتمالاً مرکز داده / هاستینگ (بر پایهٔ نام ASN)'
                  : 'احتمالاً ISP مسکونی / تجاری (بدون نشانهٔ دیتاسنتر در نام ASN)',
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
            fraudRiskScore: null,
            riskFactorsFa: [
              'بررسی فهرست‌های سیاه (Blacklist) نیازمند کلید API اختصاصی است؛ هیچ وضعیت جعلی «پاک» تولید نمی‌شود.'
            ],
            fraudStatusFa: 'بررسی‌نشده (کلید API پایگاه‌های Blacklist تنظیم نشده است)',
            fraudStatusEn: 'Unverified (Blacklist API keys not configured)',
            blacklistDetails: {
              googleSafeBrowsingStatus: 'not_configured',
              spamhausDnsblStatus: 'not_configured',
              abuseIpDbStatus: 'not_configured',
              abuseConfidenceScore: null,
              isGoogleFlagged: null,
              isSpamhausFlagged: null,
              isAbuseIpFlagged: null,
              verifiedSourcesCount: 0,
              threatCategoryFa: 'عدم پیکربندی کلید API سرویس‌های Blacklist (بدون ادعای پاک بودن)',
              threatCategoryEn: 'Blacklist APIs Not Configured',
            },
          },
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 5. Authenticated Ingest Endpoint for UDP/53 Authoritative DNS Forwarder
    //    Receives real recursive resolver source IPs observed on UDP/TCP port 53 and stores them in KV per runId.
    if (url.pathname === '/api/dns-collector/ingest' && request.method === 'POST') {
      const rate = checkEdgeRateLimit(clientRateKey, 'dns-ingest', 60, 60_000);
      if (!rate.allowed) {
        return Response.json(
          { success: false, errorCode: 'RATE_LIMIT_EXCEEDED', error: 'تعداد درخواست‌های ثبت لاگ بیش از حد مجاز است.' },
          { status: 429, headers: { ...securityAndCorsHeaders, 'Retry-After': String(rate.retryAfterSec) } }
        );
      }

      const primaryToken = (env.DNS_COLLECTOR_INGEST_TOKEN || env.DNS_COLLECTOR_API_TOKEN || '').trim();
      const previousToken = (env.DNS_COLLECTOR_API_TOKEN_PREVIOUS || '').trim();
      if ((!primaryToken && !previousToken) || !env.DNS_LOGS_KV) {
        return Response.json(
          {
            success: false,
            errorCode: 'COLLECTOR_NOT_CONFIGURED',
            error: 'سرویس ذخیره‌سازی لاگ DNS (DNS_LOGS_KV یا توکن احراز هویت) در Cloudflare Worker پیکربندی نشده است.',
          },
          { status: 503, headers: securityAndCorsHeaders }
        );
      }

      const providedToken = extractBearerToken(request);
      if (!verifyBearerTokenWithRotation(providedToken, [primaryToken, previousToken])) {
        return Response.json(
          {
            success: false,
            errorCode: 'UNAUTHORIZED',
            error: 'توکن احراز هویت کلکتور DNS نامعتبر است.',
          },
          { status: 401, headers: securityAndCorsHeaders }
        );
      }

      const parsedBody = await readBoundedJsonBody(request, MAX_JSON_BODY_BYTES);
      if (!parsedBody.ok) {
        return Response.json(
          { success: false, errorCode: parsedBody.errorCode, error: parsedBody.error },
          { status: parsedBody.status, headers: securityAndCorsHeaders }
        );
      }
      const body = parsedBody.data;

      const runId = typeof body?.runId === 'string' ? body.runId.trim() : '';
      if (!isValidDnsRunId(runId)) {
        return Response.json(
          { success: false, errorCode: 'INVALID_RUN_ID', error: 'شناسهٔ نشست (runId) نامعتبر است.' },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      const rawResolverIp = typeof body?.resolverIp === 'string' ? body.resolverIp : typeof body?.ip === 'string' ? body.ip : '';
      const canonicalResolverIp = canonicalizeIp(rawResolverIp);
      if (!canonicalResolverIp || !isGloballyRoutablePublicIp(canonicalResolverIp)) {
        return Response.json(
          {
            success: false,
            errorCode: 'INVALID_RESOLVER_IP',
            error: 'آدرس IP سرور Resolver باید یک آدرس عمومی و قابل مسیریابی معتبر باشد.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      // Timestamp freshness validation: observedAt is strictly mandatory
      if (typeof body?.observedAt !== 'string' || !body.observedAt.trim()) {
        return Response.json(
          {
            success: false,
            errorCode: 'MISSING_OBSERVED_AT',
            error: 'برچسب زمانی مشاهدهٔ رویداد (observedAt) الزامی است.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      const nowMs = Date.now();
      if (!isFreshObservationTimestamp(body.observedAt, nowMs)) {
        return Response.json(
          {
            success: false,
            errorCode: 'STALE_OR_FUTURE_TIMESTAMP',
            error: 'زمان مشاهدهٔ رویداد (observedAt) منقضی‌شده، قدیمی یا خارج از بازهٔ ۵ دقیقه‌ای مجاز نشست است.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }
      const finalObservedAt = String(body.observedAt).trim();

      // Mandatory canonical QNAME (`p<N>.<runId>.<domain>`) correlation with runId and configured DNS_LEAK_DOMAIN
      const rawQname = typeof body?.qname === 'string' ? body.qname.trim() : '';
      if (!rawQname) {
        return Response.json(
          {
            success: false,
            errorCode: 'MISSING_QNAME',
            error: 'نام دامنهٔ استعلام‌شده (qname) در قالب p<N>.<runId>.<domain> الزامی است.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      const configuredDomain = (env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
      const parsedQname = parseDnsLeakProbeQname(rawQname, configuredDomain || null);
      if (!parsedQname.valid) {
        if (parsedQname.errorCode === 'QNAME_DOMAIN_MISMATCH') {
          return Response.json(
            {
              success: false,
              errorCode: 'QNAME_DOMAIN_MISMATCH',
              error: 'نام دامنهٔ استعلام‌شده (qname) متعلق به دامنهٔ مجاز تست DNS نیست.',
            },
            { status: 400, headers: securityAndCorsHeaders }
          );
        }
        return Response.json(
          {
            success: false,
            errorCode: 'INVALID_QNAME_FORMAT',
            error: 'قالب نام دامنهٔ استعلام‌شده (qname) نامعتبر است؛ قالب مجاز p<N>.<runId>.<domain> است.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      if (parsedQname.runId !== runId.toLowerCase()) {
        return Response.json(
          {
            success: false,
            errorCode: 'QNAME_RUN_ID_MISMATCH',
            error: 'نام دامنهٔ استعلام‌شده (qname) با شناسهٔ نشست (runId) هم‌خوانی ندارد.',
          },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      const kvKey = `dns:${runId}`;
      const existingRaw = await env.DNS_LOGS_KV.get(kvKey);
      let existingList: any[] = [];
      if (existingRaw) {
        try {
          const parsed = JSON.parse(existingRaw);
          if (Array.isArray(parsed)) existingList = parsed;
        } catch {
          existingList = [];
        }
      }

      const newRecord = {
        id: `udp53-${runId.slice(0, 8)}-${existingList.length + 1}`,
        name: typeof body?.isp === 'string' && body.isp.trim() ? body.isp.trim() : 'Authoritative UDP/53 Observed Resolver',
        primaryIp: canonicalResolverIp,
        asn: typeof body?.asn === 'string' && body.asn.trim() ? body.asn.trim() : undefined,
        isp: typeof body?.isp === 'string' && body.isp.trim() ? body.isp.trim() : undefined,
        location: typeof body?.country === 'string' && body.country.trim() ? body.country.trim() : 'مشاهده‌شده در UDP/53',
        countryCode: typeof body?.countryCode === 'string' && body.countryCode.trim() ? body.countryCode.trim().toUpperCase() : undefined,
        runId,
        queryName: parsedQname.qname,
        observedAt: finalObservedAt,
        status: 'مشاهده‌شده در Authoritative DNS (UDP/53)',
        responseTimeMs: null,
        isEncryptedDoH: null,
        observationMethod: 'authoritative_dns_log' as const,
      };

      const merged = sanitizeValidatedResolversForRun(
        [...existingList, newRecord],
        runId,
        configuredDomain || null
      ).slice(0, 32);
      await env.DNS_LOGS_KV.put(kvKey, JSON.stringify(merged), { expirationTtl: 300 });

      return Response.json(
        {
          success: true,
          runId,
          storedResolversCount: merged.length,
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 6. Authenticated Collector Query Endpoint (Compatible with server.ts DNS_COLLECTOR_API_URL)
    if (url.pathname === '/api/dns-collector/logs' && request.method === 'GET') {
      const primaryToken = (env.DNS_COLLECTOR_API_TOKEN || '').trim();
      const previousToken = (env.DNS_COLLECTOR_API_TOKEN_PREVIOUS || '').trim();
      if ((!primaryToken && !previousToken) || !env.DNS_LOGS_KV) {
        return Response.json(
          {
            success: false,
            errorCode: 'COLLECTOR_NOT_CONFIGURED',
            error: 'کلکتور DNS در Cloudflare Worker پیکربندی نشده است.',
          },
          { status: 503, headers: securityAndCorsHeaders }
        );
      }

      const providedToken = extractBearerToken(request);
      if (!verifyBearerTokenWithRotation(providedToken, [primaryToken, previousToken])) {
        return Response.json(
          {
            success: false,
            errorCode: 'UNAUTHORIZED',
            error: 'توکن احراز هویت نامعتبر است.',
          },
          { status: 401, headers: securityAndCorsHeaders }
        );
      }

      const rawRunId = url.searchParams.get('runId') || '';
      if (!isValidDnsRunId(rawRunId)) {
        return Response.json(
          { success: false, errorCode: 'INVALID_RUN_ID', error: 'شناسهٔ نشست (runId) نامعتبر است.' },
          { status: 400, headers: securityAndCorsHeaders }
        );
      }

      const configuredDomain = (env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
      const raw = await env.DNS_LOGS_KV.get(`dns:${rawRunId}`);
      let parsed: unknown = [];
      if (raw) {
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = [];
        }
      }

      const resolvers = sanitizeValidatedResolversForRun(parsed, rawRunId, configuredDomain || null);
      return Response.json(
        {
          success: true,
          runId: rawRunId,
          resolvers,
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 7. Public Frontend DNS Leak Probe Endpoint
    //    Remains strictly in NOT_CONFIGURED («پیکربندی نشده») state until UDP/53 collector is verified.
    if (url.pathname === '/api/dns-leak-probe' && request.method === 'GET') {
      const rate = checkEdgeRateLimit(clientRateKey, 'dns-probe', 40, 60_000);
      if (!rate.allowed) {
        return Response.json(
          { success: false, errorCode: 'RATE_LIMIT_EXCEEDED', error: 'تعداد درخواست‌ها بیش از حد مجاز است.' },
          { status: 429, headers: { ...securityAndCorsHeaders, 'Retry-After': String(rate.retryAfterSec) } }
        );
      }

      const rawRunId = url.searchParams.get('runId') || '';
      const runId = isValidDnsRunId(rawRunId) ? rawRunId : crypto.randomUUID();
      const startedAt = new Date().toISOString();
      const dnsConfig = isAuthoritativeDnsFullyConfigured(env);

      if (!dnsConfig.configured || !env.DNS_LOGS_KV) {
        return Response.json(
          {
            success: true,
            runId,
            startedAt,
            completedAt: new Date().toISOString(),
            authoritativeConfigured: false,
            missingEnvVars: dnsConfig.missingVars,
            dnsLeakDomain: null,
            resolvers: [],
            messageFa:
              `وضعیت: پیکربندی نشده — متغیرهای زیرساختی (${dnsConfig.missingVars.join('، ')}) تنظیم یا تأیید نشده‌اند. تا پیش از راه‌اندازی و تأیید شنوندهٔ واقعی Authoritative DNS روی پورت UDP/53، هیچ نتیجه‌ای به عنوان امن یا موفق اعلام نمی‌شود.`,
          },
          { headers: securityAndCorsHeaders }
        );
      }

      const raw = await env.DNS_LOGS_KV.get(`dns:${runId}`);
      let parsed: unknown = [];
      if (raw) {
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = [];
        }
      }

      const resolvers = sanitizeValidatedResolversForRun(parsed, runId, dnsConfig.dnsLeakDomain);
      return Response.json(
        {
          success: true,
          runId,
          startedAt,
          completedAt: new Date().toISOString(),
          authoritativeConfigured: true,
          dnsLeakDomain: dnsConfig.dnsLeakDomain,
          resolvers,
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 8. Port Exposure Scan Endpoint on Cloudflare Edge (Honest INCONCLUSIVE state)
    if (url.pathname === '/api/port-scan' && request.method === 'GET') {
      const rawCfIp = request.headers.get('CF-Connecting-IP') || '';
      const clientIp = canonicalizeIp(rawCfIp);
      const now = new Date().toISOString();
      return Response.json(
        {
          success: true,
          targetIp: clientIp,
          targetSource: 'cloudflare_edge_no_inbound_tcp_scan',
          canScanFromServer: false,
          startedAt: now,
          completedAt: now,
          skippedReason: 'cloudflare_worker_edge_no_inbound_tcp_scan',
          messageFa:
            'در محیط Cloudflare Workers، اسکن مستقیم پورت‌های ورودی TCP به سمت آدرس IP کلاینت پشتیبانی نمی‌شود. وضعیت تمامی پورت‌ها «تست‌نشده» (نامشخص) ثبت شد و هیچ وضعیت امن کاذبی صادر نمی‌گردد.',
          ports: COMMON_SENSITIVE_PORTS.map(def => ({
            ...def,
            state: 'not_tested' as const,
            responseTimeMs: null,
          })),
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 9. Server-Side / Edge Security Audit Report Endpoint
    if (url.pathname === '/api/gemini-audit' && request.method === 'POST') {
      const rate = checkEdgeRateLimit(clientRateKey, 'gemini-audit', 15, 60_000);
      if (!rate.allowed) {
        return Response.json(
          { success: false, errorCode: 'RATE_LIMIT_EXCEEDED', error: 'تعداد درخواست‌ها بیش از حد مجاز است.' },
          { status: 429, headers: { ...securityAndCorsHeaders, 'Retry-After': String(rate.retryAfterSec) } }
        );
      }

      const parsedBody = await readBoundedJsonBody(request, MAX_JSON_BODY_BYTES);
      if (!parsedBody.ok) {
        return Response.json(
          { success: false, errorCode: parsedBody.errorCode, error: parsedBody.error },
          { status: parsedBody.status, headers: securityAndCorsHeaders }
        );
      }
      const body = parsedBody.data;
      const report = buildEdgeRuleBasedAuditReport(body?.networkState || body);
      return Response.json(
        {
          success: true,
          source: 'rule_based_fallback',
          data: report,
        },
        { headers: securityAndCorsHeaders }
      );
    }

    // 10. Serve Static Frontend Assets when deployed with Cloudflare Workers Static Assets
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function' && !url.pathname.startsWith('/api/')) {
      return env.ASSETS.fetch(request);
    }

    return Response.json({ error: 'Not Found' }, { status: 404, headers: securityAndCorsHeaders });
  },
};
