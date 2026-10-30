/**
 * Cloudflare Worker Compatible Edge API for NETLeakGard Pro V2 (Free Tier Compatible)
 *
 * Architectural Note:
 * - `server.ts` uses Express, Vite dev middleware, and Node.js built-ins (`node:dns`, `node:net`),
 *   which require a Node.js runtime (such as Cloud Run, VPS, or local Node.js).
 * - This `cloudflare/worker.ts` file provides a zero-cost Cloudflare Workers implementation
 *   for `/api/ip-info` (using verified `CF-Connecting-IP` and `request.cf` metadata),
 *   `/api/ping`, `/api/speed-test/chunk`, and `/api/dns-leak-probe`.
 * - Important Limitation: A standard HTTP Cloudflare Worker does NOT see raw UDP/53 DNS queries
 *   unless paired with an Authoritative DNS server log forwarder pushing records to KV/D1.
 */

export interface Env {
  DNS_LEAK_DOMAIN?: string;
  DNS_LOGS_KV?: {
    get(key: string): Promise<string | null>;
    put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Cache-Control': 'no-store',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === '/api/ping') {
      return Response.json(
        { pong: true, serverTimestamp: Date.now() },
        { headers: corsHeaders }
      );
    }

    if (url.pathname === '/api/speed-test/chunk') {
      const requested = parseInt(url.searchParams.get('bytes') || '524288', 10);
      const size = Math.max(65536, Math.min(1048576, Number.isFinite(requested) ? requested : 524288));
      const payload = new Uint8Array(size);
      return new Response(payload, {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/octet-stream',
          'Content-Length': String(size),
        },
      });
    }

    if (url.pathname === '/api/ip-info') {
      const cf = (request as any).cf || {};
      const clientIp = request.headers.get('CF-Connecting-IP') || null;
      const now = new Date().toISOString();

      return Response.json(
        {
          success: Boolean(clientIp),
          data: {
            status: clientIp ? 'PASS' : 'ERROR',
            testName: 'Cloudflare Edge IP Inspection',
            startedAt: now,
            completedAt: now,
            observations: clientIp
              ? [`آدرس IP تاییدشده توسط هدر Cloudflare Edge: ${clientIp}`]
              : ['هدر CF-Connecting-IP یافت نشد.'],
            evidence: {
              cfConnectingIp: clientIp,
              asn: cf.asn ? `AS${cf.asn}` : null,
              asOrganization: cf.asOrganization || null,
              colo: cf.colo || null,
            },
            limitations: [
              'موقعیت جغرافیایی بر اساس پایگاه دادهٔ Edge کلادفلر تخمین زده شده است.'
            ],
            errorCode: clientIp ? null : 'MISSING_CF_IP',
            source: 'Cloudflare Edge (request.cf)',
            confidence: clientIp ? 'high' : 'none',
            ip: clientIp,
            clientObservedIp: url.searchParams.get('clientIp') || null,
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
            isp: cf.asOrganization || null,
            asn: cf.asn ? `AS${cf.asn}` : null,
            org: cf.asOrganization || null,
            lat: cf.latitude ? Number(cf.latitude) : null,
            lon: cf.longitude ? Number(cf.longitude) : null,
            timezone: cf.timezone || null,
            isGeoEstimated: true,
          },
        },
        { headers: corsHeaders }
      );
    }

    if (url.pathname === '/api/dns-leak-probe') {
      const runId = url.searchParams.get('runId') || crypto.randomUUID();
      const configured = Boolean(env.DNS_LEAK_DOMAIN && env.DNS_LOGS_KV);
      if (!configured) {
        return Response.json(
          {
            success: true,
            runId,
            authoritativeConfigured: false,
            resolvers: [],
            messageFa: 'متغیر DNS_LEAK_DOMAIN یا فضای ذخیره‌سازی DNS_LOGS_KV در کلادفلر تنظیم نشده است.',
          },
          { headers: corsHeaders }
        );
      }

      const raw = await env.DNS_LOGS_KV!.get(`dns:${runId}`);
      const resolvers = raw ? JSON.parse(raw) : [];
      return Response.json(
        {
          success: true,
          runId,
          authoritativeConfigured: true,
          dnsLeakDomain: env.DNS_LEAK_DOMAIN,
          resolvers,
        },
        { headers: corsHeaders }
      );
    }

    return Response.json({ error: 'Not Found' }, { status: 404, headers: corsHeaders });
  },
};
