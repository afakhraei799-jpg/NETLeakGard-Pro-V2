import {
  AiAuditReport,
  ConfidenceLevel,
  DnsLeakResult,
  DnsResolver,
  IndependentBrowserDnsEntry,
  IndependentBrowserDnsObservation,
  IpDetails,
  NetworkMetrics,
  ObservedIpSource,
  PortLeakResult,
  PortProbeEntry,
  TestStatus,
  VpnProxyResult,
  WebRtcCandidate,
  WebRtcLeakResult
} from '../types/network';

/**
 * Parses an IPv4 string into 4 octets (Uint8Array) using strict RFC decimal rules.
 * Rejects leading zeros (octal ambiguity), negative/non-numeric segments, or out-of-range values.
 */
export function parseIpv4ToBytes(ip: string): Uint8Array | null {
  if (typeof ip !== 'string') return null;
  const trimmed = ip.trim();
  if (!trimmed || trimmed.length > 15) return null;
  const parts = trimmed.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    bytes[i] = num;
  }
  return bytes;
}

/**
 * Parses an IPv6 string into 8 16-bit words (Uint16Array) following RFC 4291 / RFC 5952.
 * Supports :: compression, IPv4-embedded suffixes (e.g. ::ffff:192.0.2.1), and optional %zone index.
 */
export function parseIpv6ToWords(
  ip: string
): { words: Uint16Array; zoneId: string | null } | null {
  if (typeof ip !== 'string') return null;
  const trimmed = ip.trim();
  if (!trimmed || trimmed.length > 64 || !trimmed.includes(':')) return null;

  let addrPart = trimmed;
  let zoneId: string | null = null;
  const pctIdx = trimmed.indexOf('%');
  if (pctIdx !== -1) {
    if (pctIdx === 0 || trimmed.indexOf('%', pctIdx + 1) !== -1) return null;
    zoneId = trimmed.slice(pctIdx + 1);
    if (!zoneId || !/^[0-9a-zA-Z._-]+$/.test(zoneId)) return null;
    addrPart = trimmed.slice(0, pctIdx);
  }

  // Reject single leading or trailing colon (when not ::)
  if (
    (addrPart.startsWith(':') && !addrPart.startsWith('::')) ||
    (addrPart.endsWith(':') && !addrPart.endsWith('::'))
  ) {
    return null;
  }

  // At most one '::' compression sequence is valid
  const doubleColonParts = addrPart.split('::');
  if (doubleColonParts.length > 2) return null;

  // Handle embedded IPv4 address at the end (e.g. ::ffff:192.0.2.1 or 64:ff9b::192.0.2.1)
  const lastColonIdx = addrPart.lastIndexOf(':');
  const suffixAfterLastColon = addrPart.slice(lastColonIdx + 1);
  if (suffixAfterLastColon.includes('.')) {
    const v4Bytes = parseIpv4ToBytes(suffixAfterLastColon);
    if (!v4Bytes) return null;
    const highWord = ((v4Bytes[0] << 8) | v4Bytes[1]).toString(16);
    const lowWord = ((v4Bytes[2] << 8) | v4Bytes[3]).toString(16);
    addrPart = `${addrPart.slice(0, lastColonIdx + 1)}${highWord}:${lowWord}`;
  }

  const reSplit = addrPart.split('::');
  if (reSplit.length > 2) return null;

  const isHexHextet = (seg: string) => /^[0-9a-fA-F]{1,4}$/.test(seg);
  const words = new Uint16Array(8);

  if (reSplit.length === 2) {
    const leftGroups = reSplit[0] === '' ? [] : reSplit[0].split(':');
    const rightGroups = reSplit[1] === '' ? [] : reSplit[1].split(':');
    if (leftGroups.length + rightGroups.length > 7) return null;
    if (!leftGroups.every(isHexHextet) || !rightGroups.every(isHexHextet)) return null;

    let idx = 0;
    for (const g of leftGroups) {
      words[idx++] = parseInt(g, 16);
    }
    const zeroFill = 8 - (leftGroups.length + rightGroups.length);
    for (let z = 0; z < zeroFill; z++) {
      words[idx++] = 0;
    }
    for (const g of rightGroups) {
      words[idx++] = parseInt(g, 16);
    }
  } else {
    const groups = addrPart.split(':');
    if (groups.length !== 8) return null;
    if (!groups.every(isHexHextet)) return null;
    for (let i = 0; i < 8; i++) {
      words[i] = parseInt(groups[i], 16);
    }
  }

  return { words, zoneId };
}

/**
 * Checks whether an IP string is a valid IPv4 address.
 */
export function isValidIpv4(ip: string): boolean {
  return parseIpv4ToBytes(ip) !== null;
}

/**
 * Checks whether an IP string is a valid RFC-4291 IPv6 address.
 */
export function isValidIpv6(ip: string): boolean {
  return parseIpv6ToWords(ip) !== null;
}

/**
 * Normalizes an IPv4 or IPv6 address into a canonical string for reliable equality comparisons.
 * Unwraps IPv4-mapped IPv6 addresses (::ffff:0:0/96) into canonical IPv4 form.
 */
export function canonicalizeIp(ip: string | null | undefined): string | null {
  if (!ip || typeof ip !== 'string') return null;
  const v4 = parseIpv4ToBytes(ip);
  if (v4) {
    return `${v4[0]}.${v4[1]}.${v4[2]}.${v4[3]}`;
  }
  const v6 = parseIpv6ToWords(ip);
  if (v6) {
    const w = v6.words;
    // Unwrap IPv4-mapped IPv6 ::ffff:a.b.c.d (0:0:0:0:0:ffff:xxxx:xxxx)
    if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff) {
      const b0 = (w[6] >> 8) & 0xff;
      const b1 = w[6] & 0xff;
      const b2 = (w[7] >> 8) & 0xff;
      const b3 = w[7] & 0xff;
      return `${b0}.${b1}.${b2}.${b3}`;
    }
    return Array.from(w, x => x.toString(16).padStart(4, '0')).join(':');
  }
  return null;
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
    case 'RUNNING':
      return 'در حال آزمایش...';
    case 'IDLE':
      return 'اجرا نشده';
    default:
      return 'نامشخص';
  }
}

/**
 * Validates that geographic coordinates are finite numbers within valid Earth bounds:
 * latitude in [-90, 90] and longitude in [-180, 180].
 */
export function isValidGeoCoordinate(lat: unknown, lon: unknown): lat is number {
  return (
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    Number.isFinite(lat) &&
    Number.isFinite(lon) &&
    lat >= -90 &&
    lat <= 90 &&
    lon >= -180 &&
    lon <= 180
  );
}

export type GlobeVisualCategory = 'pass' | 'leak' | 'error' | 'inconclusive';

export interface GlobeVisualStateInfo {
  visualCategory: GlobeVisualCategory;
  isLeak: boolean;
  isError: boolean;
  isPass: boolean;
  badgeTextFa: string;
  badgeTextEn: string;
}

/**
 * Strictly separates PASS, LEAK_DETECTED, ERROR, and inconclusive states for Globe3D.
 * - Never treats ERROR as a confirmed leak.
 * - Only allows PASS when overallStatus === 'PASS' AND ipDetails has a verified PASS status and non-empty IP.
 */
export function resolveGlobeVisualStatus(
  overallStatus: TestStatus,
  ipDetails: Pick<IpDetails, 'status' | 'ip'> | null
): GlobeVisualStateInfo {
  if (overallStatus === 'LEAK_DETECTED') {
    return {
      visualCategory: 'leak',
      isLeak: true,
      isError: false,
      isPass: false,
      badgeTextFa: 'اخطار سه بعدی: نشت شبکه در تست‌های اجراشده شناسایی شد',
      badgeTextEn: '3D ALERT: Network leak detected in executed tests',
    };
  }

  if (overallStatus === 'ERROR') {
    return {
      visualCategory: 'error',
      isLeak: false,
      isError: true,
      isPass: false,
      badgeTextFa: 'خطا در اجرای تست؛ نتیجه قابل تأیید نیست',
      badgeTextEn: 'Test execution failed; result cannot be verified.',
    };
  }

  const hasValidIpEvidence =
    ipDetails !== null &&
    ipDetails.status === 'PASS' &&
    typeof ipDetails.ip === 'string' &&
    ipDetails.ip.trim().length > 0;

  if (overallStatus === 'PASS' && hasValidIpEvidence) {
    return {
      visualCategory: 'pass',
      isLeak: false,
      isError: false,
      isPass: true,
      badgeTextFa: 'وضعیت سه بعدی: بدون نشت در تست‌های بررسی‌شده (صرفاً در محدوده تست‌های اجراشده)',
      badgeTextEn: '3D STATUS: No leaks observed in executed probes (limited to tested scope)',
    };
  }

  if (overallStatus === 'WARNING') {
    return {
      visualCategory: 'inconclusive',
      isLeak: false,
      isError: false,
      isPass: false,
      badgeTextFa: 'هشدار سه بعدی: ریسک احتمالی در تست‌های اجراشده (بدون اثبات نشت قطعی)',
      badgeTextEn: '3D WARNING: Potential risk in executed tests (no confirmed leak)',
    };
  }

  if (overallStatus === 'TESTING' || overallStatus === 'RUNNING') {
    return {
      visualCategory: 'inconclusive',
      isLeak: false,
      isError: false,
      isPass: false,
      badgeTextFa: 'وضعیت سه بعدی: در حال اجرای تست‌های شبکه... نتیجه هنوز قطعی نیست',
      badgeTextEn: '3D STATUS: Executing network probes... Result not yet determined',
    };
  }

  return {
    visualCategory: 'inconclusive',
    isLeak: false,
    isError: false,
    isPass: false,
    badgeTextFa: 'وضعیت سه بعدی: بررسی ناقص یا نیازمند پیکربندی زیرساخت (بدون ادعای امنیت کامل)',
    badgeTextEn: '3D STATUS: Inconclusive or pending infrastructure setup (no claim of full security)',
  };
}


function isPrivateOrLocalIpv4Bytes(b: Uint8Array): boolean {
  if (b[0] === 0) return true; // 0.0.0.0/8 current network
  if (b[0] === 10) return true; // 10.0.0.0/8 RFC1918
  if (b[0] === 127) return true; // 127.0.0.0/8 loopback
  if (b[0] === 169 && b[1] === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12 RFC1918
  if (b[0] === 192 && b[1] === 168) return true; // 192.168.0.0/16 RFC1918
  if (b[0] === 100 && b[1] >= 64 && b[1] <= 127) return true; // 100.64.0.0/10 CGNAT
  if (b[0] === 192 && b[1] === 0 && b[2] === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (b[0] === 198 && (b[1] === 18 || b[1] === 19)) return true; // 198.18.0.0/15 benchmarking
  if (b[0] >= 224) return true; // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved/broadcast
  return false;
}

function isNonRoutableIpv4Bytes(b: Uint8Array): boolean {
  if (isPrivateOrLocalIpv4Bytes(b)) return true;
  if (b[0] === 192 && b[1] === 0 && b[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (b[0] === 192 && b[1] === 88 && b[2] === 99) return true; // 192.88.99.0/24 6to4 relay anycast
  if (b[0] === 198 && b[1] === 51 && b[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (b[0] === 203 && b[1] === 0 && b[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
  return false;
}

function extractEmbeddedIpv4BytesFromIpv6(w: Uint16Array): Uint8Array | null {
  // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::/96 or IPv4-translated ::ffff:0:0:0/96
  const isMapped = w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff;
  const isTranslated = w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0xffff && w[5] === 0;
  const isCompatible =
    w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0 && (w[6] !== 0 || w[7] > 1);
  const isNat64 = w[0] === 0x0064 && w[1] === 0xff9b;

  if (isMapped || isTranslated || isCompatible || isNat64) {
    return new Uint8Array([
      (w[6] >> 8) & 0xff,
      w[6] & 0xff,
      (w[7] >> 8) & 0xff,
      w[7] & 0xff,
    ]);
  }
  // 6to4 (2002::/16) embeds IPv4 in w[1], w[2]
  if (w[0] === 0x2002) {
    return new Uint8Array([
      (w[1] >> 8) & 0xff,
      w[1] & 0xff,
      (w[2] >> 8) & 0xff,
      w[2] & 0xff,
    ]);
  }
  return null;
}

/**
 * Determines whether an IP or hostname is RFC1918 private, loopback, link-local, CGNAT, multicast, reserved, unique-local IPv6, or mDNS (.local).
 */
export function isPrivateOrLocalAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return true;
  const addr = address.trim().toLowerCase();
  if (addr.endsWith('.local') || addr === 'localhost' || addr.endsWith('.localhost') || addr.endsWith('.internal')) {
    return true;
  }

  const v4 = parseIpv4ToBytes(addr);
  if (v4) {
    return isPrivateOrLocalIpv4Bytes(v4);
  }

  const v6 = parseIpv6ToWords(addr);
  if (v6) {
    if (v6.zoneId !== null) return true; // Scoped zone addresses (%eth0) are always local
    const w = v6.words;
    const allZeroHigh = w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0 && w[6] === 0;
    if (allZeroHigh && (w[7] === 0 || w[7] === 1)) return true; // :: and ::1

    const embeddedV4 = extractEmbeddedIpv4BytesFromIpv6(w);
    if (embeddedV4) {
      return isPrivateOrLocalIpv4Bytes(embeddedV4);
    }

    if ((w[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique Local (ULA)
    if ((w[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-Local
    if ((w[0] & 0xff00) === 0xff00) return true; // ff00::/8 Multicast
    if (w[0] === 0x2001 && w[1] === 0x0db8) return true; // 2001:db8::/32 Documentation
    if (w[0] === 0x2001 && w[1] === 0x0002 && w[2] === 0x0000) return true; // 2001:2::/48 Benchmarking
    if (w[0] === 0x0100 && w[1] === 0 && w[2] === 0 && w[3] === 0) return true; // 100::/64 Discard-Only
    return false;
  }

  return true;
}

/**
 * Strictly checks if an input is a globally routable public IPv4 or IPv6 literal suitable for external scanning/probing.
 * Rejects hostnames, loopback, RFC1918, CGNAT, link-local/metadata (169.254.169.254), multicast, broadcast, NAT64/6to4/Teredo, and documentation ranges.
 */
export function isGloballyRoutablePublicIp(address: string | null | undefined): boolean {
  if (!address || typeof address !== 'string') return false;
  const trimmed = address.trim();
  if (!trimmed) return false;

  const v4 = parseIpv4ToBytes(trimmed);
  if (v4) {
    return !isNonRoutableIpv4Bytes(v4);
  }

  const v6 = parseIpv6ToWords(trimmed);
  if (v6) {
    if (v6.zoneId !== null) return false;
    const w = v6.words;

    // Check IPv4-mapped ::ffff:0:0/96 specifically
    if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff) {
      const mappedBytes = new Uint8Array([
        (w[6] >> 8) & 0xff,
        w[6] & 0xff,
        (w[7] >> 8) & 0xff,
        w[7] & 0xff,
      ]);
      return !isNonRoutableIpv4Bytes(mappedBytes);
    }

    // Must be within IANA Global Unicast range 2000::/3
    if ((w[0] & 0xe000) !== 0x2000) return false;

    // Reject special-purpose prefixes inside 2000::/3
    if (w[0] === 0x2001 && w[1] === 0x0000) return false; // 2001::/32 Teredo
    if (w[0] === 0x2001 && w[1] === 0x0002 && w[2] === 0x0000) return false; // 2001:2::/48 Benchmarking
    if (w[0] === 0x2001 && w[1] === 0x0db8) return false; // 2001:db8::/32 Documentation
    if (w[0] === 0x2001 && (w[1] & 0xfff0) === 0x0010) return false; // 2001:10::/28 ORCHID
    if (w[0] === 0x2001 && (w[1] & 0xfff0) === 0x0020) return false; // 2001:20::/28 ORCHIDv2
    if (w[0] === 0x2002) return false; // 2002::/16 6to4 transition

    return !isPrivateOrLocalAddress(trimmed);
  }

  return false;
}

/**
 * Validates that an external URL is safe for server-side HTTP/HTTPS requests (SSRF prevention).
 * Rejects credentials in URL, non-HTTP(S) schemes, localhost/internal domains, numeric/hex IP obfuscations, and non-public IP literals.
 */
export function isSafeExternalUrl(rawUrl: string): { valid: boolean; url?: URL; reason?: string } {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, reason: 'ساختار URL نامعتبر است.' };
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { valid: false, reason: 'پروتکل آدرس باید HTTP یا HTTPS باشد.' };
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return { valid: false, reason: 'استفاده از نام کاربری یا گذرواژه در URL مجاز نیست.' };
    }

    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
    if (!host) {
      return { valid: false, reason: 'نام میزبان (Hostname) خالی است.' };
    }

    if (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.home.arpa') ||
      host.endsWith('.lan') ||
      host.endsWith('.corp') ||
      host === 'metadata.google.internal' ||
      host === ' metadata' ||
      host === 'instance-data'
    ) {
      return { valid: false, reason: 'آدرس‌های میزبان محلی یا متادیتای داخلی (localhost / .local / .internal) مجاز نیستند.' };
    }

    // If hostname is an IPv6 literal or contains colons
    if (host.includes(':')) {
      if (!isGloballyRoutablePublicIp(host)) {
        return { valid: false, reason: 'آدرس IPv6 خصوصی، Loopback، رزرو یا نامعتبر در URL مجاز نیست.' };
      }
      return { valid: true, url: parsed };
    }

    // Check for numeric/octal/hex IPv4 obfuscation (e.g. 2130706433, 0x7f000001, 0177.0.0.1, 127.1)
    const labels = host.split('.');
    const looksLikeNumericOrHexIp = labels.every(
      l => /^[0-9]+$/.test(l) || /^0x[0-9a-f]+$/i.test(l)
    );
    if (looksLikeNumericOrHexIp) {
      if (!isValidIpv4(host) || !isGloballyRoutablePublicIp(host)) {
        return { valid: false, reason: 'آدرس IP خصوصی، Loopback، Link-Local یا فرمت عددی غیراستاندارد در URL مجاز نیست.' };
      }
      return { valid: true, url: parsed };
    }

    if (isValidIpv4(host) && !isGloballyRoutablePublicIp(host)) {
      return { valid: false, reason: 'آدرس IP خصوصی، Loopback یا رزروشده در URL مجاز نیست.' };
    }

    return { valid: true, url: parsed };
  } catch {
    return { valid: false, reason: 'ساختار URL نامعتبر است.' };
  }
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

  const canonicalRefIpv4s = new Set<string>();
  const canonicalRefIpv6s = new Set<string>();
  for (const refIp of cleanRefIps) {
    const canon = canonicalizeIp(refIp);
    if (!canon) continue;
    if (canon.includes(':')) {
      canonicalRefIpv6s.add(canon);
    } else {
      canonicalRefIpv4s.add(canon);
    }
  }

  const mismatchedPublicIps: string[] = [];
  const dualStackUnmatchedFamilyIps: string[] = [];

  for (const candIp of publicCandidates) {
    const canonCand = canonicalizeIp(candIp);
    if (!canonCand || cleanRefIps.length === 0) continue;
    const isCandV6 = canonCand.includes(':');
    const sameFamilyRefs = isCandV6 ? canonicalRefIpv6s : canonicalRefIpv4s;
    const otherFamilyRefs = isCandV6 ? canonicalRefIpv4s : canonicalRefIpv6s;

    if (sameFamilyRefs.size > 0) {
      if (!sameFamilyRefs.has(canonCand)) {
        mismatchedPublicIps.push(candIp);
      }
    } else if (otherFamilyRefs.size > 0) {
      dualStackUnmatchedFamilyIps.push(candIp);
    }
  }

  // Leak confirmed if a public candidate IP differs from reference public IP(s) of the same address family
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

  // Dual-stack STUN candidate where no reference IP of the same family (IPv4 vs IPv6) was observed
  if (dualStackUnmatchedFamilyIps.length > 0) {
    return {
      status: 'WARNING',
      testName: 'WebRTC ICE Candidate Leak Test',
      startedAt,
      completedAt,
      observations: [
        `نامزد عمومی STUN در خانوادهٔ آدرس متفاوت (${dualStackUnmatchedFamilyIps.join(', ')}) مشاهده شد، در حالی که آدرس مرجع فقط در خانوادهٔ دیگر (${cleanRefIps.join(', ')}) ثبت شده است (اتصال Dual-Stack IPv4/IPv6).`,
      ],
      evidence: {
        referencePublicIps: cleanRefIps,
        publicCandidates,
        dualStackUnmatchedFamilyIps,
        localIps,
        mdnsHosts,
      },
      limitations: commonLimitations,
      errorCode: 'DUAL_STACK_FAMILY_UNVERIFIED',
      source: 'Browser RTCPeerConnection ICE Gathering',
      confidence: 'medium',
      isSupported: true,
      stunServersUsed,
      localIps,
      mdnsHosts,
      publicCandidates,
      isLeakingRealIp: null,
      candidates,
      messageFa: `هشدار Dual-Stack: نامزد عمومی STUN (${dualStackUnmatchedFamilyIps.join(', ')}) از خانوادهٔ آدرس متفاوتی نسبت به IP مرجع (${cleanRefIps.join(', ')}) است؛ بررسی تونل IPv6 توصیه می‌شود.`,
      messageEn: `Dual-Stack Warning: WebRTC STUN candidate (${dualStackUnmatchedFamilyIps.join(', ')}) is a different address family from reference IP (${cleanRefIps.join(', ')}).`,
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

function normalizeAsnString(asn: string | undefined | null): string | null {
  if (!asn || typeof asn !== 'string') return null;
  const match = asn.trim().toUpperCase().match(/^(?:AS)?(\d+)$/);
  return match ? `AS${match[1]}` : null;
}

function extractIsoCountryCode(raw: string | undefined | null): string | null {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim().toUpperCase();
  if (trimmed === 'ANYCAST') return 'ANYCAST';
  if (/^[A-Z]{2}$/.test(trimmed)) return trimmed;
  return null;
}

/**
 * Evaluates independent, zero-cost browser-observable DNS & edge trace data (e.g. edns.ip-api.com, 1.1.1.1/cdn-cgi/trace).
 * Strictly separated from Authoritative DNS Leak Test:
 * - Observing a single resolver or country match NEVER proves absence of a DNS leak (never returns PASS based on resolver/country).
 * - Country difference alone NEVER proves a confirmed DNS leak (never returns LEAK_DETECTED based on country alone).
 * - `matchesPrimaryEgressIp` is ONLY `true` when an entry of the same data type (`edge_trace_egress`) has a valid IP that canonically matches `ipDetails.ip`, `false` when a valid `edge_trace_egress` IP differs from `ipDetails.ip`, and `null` otherwise.
 */
export function evaluateIndependentBrowserDnsObservation(
  entries: IndependentBrowserDnsEntry[],
  ipDetails: IpDetails | null
): IndependentBrowserDnsObservation {
  const limitationsFa = [
    'این بررسی مستقل از طریق درخواست‌های HTTPS مرورگر به سرویس‌های عمومی رایگان (مانند EDNS و Cloudflare Trace) انجام می‌شود و جایگزین تست Authoritative DNS Leak اختصاصی نیست.',
    'در صورتی که مرورگر از DNS-over-HTTPS (DoH) داخلی استفاده کند، مسیر DNS مرورگر ممکن است با Resolver سطح سیستم‌عامل (OS-level DNS) متفاوت باشد.',
    'مشاهدهٔ یک Resolver یا تطابق جغرافیایی کشورها در یک استعلام تک‌نقطه‌ای، عدم نشت DNS را اثبات نمی‌کند و تفاوت کشور نیز به‌تنهایی دلیل قطعی نشت DNS نیست.'
  ];

  const validEntries = Array.isArray(entries)
    ? entries.filter(e => e && typeof e.observedIp === 'string' && canonicalizeIp(e.observedIp) !== null)
    : [];

  if (validEntries.length === 0) {
    return {
      status: 'INCONCLUSIVE',
      entries: [],
      matchesPrimaryEgressIp: null,
      summaryFa:
        'نامشخص: پاسخ معتبری از منابع مستقل بررسی DNS/Trace مرورگر دریافت نشد (احتمال مسدودسازی CORS، فایروال یا عدم دسترسی شبکه). هیچ مقدار جعلی تولید نشد.',
      summaryEn:
        'Inconclusive: No valid response received from independent browser DNS/trace endpoints. No synthetic data generated.',
      limitationsFa,
    };
  }

  const primaryEgressCanonical =
    ipDetails && ipDetails.status !== 'ERROR' && ipDetails.ip
      ? canonicalizeIp(ipDetails.ip)
      : null;

  // Only compare entries of the exact same data type (`edge_trace_egress` = client HTTP egress IP) against primary egress IP
  const edgeEgressEntries = validEntries.filter(e => e.role === 'edge_trace_egress');
  let matchesPrimaryEgressIp: boolean | null = null;

  if (primaryEgressCanonical !== null && edgeEgressEntries.length > 0) {
    const allMatch = edgeEgressEntries.every(
      e => canonicalizeIp(e.observedIp) === primaryEgressCanonical
    );
    matchesPrimaryEgressIp = allMatch;
  }

  // If an observed edge egress IP explicitly differs from primary egress IP, report WARNING (split-tunnel / multi-path)
  if (matchesPrimaryEgressIp === false) {
    return {
      status: 'WARNING',
      entries: validEntries,
      matchesPrimaryEgressIp: false,
      summaryFa:
        'هشدار مغایرت IP خروجی در مشاهدهٔ مرورگر: آدرس IP خروجی مشاهده‌شده در Edge Trace با آدرس IP خروجی اصلی یکسان نیست (احتمال Split-Tunneling یا مسیرهای متفاوت HTTP).',
      summaryEn:
        'Warning (Independent Browser Observation): Observed Edge Trace egress IP differs from primary egress IP.',
      limitationsFa,
    };
  }

  const ednsResolvers = validEntries.filter(
    e => e.role === 'edns_recursive_resolver' || e.role === 'client_subnet_edns'
  );

  if (ednsResolvers.length > 0) {
    return {
      status: 'INCONCLUSIVE',
      entries: validEntries,
      matchesPrimaryEgressIp,
      summaryFa: `نامشخص (مشاهدهٔ کمکی مرورگر از ${validEntries.length} منبع): آدرس Resolver در استعلام تک‌نقطه‌ای ثبت شد، اما مشاهدهٔ یک Resolver یا موقعیت جغرافیایی در مرورگر، اثبات‌کنندهٔ عدم نشت یا نشت قطعی DNS نیست.`,
      summaryEn: `Inconclusive (Browser auxiliary observation from ${validEntries.length} source(s)): Observing a single resolver or country in browser does not prove absence or presence of a DNS leak.`,
      limitationsFa,
    };
  }

  return {
    status: 'INCONCLUSIVE',
    entries: validEntries,
    matchesPrimaryEgressIp,
    summaryFa:
      'نامشخص: فقط مسیر خروجی (Edge Trace) از مرورگر مشاهده شد و اطلاعاتی از Recursive Resolver توسط سرویس EDNS برگردانده نشد.',
    summaryEn:
      'Inconclusive: Only edge trace egress was observed; recursive DNS resolver IP was not returned by independent EDNS.',
    limitationsFa,
  };
}

export interface ParsedDnsLeakQname {
  valid: boolean;
  qname: string;
  probeLabel: string | null;
  probeNumber: number | null;
  runId: string | null;
  baseDomain: string | null;
  errorCode:
    | null
    | 'EMPTY_OR_OVERSIZED_QNAME'
    | 'INVALID_DNS_LABEL'
    | 'QNAME_DOMAIN_MISMATCH'
    | 'INVALID_QNAME_STRUCTURE'
    | 'INVALID_PROBE_LABEL'
    | 'INVALID_RUN_ID_LABEL';
}

const DNS_SINGLE_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const DNS_PROBE_LABEL_REGEX = /^p([1-9][0-9]?)$/i;
const DNS_RUN_ID_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{6,61}[a-z0-9])$/i;
const PREFIXED_UUID_TRAP_REGEX = /^p[0-9]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates that a runId is a single RFC 1035 compliant DNS label (8 to 63 ASCII alphanumeric/hyphen chars,
 * not starting or ending with a hyphen, containing no dots, and not contaminated by a `p<N>-` probe prefix).
 */
export function isValidDnsRunId(runId: unknown): boolean {
  if (typeof runId !== 'string') return false;
  if (runId.trim() !== runId || runId.length < 8 || runId.length > 63) return false;
  if (!DNS_RUN_ID_LABEL_REGEX.test(runId)) return false;
  if (PREFIXED_UUID_TRAP_REGEX.test(runId)) return false;
  return true;
}

/**
 * Validates that a base domain for DNS leak testing is a well-formed multi-label DNS domain
 * within RFC 1035 length limits (allowing room for `p<N>.<runId>.` prefix labels).
 */
export function isValidDnsLeakBaseDomain(domain: unknown): boolean {
  if (typeof domain !== 'string') return false;
  const norm = domain.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (norm.length < 3 || norm.length > 185 || norm.includes('..')) return false;
  const labels = norm.split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63 || !DNS_SINGLE_LABEL_REGEX.test(label)) {
      return false;
    }
  }
  const tld = labels[labels.length - 1];
  if (tld.length < 2 || /^\d+$/.test(tld)) return false;
  return true;
}

/**
 * Builds the canonical, unambiguous DNS leak probe QNAME: `p<probeNumber>.<runId>.<baseDomain>`
 * Returns null if any component violates RFC 1035 label or domain rules.
 */
export function buildDnsLeakProbeQname(
  probeNumber: number,
  runId: string,
  baseDomain: string
): string | null {
  if (!Number.isInteger(probeNumber) || probeNumber < 1 || probeNumber > 99) {
    return null;
  }
  if (!isValidDnsRunId(runId) || !isValidDnsLeakBaseDomain(baseDomain)) {
    return null;
  }
  const normRunId = runId.trim().toLowerCase();
  const normDomain = baseDomain.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const qname = `p${probeNumber}.${normRunId}.${normDomain}`;
  if (qname.length > 253) return null;
  return qname;
}

/**
 * Strictly parses and validates a DNS leak probe QNAME against the canonical `<probeLabel>.<runId>.<baseDomain>` format.
 * - Enforces RFC 1035 label length (1..63) and total QNAME length (<= 253).
 * - When `allowedBaseDomain` is provided, requires `qname` to belong to `.${allowedBaseDomain}` with EXACTLY two prefix labels (`p<N>` and `<runId>`).
 * - Cleanly separates `probeNumber` (`1..99`) and `runId` (exact UUID/token without prefix or suffix).
 * - Rejects malformed formats such as `p1-<runId>.<domain>`, `<runId>.<domain>`, or `extra.p1.<runId>.<domain>`.
 */
export function parseDnsLeakProbeQname(
  rawQname: unknown,
  allowedBaseDomain?: string | null
): ParsedDnsLeakQname {
  if (typeof rawQname !== 'string') {
    return {
      valid: false,
      qname: '',
      probeLabel: null,
      probeNumber: null,
      runId: null,
      baseDomain: null,
      errorCode: 'EMPTY_OR_OVERSIZED_QNAME',
    };
  }

  const trimmed = rawQname.trim().toLowerCase();
  const qname = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (!qname || qname.length > 253 || qname.startsWith('.') || qname.endsWith('.') || qname.includes('..')) {
    return {
      valid: false,
      qname,
      probeLabel: null,
      probeNumber: null,
      runId: null,
      baseDomain: null,
      errorCode: 'EMPTY_OR_OVERSIZED_QNAME',
    };
  }

  const labels = qname.split('.');
  for (const label of labels) {
    if (label.length < 1 || label.length > 63 || !DNS_SINGLE_LABEL_REGEX.test(label)) {
      return {
        valid: false,
        qname,
        probeLabel: null,
        probeNumber: null,
        runId: null,
        baseDomain: null,
        errorCode: 'INVALID_DNS_LABEL',
      };
    }
  }

  let probeLabel: string;
  let candidateRunId: string;
  let baseDomain: string;

  if (allowedBaseDomain !== undefined && allowedBaseDomain !== null && String(allowedBaseDomain).trim() !== '') {
    const normAllowed = String(allowedBaseDomain).trim().toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!isValidDnsLeakBaseDomain(normAllowed) || !qname.endsWith(`.${normAllowed}`)) {
      return {
        valid: false,
        qname,
        probeLabel: null,
        probeNumber: null,
        runId: null,
        baseDomain: null,
        errorCode: 'QNAME_DOMAIN_MISMATCH',
      };
    }
    const prefix = qname.slice(0, qname.length - (normAllowed.length + 1));
    const prefixLabels = prefix ? prefix.split('.') : [];
    if (prefixLabels.length !== 2) {
      return {
        valid: false,
        qname,
        probeLabel: null,
        probeNumber: null,
        runId: null,
        baseDomain: normAllowed,
        errorCode: 'INVALID_QNAME_STRUCTURE',
      };
    }
    probeLabel = prefixLabels[0];
    candidateRunId = prefixLabels[1];
    baseDomain = normAllowed;
  } else {
    if (labels.length < 4) {
      return {
        valid: false,
        qname,
        probeLabel: null,
        probeNumber: null,
        runId: null,
        baseDomain: null,
        errorCode: 'INVALID_QNAME_STRUCTURE',
      };
    }
    probeLabel = labels[0];
    candidateRunId = labels[1];
    baseDomain = labels.slice(2).join('.');
    if (!isValidDnsLeakBaseDomain(baseDomain)) {
      return {
        valid: false,
        qname,
        probeLabel: null,
        probeNumber: null,
        runId: null,
        baseDomain: null,
        errorCode: 'QNAME_DOMAIN_MISMATCH',
      };
    }
  }

  const probeMatch = probeLabel.match(DNS_PROBE_LABEL_REGEX);
  if (!probeMatch) {
    return {
      valid: false,
      qname,
      probeLabel,
      probeNumber: null,
      runId: null,
      baseDomain,
      errorCode: 'INVALID_PROBE_LABEL',
    };
  }

  if (!isValidDnsRunId(candidateRunId)) {
    return {
      valid: false,
      qname,
      probeLabel,
      probeNumber: Number(probeMatch[1]),
      runId: null,
      baseDomain,
      errorCode: 'INVALID_RUN_ID_LABEL',
    };
  }

  return {
    valid: true,
    qname,
    probeLabel,
    probeNumber: Number(probeMatch[1]),
    runId: candidateRunId,
    baseDomain,
    errorCode: null,
  };
}

/**
 * Strictly verifies whether an object is an authentic, structured Authoritative DNS observation record.
 * Rejects records that:
 * 1. Lack a valid runId string or have runId mismatching expectedRunId.
 * 2. Lack an observedAt timestamp, have an unparseable timestamp, or are stale (> 5 min) / future skew (> 60s).
 * 3. Have a missing, non-canonical, or non-globally-routable public IP (RFC1918, loopback, CGNAT, link-local, multicast, documentation, etc.).
 * 4. Lack a valid canonical queryName/qname (`p<N>.<runId>.<domain>`) or have a qname whose extracted runId or domain does not match the active run.
 * 5. Have an observationMethod other than 'authoritative_dns_log'.
 */
export function isValidDnsObservationRecord(
  record: unknown,
  expectedRunId: string,
  nowMs = Date.now(),
  expectedDomain?: string | null
): boolean {
  if (!record || typeof record !== 'object') return false;
  const r = record as Record<string, unknown>;

  const normExpectedRunId = typeof expectedRunId === 'string' ? expectedRunId.trim() : '';
  if (!isValidDnsRunId(normExpectedRunId)) return false;

  // 1. Mandatory runId and strict exact match
  const recRunId = typeof r.runId === 'string' ? r.runId.trim() : '';
  if (!recRunId || recRunId.toLowerCase() !== normExpectedRunId.toLowerCase()) return false;

  // 2. Mandatory observedAt timestamp within freshness window (5 min past, 60s future)
  if (typeof r.observedAt !== 'string' || !r.observedAt.trim()) {
    return false;
  }
  const ts = Date.parse(r.observedAt);
  if (!Number.isFinite(ts)) return false;
  const ageMs = nowMs - ts;
  if (ageMs > 5 * 60 * 1000 || ageMs < -60 * 1000) {
    return false;
  }

  // 3. Strict globally routable public IP
  const rawIp = typeof r.primaryIp === 'string' ? r.primaryIp : typeof r.ip === 'string' ? r.ip : '';
  const canonicalIp = canonicalizeIp(rawIp);
  if (!canonicalIp || !isGloballyRoutablePublicIp(canonicalIp)) {
    return false;
  }

  // 4. Mandatory canonical QNAME (`p<N>.<runId>.<domain>`) bound to this exact runId (and domain if provided)
  const rawQname =
    typeof r.queryName === 'string'
      ? r.queryName
      : typeof r.qname === 'string'
        ? r.qname
        : '';
  const parsedQname = parseDnsLeakProbeQname(rawQname, expectedDomain);
  if (!parsedQname.valid || parsedQname.runId !== normExpectedRunId.toLowerCase()) {
    return false;
  }

  // 5. Must have authoritative_dns_log provenance if observationMethod is specified
  if (r.observationMethod && r.observationMethod !== 'authoritative_dns_log') {
    return false;
  }

  return true;
}

export interface OptionalDnsServerConfigEvaluation {
  authoritativeConfigured: boolean;
  configState: 'unconfigured' | 'partial_or_invalid' | 'configured';
  dnsLeakDomain: string | null;
  collectorUrl: URL | null;
  collectorToken: string | null;
  udp53Verified: boolean;
  trustProxyEnabled: boolean;
  missingEnvVars: string[];
  configIssuesFa: string[];
  messageFa: string;
}

/**
 * Evaluates optional server environment variables (DNS_LEAK_DOMAIN, DNS_COLLECTOR_API_URL,
 * DNS_COLLECTOR_API_TOKEN, DNS_UDP53_VERIFIED, TRUST_PROXY) without requiring any variable
 * to be set and without generating synthetic defaults.
 * - Completely empty values are treated as a clean, valid 'unconfigured' state (missingEnvVars = []).
 * - Partial or invalid values disable ONLY the Authoritative DNS feature (authoritativeConfigured = false,
 *   configState = 'partial_or_invalid') and record non-blocking diagnostic issues without halting execution.
 */
export function evaluateOptionalDnsServerConfig(
  env: Record<string, string | undefined> = {}
): OptionalDnsServerConfigEvaluation {
  const rawDomain = (env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const rawUrl = (env.DNS_COLLECTOR_API_URL || '').trim();
  const rawToken = (env.DNS_COLLECTOR_API_TOKEN || '').trim();
  const rawUdp53 = (env.DNS_UDP53_VERIFIED || '').trim().toLowerCase();
  const rawTrustProxy = (env.TRUST_PROXY || '').trim().toLowerCase();

  const udp53Verified = rawUdp53 === 'true';
  const trustProxyEnabled = rawTrustProxy === 'true' || rawTrustProxy === '1';

  const configIssuesFa: string[] = [];

  if (rawTrustProxy && !['true', 'false', '1', '0'].includes(rawTrustProxy)) {
    configIssuesFa.push(
      'مقدار متغیر اختیاری TRUST_PROXY نامعتبر است (مقادیر مجاز: true یا false)؛ حالت ایمن پیش‌فرض (false) اعمال شد.'
    );
  }

  if (rawUdp53 && !['true', 'false', '1', '0'].includes(rawUdp53)) {
    configIssuesFa.push(
      'مقدار متغیر اختیاری DNS_UDP53_VERIFIED نامعتبر است؛ تا زمان تنظیم صریح برابر true، شنوندهٔ UDP/53 تأییدنشده تلقی می‌شود.'
    );
  }

  const anyDnsVarProvided = Boolean(rawDomain || rawUrl || rawToken || udp53Verified);

  if (!anyDnsVarProvided) {
    return {
      authoritativeConfigured: false,
      configState: configIssuesFa.length > 0 ? 'partial_or_invalid' : 'unconfigured',
      dnsLeakDomain: null,
      collectorUrl: null,
      collectorToken: null,
      udp53Verified: false,
      trustProxyEnabled,
      missingEnvVars: [],
      configIssuesFa,
      messageFa:
        'وضعیت: پیکربندی نشده — زیرساخت اختیاری Authoritative DNS تنظیم نشده است. بررسی مستقل DNS مرورگر و سایر تست‌های شبکه بدون نیاز به متغیر محیطی اجرا می‌شوند و هیچ نتیجه‌ای به‌عنوان امن یا موفق جعل نمی‌شود.',
    };
  }

  // At least one optional DNS variable was provided; validate completeness and syntax non-blockingly
  const missingEnvVars: string[] = [];
  let validDomain: string | null = null;
  let validUrl: URL | null = null;

  if (!rawDomain) {
    missingEnvVars.push('DNS_LEAK_DOMAIN');
    configIssuesFa.push('متغیر DNS_LEAK_DOMAIN خالی است.');
  } else if (!isValidDnsLeakBaseDomain(rawDomain)) {
    missingEnvVars.push('DNS_LEAK_DOMAIN');
    configIssuesFa.push('قالب دامنهٔ DNS_LEAK_DOMAIN نامعتبر است (باید یک دامنهٔ عمومی معتبر مطابق RFC 1035 باشد).');
  } else {
    validDomain = rawDomain;
  }

  if (!rawUrl) {
    missingEnvVars.push('DNS_COLLECTOR_API_URL');
    configIssuesFa.push('متغیر DNS_COLLECTOR_API_URL خالی است.');
  } else {
    const urlCheck = isSafeExternalUrl(rawUrl);
    if (!urlCheck.valid || !urlCheck.url) {
      missingEnvVars.push('DNS_COLLECTOR_API_URL');
      configIssuesFa.push(
        `آدرس DNS_COLLECTOR_API_URL نامعتبر یا ناامن است (${urlCheck.reason || 'Invalid URL'}).`
      );
    } else {
      validUrl = urlCheck.url;
    }
  }

  if (!rawToken) {
    missingEnvVars.push('DNS_COLLECTOR_API_TOKEN');
    configIssuesFa.push('توکن احراز هویت DNS_COLLECTOR_API_TOKEN خالی است.');
  }

  if (!udp53Verified) {
    missingEnvVars.push('DNS_UDP53_VERIFIED=true');
    configIssuesFa.push('تأیید عملی شنوندهٔ UDP/53 (DNS_UDP53_VERIFIED=true) فعال نشده است.');
  }

  if (missingEnvVars.length > 0 || !validDomain || !validUrl || !rawToken || !udp53Verified) {
    return {
      authoritativeConfigured: false,
      configState: 'partial_or_invalid',
      dnsLeakDomain: null,
      collectorUrl: null,
      collectorToken: null,
      udp53Verified,
      trustProxyEnabled,
      missingEnvVars,
      configIssuesFa,
      messageFa: `وضعیت: پیکربندی نشده (تنظیمات اختیاری ناقص یا نامعتبر) — ${configIssuesFa.join(' ')} فقط تست Authoritative DNS غیرفعال شد و سایر بخش‌های برنامه بدون توقف کار می‌کنند.`,
    };
  }

  return {
    authoritativeConfigured: true,
    configState: 'configured',
    dnsLeakDomain: validDomain,
    collectorUrl: validUrl,
    collectorToken: rawToken,
    udp53Verified: true,
    trustProxyEnabled,
    missingEnvVars: [],
    configIssuesFa,
    messageFa: 'زیرساخت Authoritative DNS پیکربندی شده است.',
  };
}

/**
 * Evaluates DNS Leak results based on real authoritative logs or explicitly marks NOT_CONFIGURED / INCONCLUSIVE.
 * Never inspects localized status text (like "Leak" or "مغایرت") to decide leak state.
 * Validates runId, resolver runId + QNAME affiliation, observationMethod, valid resolver IPs, and structured comparison criteria against ipDetails.
 */
export function evaluateDnsTestResult(params: {
  runId: string;
  authoritativeConfigured: boolean;
  missingEnvVars?: string[];
  dnsLeakDomain?: string | null;
  resolvers: DnsResolver[];
  ipDetails: IpDetails | null;
  independentBrowserObservation?: IndependentBrowserDnsObservation;
  startedAt: string;
  completedAt: string;
  errorMessage?: string;
}): DnsLeakResult {
  let {
    runId,
    authoritativeConfigured,
    missingEnvVars = [],
    dnsLeakDomain,
    resolvers,
    ipDetails,
    independentBrowserObservation,
    startedAt,
    completedAt,
    errorMessage,
  } = params;

  const dnsLimitations = [
    'مشاهدهٔ آدرس IP در سرور Authoritative DNS فقط آخرین گره (Egress Resolver) زنجیرهٔ DNS را نشان می‌دهد و در صورت استفاده از DoH/DoT یا فورواردر واسط، کل زنجیره آشکار نمی‌شود.',
    'تعداد گزارش‌شده بیانگر «IPهای Resolver مشاهده‌شده» (Observed Resolver IPs) پس از حذف تکراری‌ها است؛ به دلیل توزیع بار (Load Balancing) و Anycast، چند IP مختلف ممکن است متعلق به یک سرویس‌دهندهٔ واحد باشند.',
    'تست DNS از داخل مرورگر صرفاً درخواست‌های شبکهٔ مرورگر (یا DoH اختصاصی فعال در مرورگر) را آزمایش می‌کند و وضعیت Resolver سطح سیستم‌عامل (OS-level DNS) سایر برنامه‌ها را اثبات نمی‌کند.',
    'بررسی DNS از طریق مرورگر با تست Authoritative DNS Leak یکسان نیست؛ برای اثبات قطعی عدم نشت، سرور Authoritative DNS اختصاصی الزامی است.'
  ];

  const normalizedRunId = typeof runId === 'string' ? runId.trim() : '';

  if (!authoritativeConfigured) {
    const missingList = Array.isArray(missingEnvVars) ? missingEnvVars : [];
    const detailNoteFa = errorMessage
      ? errorMessage
      : missingList.length > 0
        ? `وضعیت: پیکربندی نشده — تنظیمات اختیاری (${missingList.join('، ')}) کامل یا معتبر نیستند.`
        : 'وضعیت: پیکربندی نشده — زیرساخت اختیاری Authoritative DNS فعال نیست؛ بررسی مستقل DNS مرورگر به‌صورت جداگانه اجرا شد.';

    return {
      status: 'NOT_CONFIGURED',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        detailNoteFa,
        'طبق اصل صداقت فنی، بدون زیرساخت Authoritative DNS اختصاصی، نتیجهٔ این تست هرگز «موفق» یا «امن» اعلام نمی‌شود.',
      ],
      evidence: {
        runId: normalizedRunId,
        authoritativeConfigured: false,
        missingEnvVars: missingList,
        independentBrowserObservation: independentBrowserObservation || null,
      },
      limitations: dnsLimitations,
      errorCode: 'AUTHORITATIVE_DNS_NOT_CONFIGURED',
      source: 'Authoritative DNS Configuration Check',
      confidence: 'none',
      runId: normalizedRunId,
      authoritativeConfigured: false,
      missingEnvVars: missingList,
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: `${detailNoteFa} بدون سرور Authoritative DNS اختصاصی، نمی‌توان عدم نشت DNS را تأیید یا رد کرد.`,
      messageEn:
        'Not Configured: Optional Authoritative DNS infrastructure is not active. Independent browser DNS observation ran separately; cannot claim OS-level DNS safety without an authoritative collector.',
    };
  }

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای آزمون Authoritative DNS: ${errorMessage}`],
      evidence: { runId: normalizedRunId, authoritativeConfigured, errorMessage },
      limitations: dnsLimitations,
      errorCode: 'DNS_PROBE_ERROR',
      source: 'DNS Probe Service',
      confidence: 'none',
      runId: normalizedRunId,
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

  if (!isValidDnsRunId(normalizedRunId)) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: ['شناسهٔ اجرای تست (runId) نامعتبر یا خارج از قالب برچسب DNS است؛ امکان انتساب رویدادهای DNS به این اجرا وجود ندارد.'],
      evidence: { runId: normalizedRunId, authoritativeConfigured: true },
      limitations: dnsLimitations,
      errorCode: 'INVALID_RUN_ID',
      source: 'Authoritative DNS Collector',
      confidence: 'none',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: شناسهٔ یکتای اجرای تست (runId) برای تطبیق لاگ‌های DNS معتبر نیست.',
      messageEn: 'Inconclusive: Invalid or missing runId for authoritative DNS correlation.',
    };
  }

  if (!Array.isArray(resolvers) || resolvers.length === 0) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `درخواست‌های ساب‌دامین یکتای ${normalizedRunId} ارسال شدند، اما هیچ رکوردی در ثبت‌کنندهٔ Authoritative DNS دریافت نشد.`
      ],
      evidence: { runId: normalizedRunId, authoritativeConfigured: true, resolvers: [] },
      limitations: dnsLimitations,
      errorCode: 'NO_DNS_QUERIES_CAPTURED',
      source: 'Authoritative DNS Collector',
      confidence: 'low',
      runId: normalizedRunId,
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

  // Validate structural integrity of all resolver records:
  // 1. Mandatory runId on EVERY record, matching normalizedRunId exactly
  // 2. Mandatory canonical queryName (`p<N>.<runId>.<domain>`) matching normalizedRunId (and dnsLeakDomain if provided)
  // 3. Mandatory observedAt timestamp within 5-minute freshness window
  // 4. observationMethod === 'authoritative_dns_log' and globally routable public IP
  const hasRunIdOrQnameMismatch = resolvers.some(r => {
    if (!r || typeof r.runId !== 'string' || r.runId.trim().toLowerCase() !== normalizedRunId.toLowerCase()) {
      return true;
    }
    const rawQname =
      typeof r.queryName === 'string'
        ? r.queryName
        : typeof (r as any).qname === 'string'
          ? (r as any).qname
          : '';
    const parsedQname = parseDnsLeakProbeQname(rawQname, dnsLeakDomain);
    if (!parsedQname.valid || parsedQname.runId !== normalizedRunId.toLowerCase()) {
      return true;
    }
    return false;
  });
  if (hasRunIdOrQnameMismatch) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: ['برخی از رکوردهای Resolver دریافت‌شده فاقد runId یا queryName معتبر در قالب p<N>.<runId>.<domain> هستند یا با شناسهٔ اجرای فعلی تطابق ندارند.'],
      evidence: { runId: normalizedRunId, resolvers },
      limitations: dnsLimitations,
      errorCode: 'RUN_ID_MISMATCH',
      source: 'Authoritative DNS Collector',
      confidence: 'none',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: عدم وجود یا عدم تطابق شناسهٔ اجرا (runId) یا قالب نام پرس‌وجو (QNAME) در رویدادهای دریافت‌شده از سرور DNS.',
      messageEn: 'Inconclusive: Resolver event runId or canonical queryName is missing or does not match the active test runId.',
    };
  }

  const nowMs = Date.now();
  const MAX_DNS_OBSERVATION_AGE_MS = 5 * 60 * 1000; // 5 minutes session freshness window
  const MAX_FUTURE_SKEW_MS = 60 * 1000; // 1 minute clock skew tolerance

  const hasStaleOrInvalidTimestamp = resolvers.some(r => {
    if (!r || typeof r.observedAt !== 'string' || r.observedAt.trim() === '') return true;
    const parsedMs = Date.parse(r.observedAt);
    if (!Number.isFinite(parsedMs)) return true;
    const ageMs = nowMs - parsedMs;
    return ageMs > MAX_DNS_OBSERVATION_AGE_MS || ageMs < -MAX_FUTURE_SKEW_MS;
  });

  if (hasStaleOrInvalidTimestamp) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: ['برخی از رکوردهای Resolver فاقد زمان مشاهده (observedAt)، دارای زمان نامعتبر یا خارج از بازهٔ ۵ دقیقه‌ای نشست هستند.'],
      evidence: { runId: normalizedRunId, resolvers },
      limitations: dnsLimitations,
      errorCode: 'STALE_DNS_OBSERVATION',
      source: 'Authoritative DNS Collector',
      confidence: 'none',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: 0,
      resolvers: [],
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: رکوردهای DNS فاقد زمان ثبت معتبر، قدیمی یا خارج از بازهٔ زمانی مجاز این نشست هستند.',
      messageEn: 'Inconclusive: Observed DNS records are missing timestamps, stale, or outside the valid session time window.',
    };
  }

  const allAuthoritativeAndValidIp = resolvers.every(
    r =>
      r &&
      r.observationMethod === 'authoritative_dns_log' &&
      typeof r.primaryIp === 'string' &&
      isGloballyRoutablePublicIp(r.primaryIp)
  );

  if (!allAuthoritativeAndValidIp) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        'رکوردهای Resolver فاقد آدرس IP عمومی قابل مسیریابی معتبر یا روش مشاهدهٔ authoritative_dns_log هستند.'
      ],
      evidence: { runId: normalizedRunId, resolvers },
      limitations: dnsLimitations,
      errorCode: 'INVALID_RESOLVER_EVIDENCE',
      source: 'Authoritative DNS Collector',
      confidence: 'low',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: resolvers.length,
      resolvers,
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: آدرس IP یا ساختار شواهد Resolverهای دریافت‌شده برای داوری معتبر نیست.',
      messageEn: 'Inconclusive: Observed resolver entries lack valid globally routable public IPs or authoritative log provenance.',
    };
  }

  // Deduplicate resolvers by canonical primaryIp to avoid counting duplicate UDP retries twice
  const deduplicatedResolvers: DnsResolver[] = [];
  const seenResolverIps = new Set<string>();
  for (const r of resolvers) {
    const canon = canonicalizeIp(r.primaryIp);
    if (!canon || seenResolverIps.has(canon)) continue;
    seenResolverIps.add(canon);
    deduplicatedResolvers.push({
      ...r,
      primaryIp: canon,
    });
  }
  resolvers = deduplicatedResolvers;

  // Require valid primary egress ipDetails for comparison
  const egressIpCanonical =
    ipDetails && ipDetails.status !== 'ERROR' && ipDetails.ip
      ? canonicalizeIp(ipDetails.ip)
      : null;

  if (!ipDetails || !egressIpCanonical) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        'آدرس IP خروجی مرجع (ipDetails) برای مقایسه با Resolverهای مشاهده‌شده در دسترس نیست.'
      ],
      evidence: { runId: normalizedRunId, resolvers, ipDetailsAvailable: false },
      limitations: dnsLimitations,
      errorCode: 'MISSING_REFERENCE_IP_FOR_DNS',
      source: 'Authoritative DNS Collector',
      confidence: 'low',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: resolvers.length,
      resolvers,
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: به دلیل نبود اطلاعات معتبر از آدرس IP خروجی، امکان مقایسه و تأیید عدم نشت DNS وجود ندارد.',
      messageEn: 'Inconclusive: Reference egress IP details are missing; cannot compare authoritative resolvers.',
    };
  }

  const egressAsn = normalizeAsnString(ipDetails.asn);
  const egressIsp = (ipDetails.isp || ipDetails.org || '').trim().toLowerCase();
  const egressCountry = extractIsoCountryCode(ipDetails.countryCode);

  let hasConfirmedLeak = false;
  let hasInconclusiveResolver = false;

  for (const r of resolvers) {
    const rIpCanonical = canonicalizeIp(r.primaryIp)!;
    const sameIpAsEgress = rIpCanonical === egressIpCanonical;
    const rAsn = normalizeAsnString(r.asn);
    const rIsp = (r.isp || '').trim().toLowerCase();
    const rCountry = extractIsoCountryCode(r.countryCode || r.location);

    // 1. Exact IP match with primary egress IP is verified self-resolver
    if (sameIpAsEgress) {
      continue;
    }

    // 2. Check if sufficient comparison metadata exists on this resolver
    const hasStructuredMetadata = Boolean(rAsn || rIsp);
    if (!hasStructuredMetadata) {
      hasInconclusiveResolver = true;
      continue;
    }

    // 3. Same ASN as primary egress IP
    if (rAsn && egressAsn && rAsn === egressAsn) {
      // If country explicitly conflicts even within same ASN, treat as inconclusive (country difference alone is not a leak, nor guaranteed pass)
      if (rCountry && rCountry !== 'ANYCAST' && egressCountry && rCountry !== egressCountry) {
        hasInconclusiveResolver = true;
      }
      continue;
    }

    // 4. Verified Encrypted DoH resolver with explicit ASN & ISP metadata
    if (r.isEncryptedDoH === true && rAsn && rIsp) {
      if (rCountry && rCountry !== 'ANYCAST' && egressCountry && rCountry !== egressCountry) {
        hasInconclusiveResolver = true;
      }
      continue;
    }

    // 5. Check for confirmed structural leak:
    // Must NOT be country difference alone! Requires:
    // - explicitly unencrypted resolver (`r.isEncryptedDoH === false`),
    // - both `rAsn` and `egressAsn` present and different (`rAsn !== egressAsn`),
    // - explicit ISP metadata (`rIsp`) differing from `egressIsp`,
    // - AND country conflict (`rCountry && egressCountry && rCountry !== egressCountry && rCountry !== 'ANYCAST'`) with non-datacenter/ISP divergence.
    const hasAsnConflict = Boolean(rAsn && egressAsn && rAsn !== egressAsn);
    const hasIspConflict = Boolean(rIsp && (!egressIsp || rIsp !== egressIsp));
    const hasCountryConflict = Boolean(
      rCountry && rCountry !== 'ANYCAST' && egressCountry && rCountry !== egressCountry
    );

    if (r.isEncryptedDoH === false && hasAsnConflict && hasIspConflict && hasCountryConflict) {
      hasConfirmedLeak = true;
    } else {
      hasInconclusiveResolver = true;
    }
  }

  if (hasConfirmedLeak) {
    return {
      status: 'LEAK_DETECTED',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `تعداد ${resolvers.length} IP Resolver مشاهده‌شده در Authoritative DNS برای شناسهٔ ${normalizedRunId} ثبت شد که بر پایهٔ شواهد ساختاری (عدم تطابق ASN، ISP، کشور و عدم رمزنگاری DoH) با مسیر خروجی مغایرت دارند.`
      ],
      evidence: {
        runId: normalizedRunId,
        authoritativeConfigured: true,
        resolvers,
        egressIp: egressIpCanonical,
        egressAsn,
        egressCountry,
      },
      limitations: dnsLimitations,
      errorCode: null,
      source: 'Authoritative DNS Collector',
      confidence: 'high',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: resolvers.length,
      resolvers,
      isLeaking: true,
      independentBrowserObservation,
      messageFa: 'نشت شناسایی شد: بر اساس مقایسهٔ ساختاری ASN، ISP و مشخصات IPهای Resolver مشاهده‌شده در Authoritative DNS، درخواست‌های DNS خارج از مسیر تونل ارسال شده‌اند.',
      messageEn: 'Leak Detected: Structural comparison of ASN, ISP, and observed resolver IPs in authoritative DNS logs confirms DNS traffic outside the expected egress network.',
    };
  }

  if (hasInconclusiveResolver) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Authoritative DNS Leak & Resolver Probe',
      startedAt,
      completedAt,
      observations: [
        `تعداد ${resolvers.length} IP Resolver مشاهده‌شده برای شناسهٔ ${normalizedRunId} ثبت شد، اما شواهد ساختاری کافی برای اثبات تطابق کامل یا نشت قطعی (مانند صرفاً تفاوت کشور یا نبود متادیتای کامل ASN/ISP) وجود ندارد.`
      ],
      evidence: {
        runId: normalizedRunId,
        authoritativeConfigured: true,
        resolvers,
        egressIp: egressIpCanonical,
        egressAsn,
        egressCountry,
      },
      limitations: dnsLimitations,
      errorCode: 'INSUFFICIENT_DNS_COMPARISON_EVIDENCE',
      source: 'Authoritative DNS Collector',
      confidence: 'low',
      runId: normalizedRunId,
      authoritativeConfigured: true,
      missingEnvVars: [],
      detectedResolversCount: resolvers.length,
      resolvers,
      isLeaking: null,
      independentBrowserObservation,
      messageFa: 'نامشخص: IPهای Resolver در سرور Authoritative مشاهده شدند، اما اطلاعات مقایسه‌ای کافی نیست یا صرفاً تفاوت جغرافیایی بدون شواهد قطعی نشت ISP وجود دارد.',
      messageEn: 'Inconclusive: Authoritative resolver IP(s) observed, but comparison metadata is insufficient to prove either leak-free routing or a confirmed leak.',
    };
  }

  return {
    status: 'PASS',
    testName: 'Authoritative DNS Leak & Resolver Probe',
    startedAt,
    completedAt,
    observations: [
      `تعداد ${resolvers.length} IP Resolver مشاهده‌شده از طریق لاگ واقعی Authoritative DNS برای شناسهٔ ${normalizedRunId} با تطابق ساختاری تأیید شد.`
    ],
    evidence: {
      runId: normalizedRunId,
      authoritativeConfigured: true,
      resolvers,
      egressIp: egressIpCanonical,
      egressAsn,
    },
    limitations: dnsLimitations,
    errorCode: null,
    source: 'Authoritative DNS Collector',
    confidence: 'high',
    runId: normalizedRunId,
    authoritativeConfigured: true,
    missingEnvVars: [],
    detectedResolversCount: resolvers.length,
    resolvers,
    isLeaking: false,
    independentBrowserObservation,
    messageFa: `موفق: آزمایش Authoritative DNS با شواهد ساختاری معتبر تکمیل شد (${resolvers.length} IP Resolver مشاهده‌شده منطبق ثبت گردید).`,
    messageEn: `Pass: Authoritative DNS probe completed with ${resolvers.length} structurally verified observed resolver IP(s).`,
  };
}

/**
 * Probabilistic VPN / Proxy / Datacenter Classification with explicit limitations.
 * Strictly separates probabilistic ASN/datacenter classification (`isDatacenterIp`) from network leak status (`status`).
 * Detecting a datacenter IP alone NEVER proves an active VPN tunnel or absence of leaks (never returns PASS from datacenter classification alone).
 */
export function evaluateVpnHeuristic(
  ipDetails: IpDetails | null,
  dnsLeak: DnsLeakResult | null
): VpnProxyResult {
  const now = new Date().toISOString();
  const vpnLimitations = [
    'تشخیص VPN/دیتاسنتر صرفاً یک طبقه‌بندی احتمالی مبتنی بر ASN و نام سازمان ارائه‌دهندهٔ IP خروجی است و قطعی نیست (تشخیص IP دیتاسنتر به‌تنهایی فعال بودن VPN یا امنیت اتصال را اثبات نمی‌کند).',
    'نوع پروتکل تونل (مانند WireGuard، OpenVPN، IKEv2 یا VLESS) و اندازهٔ واقعی MTU از طریق مرورگر وب و لایهٔ HTTP قابل اثبات فنی نیست.'
  ];

  if (!ipDetails || !ipDetails.ip || ipDetails.status === 'ERROR' || !canonicalizeIp(ipDetails.ip)) {
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

  const isDatacenter: boolean | null =
    typeof ipDetails.isDatacenter === 'boolean' ? ipDetails.isDatacenter : null;
  const clientServerMismatch = ipDetails.ipMismatchDetected === true;
  const hasDnsLeak = dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.isLeaking === true;

  // Separate probabilistic ASN classification from leak status:
  // - If a path mismatch or DNS leak is observed, status is WARNING.
  // - Otherwise, browser-based VPN tunnel verification is INCONCLUSIVE (even if the IP belongs to a datacenter ASN!).
  let status: TestStatus = 'INCONCLUSIVE';
  let confidence: ConfidenceLevel = isDatacenter !== null ? 'medium' : 'low';

  if (clientServerMismatch || hasDnsLeak) {
    status = 'WARNING';
    confidence = 'high';
  }

  const observations: string[] = [
    isDatacenter === true
      ? `آدرس IP خروجی (${ipDetails.ip}) بر اساس ASN (${ipDetails.asn || 'نامشخص'}) و سازمان (${ipDetails.isp || 'نامشخص'}) احتمالاً متعلق به مرکز داده / هاستینگ است، اما صرفاً دیتاسنتر بودن IP اثبات‌کنندهٔ فعال بودن VPN یا نبود نشت نیست.`
      : isDatacenter === false
        ? `آدرس IP خروجی (${ipDetails.ip}) نشانگرهای شناخته‌شدهٔ مراکز داده را ندارد و احتمالاً متعلق به ISP مسکونی/همراه است.`
        : `متادیتای ASN برای طبقه‌بندی نوع شبکهٔ آدرس ${ipDetails.ip} کافی نیست.`,
    'پروتکل تونل (WireGuard/OpenVPN/...) و وضعیت رمزنگاری سطح سیستم‌عامل از روی درخواست HTTP قابل اثبات نیست.'
  ];

  if (clientServerMismatch) {
    observations.push(
      `مغایرت مسیر (Split-Tunnel / Proxy Rule): آدرس مشاهده‌شده از کلاینت (${ipDetails.clientObservedIp}) با آدرس مشاهده‌شده در سرور (${ipDetails.serverObservedIp}) تفاوت دارد.`
    );
  }
  if (hasDnsLeak) {
    observations.push('نشت DNS در تست Authoritative گزارش شده است که با تونل کامل هم‌خوانی ندارد.');
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
      hasDnsLeak,
    },
    limitations: vpnLimitations,
    errorCode: null,
    source: 'ASN / Organization Heuristic Classifier',
    confidence,
    score: null,
    isDatacenterIp: isDatacenter,
    isTorNode: ipDetails.connectionType === 'Tor Exit Node',
    isKnownProxy: null,
    mismatchDnsCountry: dnsLeak?.isLeaking ?? null,
    encryptionStrength: 'غیرقابل اندازه‌گیری از لایه مرورگر (HTTPS/TLS فعال)',
    protocolType:
      'غیرقابل اثبات از روی IP (طبقه‌بندی احتمالی ASN: ' +
      (isDatacenter === true ? 'خروجی دیتاسنتر' : isDatacenter === false ? 'ISP مستقیم' : 'نامشخص') +
      ')',
    protocolDetails: {
      name: 'غیرقابل اثبات از طریق مرورگر (Unprovable via Web)',
      code: 'unknown_protocol',
      isProvableFromBrowser: false,
      encryptionNameFa: 'نامشخص (فقط TLS مرورگر قابل مشاهده است)',
      estimatedMtu: null,
      obfuscationStatusFa: 'غیرقابل تشخیص بدون دسترسی سطح پکت',
      descriptionFa: 'مشاهدهٔ IP خروجی فقط مالک شبکهٔ مقصد (ASN) را مشخص می‌کند و فعال بودن VPN یا پروتکل تونل (WireGuard، OpenVPN، V2Ray یا L2TP) را اثبات نمی‌کند.',
    },
    messageFa:
      clientServerMismatch || hasDnsLeak
        ? `هشدار مغایرت مسیر شبکه: با وجود آدرس خروجی (${ipDetails.ip})، عدم تطابق در مسیر IP یا نشت DNS مشاهده شد.`
        : isDatacenter === true
          ? `طبقه‌بندی احتمالی ASN: مرکز داده (${ipDetails.isp || ipDetails.asn}). وضعیت تونل: نامشخص (تشخیص IP دیتاسنتر به‌تنهایی فعال بودن VPN یا امنیت اتصال را اثبات نمی‌کند).`
          : `طبقه‌بندی احتمالی ASN: شبکه ISP (${ipDetails.isp || ipDetails.asn || 'نامشخص'}). وضعیت تونل از طریق مرورگر قابل اثبات قطعی نیست.`,
    messageEn:
      clientServerMismatch || hasDnsLeak
        ? `Warning: Network path or DNS mismatch observed alongside egress IP (${ipDetails.ip}).`
        : isDatacenter === true
          ? `Probabilistic ASN Classification: Datacenter (${ipDetails.isp || ipDetails.asn}). Tunnel status is Inconclusive (datacenter IP alone does not prove active VPN or leak-free security).`
          : `Probabilistic ASN Classification: Residential/Mobile ISP (${ipDetails.isp || ipDetails.asn || 'Unknown'}). Tunnel status cannot be proven from browser.`,
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
    serviceName: 'HTTP Web / TCP-80 Service',
    category: 'router_admin',
    descriptionFa: 'سرویس وب HTTP (وب‌سرور، پروکسی یا رابط وب؛ باز بودن پورت به‌تنهایی افشای پنل روتر را اثبات نمی‌کند)',
    descriptionEn: 'HTTP TCP Service (Web server, proxy, or web UI; open port alone does not prove router admin exposure)',
    riskLevel: 'high',
  },
  {
    port: 443,
    protocol: 'TCP',
    serviceName: 'HTTPS / TLS TCP-443 Service',
    category: 'router_admin',
    descriptionFa: 'سرویس رمزنگاری‌شده TLS/HTTPS (وب‌سرور، گره VPN یا رابط وب؛ نیازمند بررسی لایه کاربرد)',
    descriptionEn: 'TLS/HTTPS TCP Service (Web server, VPN node, or web interface)',
    riskLevel: 'medium',
  },
  {
    port: 8080,
    protocol: 'TCP',
    serviceName: 'HTTP Alternate / Proxy TCP-8080',
    category: 'router_admin',
    descriptionFa: 'پورت جایگزین وب HTTP یا پروکسی (صرفاً پاسخ هندشیک TCP بررسی می‌شود)',
    descriptionEn: 'Alternative HTTP or Proxy TCP Port (TCP handshake probe only)',
    riskLevel: 'high',
  },
  {
    port: 8291,
    protocol: 'TCP',
    serviceName: 'TCP/8291 (MikroTik Winbox Candidate)',
    category: 'router_admin',
    descriptionFa: 'پورت پیش‌فرض Winbox در روترهای MikroTik (بدون بررسی بنر پروتکل، نوع سرویس قطعی نیست)',
    descriptionEn: 'Default MikroTik Winbox TCP Port (service identity not banner-verified)',
    riskLevel: 'critical',
  },
  {
    port: 22,
    protocol: 'TCP',
    serviceName: 'SSH / TCP-22 Service',
    category: 'remote_access',
    descriptionFa: 'پورت پیش‌فرض پوسته راه دور SSH (روی سرور یا تجهیزات شبکه)',
    descriptionEn: 'Default SSH Remote Access TCP Port (Server or network device)',
    riskLevel: 'high',
  },
  {
    port: 23,
    protocol: 'TCP',
    serviceName: 'Telnet / TCP-23 Service',
    category: 'remote_access',
    descriptionFa: 'پورت پیش‌فرض سرویس متنی غیررمزنگاری‌شده Telnet',
    descriptionEn: 'Default Unencrypted Telnet TCP Port',
    riskLevel: 'critical',
  },
  {
    port: 21,
    protocol: 'TCP',
    serviceName: 'FTP / TCP-21 Service',
    category: 'file_share',
    descriptionFa: 'پورت پیش‌فرض انتقال فایل FTP',
    descriptionEn: 'Default FTP File Transfer TCP Port',
    riskLevel: 'high',
  },
  {
    port: 1080,
    protocol: 'TCP',
    serviceName: 'SOCKS / TCP-1080 Service',
    category: 'proxy_relay',
    descriptionFa: 'پورت پیش‌فرض پروکسی SOCKS (صرفاً پاسخ اتصال TCP بررسی می‌شود)',
    descriptionEn: 'Default SOCKS Proxy TCP Port',
    riskLevel: 'critical',
  },
];

/**
 * Evaluates TCP Port Exposure results strictly from real server-side TCP socket probes.
 * - Never fabricates open/closed port states when the client IP is local/loopback or unverifiable.
 * - Never confuses incomplete port lists or `not_tested` ports with all ports being closed (`PASS` requires all expected ports in `COMMON_SENSITIVE_PORTS` to have valid `closed` or `filtered_timeout` states and 0 `open` ports).
 * - Clarifies that an open TCP port alone does not prove router admin panel exposure (`confidence: 'medium'` on open ports).
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
    'این آزمایش صرفاً هندشیک TCP (SYN/ACK) از سمت سرور برنامه به آدرس IP عمومی مشاهده‌شدهٔ شما انجام می‌دهد و به دلیل امنیت (جلوگیری از SSRF) هرگز آدرس‌های دلخواه یا شبکهٔ داخلی اسکن نمی‌شوند.',
    'باز بودن یک پورت TCP (مانند 80 یا 443) به‌تنهایی اثبات‌کنندهٔ افشای پنل مدیریت روتر نیست؛ ممکن است متعلق به وب‌سرور، سرویس سرور VPN یا NAT اپراتور باشد.',
    'اگر پشت CGNAT اپراتور یا سرور خروجی VPN باشید، نتیجهٔ اسکن وضعیت فایروالِ IP خروجی فعلی را نشان می‌دهد و پورت‌های شبکهٔ داخلی (LAN) را از بیرون اینترنت رؤیت نمی‌کند.'
  ];

  const expectedPortNumbers = COMMON_SENSITIVE_PORTS.map(p => p.port);
  const providedByPort = new Map<number, PortProbeEntry>();
  if (Array.isArray(ports)) {
    for (const p of ports) {
      if (p && typeof p.port === 'number') {
        providedByPort.set(p.port, p);
      }
    }
  }

  // Merge with expected port definitions so any missing expected port is explicitly tracked as `not_tested`
  const mergedPorts: PortProbeEntry[] = COMMON_SENSITIVE_PORTS.map(def => {
    const found = providedByPort.get(def.port);
    if (!found) {
      return {
        ...def,
        state: 'not_tested',
        responseTimeMs: null,
      };
    }
    return {
      ...def,
      ...found,
    };
  });

  if (errorMessage) {
    return {
      status: 'ERROR',
      testName: 'Public Egress TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [`خطا در اجرای تست پورت‌های TCP: ${errorMessage}`],
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
      ports: mergedPorts.map(p => ({ ...p, state: 'not_tested', responseTimeMs: null })),
      messageFa: `خطا در بررسی پورت‌ها: ${errorMessage}. هیچ وضعیت ساختگی تولید نشد.`,
      messageEn: `Port exposure probe failed: ${errorMessage}.`,
    };
  }

  if (!canScanFromServer || !targetIp || isPrivateOrLocalAddress(targetIp)) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Public Egress TCP Port Exposure Probe',
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
      ports: mergedPorts.map(p => ({ ...p, state: 'not_tested', responseTimeMs: null })),
      messageFa:
        'نتیجه نامشخص (تست‌نشده): از آنجا که سرور برنامه به آدرس عمومی مستقیم سوکت کلاینت دسترسی ندارد (اتصال محلی یا پشت پروکسی غیرمعتمد)، اسکن پورت TCP اجرا نشد تا از اسکن اشتباه سرور جلوگیری شود.',
      messageEn:
        'Inconclusive (Not Tested): Server observed a local/untrusted socket IP; TCP port probing was skipped to prevent SSRF or self-scanning.',
    };
  }

  const openEntries = mergedPorts.filter(p => p.state === 'open');
  const closedEntries = mergedPorts.filter(p => p.state === 'closed');
  const filteredEntries = mergedPorts.filter(p => p.state === 'filtered_timeout');
  const notTestedEntries = mergedPorts.filter(
    p => p.state !== 'open' && p.state !== 'closed' && p.state !== 'filtered_timeout'
  );
  const openPorts = openEntries.map(p => p.port);
  const scannedCount = openEntries.length + closedEntries.length + filteredEntries.length;

  if (scannedCount === 0) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Public Egress TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: ['هیچ پورتی در این نوبت مورد سنجش قرار نگرفت.'],
      evidence: { targetIp, targetSource },
      limitations: portLimitations,
      errorCode: 'NO_PORTS_SCANNED',
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'none',
      targetIp,
      targetSource,
      canScanFromServer: true,
      scannedPortsCount: 0,
      openPortsCount: 0,
      closedPortsCount: 0,
      filteredPortsCount: 0,
      openPorts: [],
      isExposingSensitivePorts: null,
      ports: mergedPorts,
      messageFa: 'نتیجه نامشخص: هیچ دادهٔ معتبری از وضعیت پورت‌ها ثبت نشد.',
      messageEn: 'Inconclusive: No port probe results recorded.',
    };
  }

  const hasCriticalOpen = openEntries.some(p => p.riskLevel === 'critical');

  if (openEntries.length > 0) {
    return {
      status: hasCriticalOpen ? 'LEAK_DETECTED' : 'WARNING',
      testName: 'Public Egress TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [
        `روی آدرس خروجی ${targetIp} تعداد ${openEntries.length} پورت TCP (${openPorts.join(', ')}) به هندشیک اتصال پاسخ مثبت دادند.`,
        'توجه فنی: باز بودن پورت TCP صرفاً پذیرش اتصال در لایهٔ انتقال را نشان می‌دهد و به‌تنهایی اثبات‌کنندهٔ افشای پنل مدیریت روتر نیست.',
        ...openEntries.map(
          p => `پورت TCP/${p.port} (${p.serviceName}) باز است — زمان پاسخ هندشیک: ${p.responseTimeMs ?? 'نامشخص'} ms.`
        ),
      ],
      evidence: {
        targetIp,
        targetSource,
        openPorts,
        notTestedPorts: notTestedEntries.map(p => p.port),
        openServices: openEntries.map(p => ({ port: p.port, service: p.serviceName, rttMs: p.responseTimeMs })),
      },
      limitations: portLimitations,
      errorCode: null,
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'medium',
      targetIp,
      targetSource,
      canScanFromServer: true,
      scannedPortsCount: scannedCount,
      openPortsCount: openEntries.length,
      closedPortsCount: closedEntries.length,
      filteredPortsCount: filteredEntries.length,
      openPorts,
      isExposingSensitivePorts: true,
      ports: mergedPorts,
      messageFa: `پاسخ TCP روی پورت‌های (${openPorts.join(', ')}) در آدرس ${targetIp} مشاهده شد (درجه اطمینان نوع سرویس: متوسط — باز بودن پورت به‌تنهایی افشای پنل مدیریت روتر را اثبات نمی‌کند).`,
      messageEn: `Open TCP port(s) ${openPorts.join(', ')} detected on ${targetIp} (Medium confidence — open TCP handshake alone does not prove router admin panel exposure).`,
    };
  }

  // If no open ports were found, require ALL expected ports in COMMON_SENSITIVE_PORTS to have been tested (`not_tested` count === 0)
  const allExpectedPortsTested =
    notTestedEntries.length === 0 &&
    scannedCount === expectedPortNumbers.length &&
    expectedPortNumbers.every(portNum => {
      const entry = providedByPort.get(portNum);
      return entry && (entry.state === 'closed' || entry.state === 'filtered_timeout');
    });

  if (!allExpectedPortsTested) {
    return {
      status: 'INCONCLUSIVE',
      testName: 'Public Egress TCP Port Exposure Probe',
      startedAt,
      completedAt,
      observations: [
        `اسکن پورت ناقص است: از ${expectedPortNumbers.length} پورت مورد انتظار، تنها ${scannedCount} پورت نتیجهٔ معتبر دارند و ${notTestedEntries.length} پورت در وضعیت not_tested هستند.`,
        'پورت‌های تست‌نشده یا نتایج ناقص هرگز به عنوان بسته بودن تمام پورت‌ها (PASS) تلقی نمی‌شوند.'
      ],
      evidence: {
        targetIp,
        targetSource,
        scannedCount,
        expectedCount: expectedPortNumbers.length,
        notTestedPorts: notTestedEntries.map(p => p.port),
      },
      limitations: portLimitations,
      errorCode: 'INCOMPLETE_PORT_SCAN',
      source: 'Server TCP Socket Probe (/api/port-scan)',
      confidence: 'low',
      targetIp,
      targetSource,
      canScanFromServer: true,
      scannedPortsCount: scannedCount,
      openPortsCount: 0,
      closedPortsCount: closedEntries.length,
      filteredPortsCount: filteredEntries.length,
      openPorts: [],
      isExposingSensitivePorts: null,
      ports: mergedPorts,
      messageFa: `نتیجه نامشخص: تنها ${scannedCount} از ${expectedPortNumbers.length} پورت هدف بررسی شدند (${notTestedEntries.length} پورت بررسی‌نشده). برای صدور وضعیت موفق، بررسی کامل تمام پورت‌های مورد انتظار الزامی است.`,
      messageEn: `Inconclusive: Only ${scannedCount} of ${expectedPortNumbers.length} expected ports were tested (${notTestedEntries.length} not_tested). Cannot issue PASS on partial scan.`,
    };
  }

  return {
    status: 'PASS',
    testName: 'Public Egress TCP Port Exposure Probe',
    startedAt,
    completedAt,
    observations: [
      `تمامی ${scannedCount} پورت هدف بررسی‌شده روی آدرس ${targetIp} بسته (Closed: ${closedEntries.length}) یا توسط فایروال فیلتر (Filtered: ${filteredEntries.length}) هستند.`
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
    ports: mergedPorts,
    messageFa: `موفق (در محدودهٔ پورت‌های بررسی‌شده): از میان تمامی ${scannedCount} پورت بررسی‌شده روی آدرس ${targetIp}، هیچ پورت بازی مشاهده نشد.`,
    messageEn: `Pass (within probed port scope): 0 open ports detected out of all ${scannedCount} expected ports on ${targetIp}.`,
  };
}

/**
 * Evaluates Overall Status and Privacy Score strictly from verified evidence.
 * - UNSUPPORTED, ERROR, INCONCLUSIVE, and NOT_CONFIGURED never count as valid baseline test completion.
 * - If any mandatory baseline test (IP, Authoritative DNS, WebRTC) has not run or lacks valid PASS/WARNING evidence,
 *   `isScoreCalculable` is false, `privacyScore` is null, and `overallStatus` is never `PASS`.
 * - Score 100 and overallStatus `PASS` are only issued when all mandatory tests have valid `PASS` evidence and no warnings exist.
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
  const hasIpMismatch = ipDetails?. status === 'LEAK_DETECTED' || ipDetails?.ipMismatchDetected === true;
  const hasPortExposure = portLeak?.status === 'LEAK_DETECTED';

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
      reasonsFa.push(`پاسخ اتصال روی پورت‌های حساس (${portLeak?.openPorts.join(', ')}) در آدرس خروجی ثبت شد.`);
    }
    return {
      overallStatus: 'LEAK_DETECTED',
      privacyScore: Math.max(5, score),
      isScoreCalculable: true,
      reasonsFa,
    };
  }

  // 2. Check if primary IP inspection failed or lacks valid evidence
  const ipHasValidEvidence = Boolean(
    ipDetails &&
      (ipDetails.status === 'PASS' || ipDetails.status === 'WARNING') &&
      typeof ipDetails.ip === 'string' &&
      canonicalizeIp(ipDetails.ip) !== null
  );

  if (!ipDetails || ipDetails.status === 'ERROR') {
    reasonsFa.push('تست آدرس IP عمومی به دلیل خطا کامل نشد؛ امتیاز کلی امنیت قابل محاسبه نیست.');
    return {
      overallStatus: 'ERROR',
      privacyScore: null,
      isScoreCalculable: false,
      reasonsFa,
    };
  }

  // 3. Strictly verify that all mandatory baseline tests (IP, Authoritative DNS, WebRTC) have valid evidence.
  // UNSUPPORTED, ERROR, INCONCLUSIVE, and NOT_CONFIGURED are NEVER treated as passed baseline tests.
  const dnsHasValidEvidence = Boolean(
    dnsLeak &&
      (dnsLeak.status === 'PASS' || dnsLeak.status === 'WARNING') &&
      dnsLeak.authoritativeConfigured === true &&
      dnsLeak.detectedResolversCount > 0 &&
      dnsLeak.isLeaking === false
  );

  const webRtcHasValidEvidence = Boolean(
    webRtcLeak &&
      (webRtcLeak.status === 'PASS' || webRtcLeak.status === 'WARNING') &&
      webRtcLeak.isLeakingRealIp === false &&
      webRtcLeak.publicCandidates.length > 0
  );

  const portHasError = portLeak?.status === 'ERROR';

  if (!ipHasValidEvidence || !dnsHasValidEvidence || !webRtcHasValidEvidence || portHasError) {
    if (!ipHasValidEvidence) {
      reasonsFa.push(`شواهد تست آدرس IP عمومی کامل یا معتبر نیست (${ipDetails?.status || 'IDLE'}).`);
    }
    if (dnsLeak?.status === 'NOT_CONFIGURED') {
      reasonsFa.push('زیرساخت دامنهٔ Authoritative DNS تنظیم نشده است (NOT_CONFIGURED).');
    } else if (!dnsHasValidEvidence) {
      reasonsFa.push(`شواهد تست Authoritative DNS کامل یا قطعی نیست (${dnsLeak?.status || 'IDLE'}).`);
    }

    if (webRtcLeak?.status === 'UNSUPPORTED') {
      reasonsFa.push('پروتکل WebRTC در این محیط پشتیبانی نمی‌شود (UNSUPPORTED)؛ عدم پشتیبانی به‌منزلهٔ موفقیت تست نیست.');
    } else if (!webRtcHasValidEvidence) {
      reasonsFa.push(`شواهد تست WebRTC کامل یا قطعی نیست (${webRtcLeak?.status || 'IDLE'}).`);
    }

    if (portHasError) {
      reasonsFa.push('تست بررسی پورت‌ها با خطا مواجه شد (ERROR).');
    }

    const anyError =
      dnsLeak?.status === 'ERROR' || webRtcLeak?.status === 'ERROR' || portHasError;

    return {
      overallStatus: anyError ? 'ERROR' : 'INCONCLUSIVE',
      privacyScore: null,
      isScoreCalculable: false,
      reasonsFa: [
        ...reasonsFa,
        'به دلیل نبود شواهد معتبر در تمام تست‌های الزامی پایه، امتیاز عددی ۱۰۰ یا وضعیت PASS صادر نمی‌شود.'
      ],
    };
  }

  // 4. All mandatory baseline tests have valid, verified evidence! Calculate evidence-based score:
  let score = 100;
  let status: TestStatus = 'PASS';

  if (ipDetails.status === 'WARNING') {
    score -= 15;
    status = 'WARNING';
    reasonsFa.push('هشدار در بررسی آدرس IP خروجی ثبت شده است.');
  }

  if (dnsLeak!.status === 'WARNING') {
    score -= 15;
    status = 'WARNING';
    reasonsFa.push('هشدار در بررسی سرورهای Resolver ثبت شده است.');
  }

  if (webRtcLeak!.status === 'WARNING' || webRtcLeak!.localIps.length > 0) {
    score -= 10;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push('آدرس خصوصی شبکهٔ محلی (LAN) در نامزدهای WebRTC قابل مشاهده است.');
  }

  if (vpnProxy?.isDatacenterIp === false || ipDetails.isDatacenter === false) {
    score -= 20;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push('آدرس IP خروجی متعلق به شبکهٔ دیتاسنتر شناخته شده نیست (احتمال اتصال مستقیم ISP).');
  }

  if (vpnProxy?.status === 'WARNING') {
    score -= 15;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push('هشدار در ارزیابی مسیر شبکه / VPN ثبت شده است.');
  }

  if (portLeak?.status === 'WARNING' || (portLeak?.isExposingSensitivePorts === true && portLeak.openPorts.length > 0)) {
    score -= 15;
    if (status === 'PASS') status = 'WARNING';
    reasonsFa.push(`پورت‌های TCP باز (${portLeak.openPorts.join(', ')}) روی آدرس خروجی مشاهده شد.`);
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
        : ['آزمون‌های الزامی IP، Authoritative DNS و WebRTC با شواهد معتبر و بدون مشاهدهٔ نشت در محدودهٔ تست تکمیل شدند.'],
  };
}

/**
 * Compares observed public IP sources across client and server while accounting for IPv4 vs IPv6 dual-stack.
 * - Normalizes IPs canonically via `canonicalizeIp` and ignores private/local addresses.
 * - `ipMismatchDetected` is ONLY true when two or more distinct canonical public IPs of the SAME address family (IPv4 vs IPv4, or IPv6 vs IPv6) are observed.
 * - Observing one IPv4 and one IPv6 address across dual-stack endpoints is flagged as `isDualStackObserved: true`, NOT a false-positive split-tunnel IP leak.
 */
export function evaluateObservedIpSources(sources: ObservedIpSource[]): {
  uniquePublicIps: string[];
  uniqueIpv4s: string[];
  uniqueIpv6s: string[];
  ipMismatchDetected: boolean;
  isDualStackObserved: boolean;
} {
  const v4Set = new Set<string>();
  const v6Set = new Set<string>();
  const allPublicSet = new Set<string>();

  if (Array.isArray(sources)) {
    for (const s of sources) {
      if (!s || typeof s.ip !== 'string') continue;
      const canon = canonicalizeIp(s.ip);
      if (!canon || isPrivateOrLocalAddress(canon)) continue;
      allPublicSet.add(canon);
      if (canon.includes(':')) {
        v6Set.add(canon);
      } else {
        v4Set.add(canon);
      }
    }
  }

  const uniqueIpv4s = Array.from(v4Set);
  const uniqueIpv6s = Array.from(v6Set);
  const uniquePublicIps = Array.from(allPublicSet);
  const ipMismatchDetected = uniqueIpv4s.length > 1 || uniqueIpv6s.length > 1;
  const isDualStackObserved = uniqueIpv4s.length >= 1 && uniqueIpv6s.length >= 1;

  return {
    uniquePublicIps,
    uniqueIpv4s,
    uniqueIpv6s,
    ipMismatchDetected,
    isDualStackObserved,
  };
}

/**
 * Validates raw JSON output from Gemini AI Audit against a strict schema before returning it to the client.
 * Rejects malformed objects, non-array lists, out-of-range scores, or unrecognized status levels.
 */
export function validateAiAuditPayload(raw: unknown): {
  valid: boolean;
  audit?: Pick<
    AiAuditReport,
    'riskScore' | 'statusLevel' | 'summaryFa' | 'detailedAnalysisFa' | 'threatsFoundFa' | 'recommendationsFa'
  >;
  reason?: string;
} {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { valid: false, reason: 'Payload is not a plain object.' };
  }
  const obj = raw as Record<string, unknown>;

  const validStatusLevels = ['امن', 'هشدار', 'خطر نشت', 'نامشخص'] as const;
  if (
    typeof obj.statusLevel !== 'string' ||
    !(validStatusLevels as readonly string[]).includes(obj.statusLevel)
  ) {
    return { valid: false, reason: 'Invalid or missing statusLevel.' };
  }

  if (typeof obj.summaryFa !== 'string' || obj.summaryFa.trim().length === 0) {
    return { valid: false, reason: 'Invalid or empty summaryFa.' };
  }

  let riskScore: number | null = null;
  if (obj.riskScore !== null && obj.riskScore !== undefined) {
    if (
      typeof obj.riskScore !== 'number' ||
      !Number.isFinite(obj.riskScore) ||
      obj.riskScore < 0 ||
      obj.riskScore > 100
    ) {
      return { valid: false, reason: 'riskScore must be null or a finite number between 0 and 100.' };
    }
    riskScore = Math.round(obj.riskScore);
  }

  const isStringArray = (val: unknown): val is string[] =>
    Array.isArray(val) && val.every(item => typeof item === 'string');

  if (!isStringArray(obj.detailedAnalysisFa)) {
    return { valid: false, reason: 'detailedAnalysisFa must be an array of strings.' };
  }
  if (!isStringArray(obj.threatsFoundFa)) {
    return { valid: false, reason: 'threatsFoundFa must be an array of strings.' };
  }
  if (!isStringArray(obj.recommendationsFa)) {
    return { valid: false, reason: 'recommendationsFa must be an array of strings.' };
  }

  return {
    valid: true,
    audit: {
      riskScore,
      statusLevel: obj.statusLevel as AiAuditReport['statusLevel'],
      summaryFa: obj.summaryFa.trim(),
      detailedAnalysisFa: obj.detailedAnalysisFa.map(s => s.trim()).filter(Boolean),
      threatsFoundFa: obj.threatsFoundFa.map(s => s.trim()).filter(Boolean),
      recommendationsFa: obj.recommendationsFa.map(s => s.trim()).filter(Boolean),
    },
  };
}


