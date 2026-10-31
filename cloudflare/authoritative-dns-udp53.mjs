#!/usr/bin/env node
/**
 * شنوندهٔ سبک و بدون وابستگی Authoritative DNS روی پورت UDP/53 برای NETLeakGuard Pro V2
 *
 * چرا این جزء در کنار Cloudflare Workers الزامی است؟
 * - Cloudflare Workers و Cloudflare Pages صرفاً درخواست‌های HTTP/HTTPS (پورت 80/443) را پردازش می‌کنند
 *   و قادر به باز کردن سوکت UDP/53 به عنوان سرور Authoritative Name Server (NS) نیستند.
 * - همچنین در پلن رایگان DNS کلادفلر، دسترسی به لاگ درخواست‌های Recursive Resolverها (DNS Logpush) وجود ندارد.
 * - برای تشخیص واقعی نشت DNS، باید بسته‌های UDP/53 که توسط Recursive DNS Resolverِ کاربر (یا ISP/VPN او)
 *   برای استعلام زیردامنهٔ یکتای `<probe>.<runId>.<DNS_LEAK_DOMAIN>` ارسال می‌شوند دریافت گردند تا آدرس IP مبدأ بستهٔ UDP/53 استخراج شود.
 *
 * نحوهٔ کارکرد این اسکریپت:
 * ۱. روی پورت UDP/53 (یا پورت دلخواه آزمایشی `UDP_PORT`) گوش می‌دهد.
 * ۲. بسته‌های استاندارد DNS (RFC 1035) را تجزیه کرده و نام دامنهٔ استعلام‌شده (`qname`) را استخراج می‌کند.
 * ۳. بررسی می‌کند آیا `qname` متعلق به `<label>.<runId>.<DNS_LEAK_DOMAIN>` است و آیا `runId` ساختار معتبر دارد.
 * ۴. یک پاسخ حداقلی معتبر DNS (`NOERROR`) به Resolver برمی‌گرداند تا از تکرار بی‌مورد کوئری جلوگیری شود.
 * ۵. آدرس IP واقعی مبدأ بستهٔ UDP (`rinfo.address`) را به همراه `runId` از طریق HTTPS POST و هدر
 *    `Authorization: Bearer <DNS_COLLECTOR_API_TOKEN>` به مسیر `/api/dns-collector/ingest` در Cloudflare Worker ارسال می‌کند.
 *
 * متغیرهای محیطی مورد نیاز (هیچ کلیدی در کد ذخیره نشده است):
 *   DNS_LEAK_DOMAIN          : دامنهٔ اختصاصی تست که رکورد NS آن به IP این سرویس اشاره می‌کند
 *   WORKER_INGEST_URL        : آدرس مسیر `/api/dns-collector/ingest` روی Cloudflare Worker
 *   DNS_COLLECTOR_API_TOKEN  : توکن محرمانهٔ مشترک با Cloudflare Worker Secret
 *   UDP_PORT                 : پورت شنوندهٔ UDP (پیش‌فرض: 53)
 *   BIND_ADDRESS             : آدرس بایند سوکت (پیش‌فرض: 0.0.0.0)
 */

import dgram from 'node:dgram';
import https from 'node:https';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const DNS_LEAK_DOMAIN = (process.env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
const WORKER_INGEST_URL = (process.env.WORKER_INGEST_URL || '').trim();
const DNS_COLLECTOR_API_TOKEN = (process.env.DNS_COLLECTOR_API_TOKEN || '').trim();
const UDP_PORT = Number(process.env.UDP_PORT || 53);
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';

const DNS_SINGLE_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const DNS_PROBE_LABEL_REGEX = /^p([1-9][0-9]?)$/i;
const VALID_RUN_ID_REGEX = /^[a-z0-9](?:[a-z0-9-]{6,61}[a-z0-9])$/i;
const PREFIXED_UUID_TRAP_REGEX = /^p[0-9]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * استخراج نام دامنهٔ استعلام‌شده (QNAME) از بستهٔ باینری DNS طبق RFC 1035
 */
export function parseDnsQname(msg) {
  if (!Buffer.isBuffer(msg) || msg.length < 17) return null;
  const flags = msg.readUInt16BE(2);
  // بسته‌هایی که بیت QR=1 دارند (پاسخ DNS هستند نه پرس‌وجو) نباید پردازش شوند
  if ((flags & 0x8000) !== 0) return null;

  const qdCount = msg.readUInt16BE(4);
  if (qdCount < 1) return null;

  const labels = [];
  let offset = 12;
  while (offset < msg.length) {
    const len = msg[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    // عدم پذیرش پوینترهای فشرده‌سازی در بخش Question اول برای جلوگیری از حلقه و رعایت طول برچسب RFC 1035 (1..63)
    if ((len & 0xc0) !== 0 || len > 63) return null;
    if (offset + 1 + len > msg.length) return null;
    const label = msg.subarray(offset + 1, offset + 1 + len).toString('ascii');
    if (!DNS_SINGLE_LABEL_REGEX.test(label)) return null;
    labels.push(label);
    offset += 1 + len;
    if (labels.length > 16) return null;
  }

  if (offset + 4 > msg.length || labels.length === 0) return null;
  const qname = labels.join('.').toLowerCase();
  if (qname.length > 253) return null;

  const qtype = msg.readUInt16BE(offset);
  const qclass = msg.readUInt16BE(offset + 2);
  return {
    qname,
    labels: labels.map(l => l.toLowerCase()),
    qtype,
    qclass,
    questionEndOffset: offset + 4,
  };
}

/**
 * ساخت بستهٔ پاسخ DNS طبق RFC 1035 با کد وضعیت (RCODE) و بیت Authoritative (AA) مشخص
 * - RCODE=0 (NOERROR): برای QTYPE=1 (A) رکورد A=0.0.0.0 با TTL=10s برمی‌گرداند و برای سایر انواع مجاز (مانند AAAA) پاسخ NODATA (ANCOUNT=0) می‌دهد.
 * - RCODE=1 (FORMERR)، RCODE=3 (NXDOMAIN)، RCODE=4 (NOTIMP)، RCODE=5 (REFUSED)
 */
export function buildMinimalDnsResponse(queryBuf, questionEndOffset, qtype, rcode = 0, authoritative = true) {
  const txId = queryBuf.readUInt16BE(0);
  const reqFlags = queryBuf.readUInt16BE(2);
  const rdBit = reqFlags & 0x0100;
  const aaBit = authoritative ? 0x0400 : 0x0000;
  const safeRcode = rcode & 0x000f;
  // QR=1 (0x8000) | AA | RD | RCODE
  const respFlags = 0x8000 | aaBit | rdBit | safeRcode;

  const hasValidQuestion =
    typeof questionEndOffset === 'number' &&
    questionEndOffset > 12 &&
    questionEndOffset <= queryBuf.length;
  const questionSection = hasValidQuestion ? queryBuf.subarray(12, questionEndOffset) : Buffer.alloc(0);
  const includeARecord = safeRcode === 0 && authoritative && hasValidQuestion && qtype === 1;

  const header = Buffer.alloc(12);
  header.writeUInt16BE(txId, 0);
  header.writeUInt16BE(respFlags, 2);
  header.writeUInt16BE(hasValidQuestion ? 1 : 0, 4); // QDCOUNT
  header.writeUInt16BE(includeARecord ? 1 : 0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  if (!includeARecord) {
    return hasValidQuestion ? Buffer.concat([header, questionSection]) : header;
  }

  // پاسخ A رکورد با TTL=10 ثانیه به 0.0.0.0 صرفاً جهت بسته شدن سریع کوئری DNS
  const answer = Buffer.from([
    0xc0, 0x0c, // Pointer to QNAME at offset 12
    0x00, 0x01, // TYPE A
    0x00, 0x01, // CLASS IN
    0x00, 0x00, 0x00, 0x0a, // TTL = 10s
    0x00, 0x04, // RDLENGTH = 4
    0x00, 0x00, 0x00, 0x00  // RDATA = 0.0.0.0
  ]);

  return Buffer.concat([header, questionSection, answer]);
}

const SUPPORTED_DNS_QTYPES = new Set([
  1,  // A
  2,  // NS
  6,  // SOA
  16, // TXT
  28, // AAAA
  64, // SVCB
  65, // HTTPS
]);

/**
 * ارزیابی کامل بستهٔ ورودی UDP/53 و تعیین پاسخ استاندارد RFC 1035 و شواهد معتبر
 */
export function evaluateDnsQueryPacket(msg, allowedDomain = DNS_LEAK_DOMAIN) {
  if (!Buffer.isBuffer(msg) || msg.length < 12) {
    return { ignore: true, rcode: null, responseBuffer: null, observation: null };
  }

  const flags = msg.readUInt16BE(2);
  // ۱. نادیده گرفتن بسته‌های پاسخ (QR=1) جهت جلوگیری از حلقهٔ بازتاب UDP
  if ((flags & 0x8000) !== 0) {
    return { ignore: true, rcode: null, responseBuffer: null, observation: null };
  }

  // ۲. بررسی OPCODE استاندارد (OPCODE=0 برای QUERY)
  const opcode = (flags >> 11) & 0x0f;
  if (opcode !== 0) {
    return {
      ignore: false,
      rcode: 4, // NOTIMP
      responseBuffer: buildMinimalDnsResponse(msg, 0, 0, 4, false),
      observation: null,
    };
  }

  // ۳. تجزیهٔ بخش Question؛ در صورت ساختار معیوب، بازگرداندن FORMERR (RCODE=1)
  const parsed = parseDnsQname(msg);
  if (!parsed) {
    return {
      ignore: false,
      rcode: 1, // FORMERR
      responseBuffer: buildMinimalDnsResponse(msg, 0, 0, 1, false),
      observation: null,
    };
  }

  const normDomain = typeof allowedDomain === 'string'
    ? allowedDomain.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
    : '';
  const isInAllowedZone =
    normDomain.length > 0 &&
    (parsed.qname === normDomain || parsed.qname.endsWith(`.${normDomain}`));

  // ۴. پرس‌وجوهای خارج از دامنهٔ مجاز تست -> REFUSED (RCODE=5, AA=0)
  if (!isInAllowedZone) {
    return {
      ignore: false,
      rcode: 5, // REFUSED
      responseBuffer: buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype, 5, false),
      observation: null,
    };
  }

  // ۵. بررسی کلاس اینترنت (CLASS IN = 1) و انواع کوئری پشتیبانی‌شده؛ در غیر این صورت NOTIMP (RCODE=4)
  if (parsed.qclass !== 1 || !SUPPORTED_DNS_QTYPES.has(parsed.qtype)) {
    return {
      ignore: false,
      rcode: 4, // NOTIMP
      responseBuffer: buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype, 4, true),
      observation: null,
    };
  }

  // ۶. بررسی تطابق نام پرس‌وجو با قالب استاندارد `p<N>.<runId>.<allowedDomain>`
  const validatedQname = parseDnsLeakQname(parsed.qname, normDomain);
  if (!validatedQname) {
    // اگر خود دامنهٔ پایه برای NS/SOA استعلام شده باشد، پاسخ خالی NOERROR (NODATA) بدون ثبت شاهد برگردانده می‌شود
    if (parsed.qname === normDomain && (parsed.qtype === 2 || parsed.qtype === 6)) {
      return {
        ignore: false,
        rcode: 0,
        responseBuffer: buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype, 0, true),
        observation: null,
      };
    }
    // سایر زیردامنه‌های نامعتبر در داخل دامنهٔ تست -> NXDOMAIN (RCODE=3, AA=1)
    return {
      ignore: false,
      rcode: 3, // NXDOMAIN
      responseBuffer: buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype, 3, true),
      observation: null,
    };
  }

  // ۷. پرس‌وجوی معتبر برای `p<N>.<runId>.<allowedDomain>` -> NOERROR (RCODE=0, AA=1) و ثبت شاهد
  return {
    ignore: false,
    rcode: 0, // NOERROR
    responseBuffer: buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype, 0, true),
    observation: validatedQname,
  };
}

/**
 * تجزیه و اعتبارسنجی دقیق QNAME در قالب استاندارد `p<probeNumber>.<runId>.<allowedDomain>`
 * - الزام تعلق به دامنهٔ مجاز تست (`allowedDomain`)
 * - الزام وجود دقیقاً ۲ برچسب پیشوند (`p<N>` و `<runId>`)
 * - تفکیک دقیق شمارهٔ پروب (`1..99`) و شناسهٔ اجرا (`runId`) بدون هیچ پیشوند یا پسوند اضافی
 */
export function parseDnsLeakQname(rawQname, allowedDomain = DNS_LEAK_DOMAIN) {
  if (typeof rawQname !== 'string' || typeof allowedDomain !== 'string') return null;
  const normDomain = allowedDomain.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (normDomain.length < 3 || normDomain.length > 185 || normDomain.includes('..')) return null;
  const domainLabels = normDomain.split('.');
  if (
    domainLabels.length < 2 ||
    !domainLabels.every(l => l.length >= 1 && l.length <= 63 && DNS_SINGLE_LABEL_REGEX.test(l)) ||
    domainLabels[domainLabels.length - 1].length < 2 ||
    /^\d+$/.test(domainLabels[domainLabels.length - 1])
  ) {
    return null;
  }

  const trimmedQname = rawQname.trim().toLowerCase();
  const qname = trimmedQname.endsWith('.') ? trimmedQname.slice(0, -1) : trimmedQname;
  if (!qname || qname.length > 253 || qname.startsWith('.') || qname.includes('..')) return null;

  const suffix = `.${normDomain}`;
  if (!qname.endsWith(suffix)) return null;

  const prefix = qname.slice(0, qname.length - suffix.length);
  if (!prefix) return null;

  const prefixParts = prefix.split('.');
  // قالب مجاز دقیقاً ۲ برچسب پیشوند دارد: <probeLabel>.<runId>
  if (prefixParts.length !== 2) return null;

  const [probeLabel, candidateRunId] = prefixParts;
  const probeMatch = probeLabel.match(DNS_PROBE_LABEL_REGEX);
  if (!probeMatch) return null;

  if (
    candidateRunId.length < 8 ||
    candidateRunId.length > 63 ||
    !VALID_RUN_ID_REGEX.test(candidateRunId) ||
    PREFIXED_UUID_TRAP_REGEX.test(candidateRunId)
  ) {
    return null;
  }

  return {
    qname,
    probeLabel,
    probeNumber: Number(probeMatch[1]),
    runId: candidateRunId,
    baseDomain: normDomain,
  };
}

/**
 * استخراج شناسهٔ دقیق runId (بدون پیشوند و پسوند) از زیردامنهٔ `p<N>.<runId>.<DNS_LEAK_DOMAIN>`
 */
export function extractRunIdFromQname(qname, allowedDomain = DNS_LEAK_DOMAIN) {
  const parsed = parseDnsLeakQname(qname, allowedDomain);
  return parsed ? parsed.runId : null;
}

/**
 * ارسال امن مشاهدهٔ UDP/53 به مسیر `/api/dns-collector/ingest` در Cloudflare Worker
 */
function forwardObservationToWorker(payload) {
  try {
    const targetUrl = new URL(WORKER_INGEST_URL);
    const bodyStr = JSON.stringify(payload);
    const client = targetUrl.protocol === 'https:' ? https : http;

    const req = client.request(
      targetUrl,
      {
        method: 'POST',
        timeout: 4000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          Authorization: `Bearer ${DNS_COLLECTOR_API_TOKEN}`,
        },
      },
      res => {
        res.resume();
      }
    );

    req.on('error', () => {
      // خطاهای شبکه در ارسال لاگ باعث توقف شنوندهٔ UDP نمی‌شوند
    });
    req.on('timeout', () => {
      req.destroy();
    });
    req.write(bodyStr);
    req.end();
  } catch {
    // نادیده گرفتن خطاهای غیرمنتظره در ارسال پس‌زمینه
  }
}

export function isUdp53ResponderConfigured(env = process.env) {
  const domain = String(env?.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const ingestUrl = String(env?.WORKER_INGEST_URL || '').trim();
  const token = String(env?.DNS_COLLECTOR_API_TOKEN || '').trim();
  const configured = Boolean(domain && ingestUrl && token && isValidBaseDomain(domain));
  return {
    configured,
    domain: configured ? domain : null,
  };
}

const isMainModule =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMainModule) {
  if (!DNS_LEAK_DOMAIN || !WORKER_INGEST_URL || !DNS_COLLECTOR_API_TOKEN || !isValidBaseDomain(DNS_LEAK_DOMAIN)) {
    console.log(
      '[Authoritative-UDP53] وضعیت: پیکربندی نشده (غیرفعال) — متغیرهای اختیاری شنوندهٔ UDP/53 تنظیم نشده‌اند؛ سرویس بدون خطا متوقف شد.'
    );
    process.exit(0);
  }

  const server = dgram.createSocket('udp4');

  server.on('message', (msg, rinfo) => {
    const decision = evaluateDnsQueryPacket(msg, DNS_LEAK_DOMAIN);
    if (decision.ignore || !decision.responseBuffer) return;

    server.send(decision.responseBuffer, rinfo.port, rinfo.address);

    if (decision.observation && rinfo?.address) {
      forwardObservationToWorker({
        runId: decision.observation.runId,
        resolverIp: rinfo.address,
        qname: decision.observation.qname,
        probeNumber: decision.observation.probeNumber,
        observedAt: new Date().toISOString(),
      });
    }
  });

  server.on('listening', () => {
    const addr = server.address();
    console.log(
      `[Authoritative-UDP53] شنوندهٔ Authoritative DNS برای دامنهٔ ${DNS_LEAK_DOMAIN} روی ${addr.address}:${addr.port} فعال شد.`
    );
  });

  server.bind(UDP_PORT, BIND_ADDRESS);
}

