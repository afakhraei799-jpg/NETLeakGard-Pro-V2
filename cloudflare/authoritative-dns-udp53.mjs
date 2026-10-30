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

const DNS_LEAK_DOMAIN = (process.env.DNS_LEAK_DOMAIN || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
const WORKER_INGEST_URL = (process.env.WORKER_INGEST_URL || '').trim();
const DNS_COLLECTOR_API_TOKEN = (process.env.DNS_COLLECTOR_API_TOKEN || '').trim();
const UDP_PORT = Number(process.env.UDP_PORT || 53);
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';

if (!DNS_LEAK_DOMAIN || !WORKER_INGEST_URL || !DNS_COLLECTOR_API_TOKEN) {
  console.error(
    '[Authoritative-UDP53] خطا: متغیرهای محیطی DNS_LEAK_DOMAIN، WORKER_INGEST_URL و DNS_COLLECTOR_API_TOKEN باید تنظیم شوند.'
  );
  process.exit(1);
}

const VALID_RUN_ID_REGEX = /^[a-zA-Z0-9-]{8,64}$/;

/**
 * استخراج نام دامنهٔ استعلام‌شده (QNAME) از بستهٔ باینری DNS طبق RFC 1035
 */
function parseDnsQname(msg) {
  if (!Buffer.isBuffer(msg) || msg.length < 17) return null;
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
    // عدم پذیرش پوینترهای فشرده‌سازی در بخش Question اول برای جلوگیری از حلقه
    if ((len & 0xc0) !== 0) return null;
    if (offset + 1 + len > msg.length) return null;
    const label = msg.subarray(offset + 1, offset + 1 + len).toString('ascii');
    labels.push(label);
    offset += 1 + len;
    if (labels.length > 16) return null;
  }

  if (offset + 4 > msg.length || labels.length === 0) return null;
  const qtype = msg.readUInt16BE(offset);
  const qclass = msg.readUInt16BE(offset + 2);
  return {
    qname: labels.join('.').toLowerCase(),
    labels: labels.map(l => l.toLowerCase()),
    qtype,
    qclass,
    questionEndOffset: offset + 4,
  };
}

/**
 * ساخت بستهٔ پاسخ DNS حداقلی (NOERROR، Authoritative Answer، بدون رکورد اضافی یا همراه با A=127.0.0.1 برای جلوگیری از Timeout کلاینت)
 */
function buildMinimalDnsResponse(queryBuf, questionEndOffset, qtype) {
  const txId = queryBuf.readUInt16BE(0);
  const reqFlags = queryBuf.readUInt16BE(2);
  const rdBit = reqFlags & 0x0100;
  // QR=1 (0x8000), AA=1 (0x0400), RCODE=0 (NOERROR)
  const respFlags = 0x8400 | rdBit;

  const questionSection = queryBuf.subarray(12, questionEndOffset);
  const includeARecord = qtype === 1; // A record query

  const header = Buffer.alloc(12);
  header.writeUInt16BE(txId, 0);
  header.writeUInt16BE(respFlags, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT = 1
  header.writeUInt16BE(includeARecord ? 1 : 0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10); // ARCOUNT

  if (!includeARecord) {
    return Buffer.concat([header, questionSection]);
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

/**
 * استخراج شناسهٔ runId از زیردامنهٔ `<probe>.<runId>.<DNS_LEAK_DOMAIN>`
 */
function extractRunIdFromQname(qname) {
  const suffix = `.${DNS_LEAK_DOMAIN}`;
  if (!qname.endsWith(suffix)) return null;
  const prefix = qname.slice(0, qname.length - suffix.length);
  const parts = prefix.split('.').filter(Boolean);
  // انتظار می‌رود آخرین بخشِ پیشوند، runId باشد: <probeLabel>.<runId>
  if (parts.length < 1) return null;
  const candidateRunId = parts[parts.length - 1];
  return VALID_RUN_ID_REGEX.test(candidateRunId) ? candidateRunId : null;
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

const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
  const parsed = parseDnsQname(msg);
  if (!parsed) return;

  const runId = extractRunIdFromQname(parsed.qname);
  const respBuf = buildMinimalDnsResponse(msg, parsed.questionEndOffset, parsed.qtype);
  server.send(respBuf, rinfo.port, rinfo.address);

  if (runId && rinfo?.address) {
    forwardObservationToWorker({
      runId,
      resolverIp: rinfo.address,
      qname: parsed.qname,
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
