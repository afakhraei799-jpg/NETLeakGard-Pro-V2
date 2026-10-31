import React from 'react';
import { Server, AlertTriangle, ShieldCheck, Lock, HelpCircle, Clock, Info, Globe } from 'lucide-react';
import { DnsLeakResult, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface DnsLeakCardProps {
  dnsLeak: DnsLeakResult | null;
  lang: Language;
}

export const DnsLeakCard: React.FC<DnsLeakCardProps> = ({ dnsLeak, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const statusBadge = formatStatusBadgeFa(dnsLeak?.status, isFa);
  const browserObs = dnsLeak?.independentBrowserObservation;
  const browserObsBadge = formatStatusBadgeFa(browserObs?.status, isFa);

  const accentBarClass =
    dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.status === 'ERROR'
      ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600'
      : dnsLeak?.status === 'PASS'
        ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
        : 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4 flex-1">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-emerald-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.dnsLeakTitle}</h3>
              <p className="text-[11px] text-slate-400">
                {isFa
                  ? 'تفکیک تست Authoritative DNS اختصاصی و مشاهدهٔ مستقل مرورگر'
                  : 'Authoritative DNS Leak vs. Independent Browser DNS Observation'}
              </p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold bg-slate-950 border border-slate-800 shrink-0 whitespace-nowrap ${statusBadge.colorClass}`}>
            {statusBadge.text}
          </span>
        </div>

        {/* Cryptographic Run Token */}
        <div className="bg-slate-950/80 border border-slate-800 p-3 rounded-xl flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">{isFa ? 'شناسه یکتای آزمون (Run Token):' : 'Run Token:'}</span>
          <span dir="ltr" className="text-cyan-300 truncate max-w-[180px]" title={dnsLeak?.runId || ''}>
            {dnsLeak?.runId || '---'}
          </span>
        </div>

        {/* PART 1: Authoritative DNS Leak Test Status Banner */}
        <div className={`p-3.5 rounded-2xl border flex items-start gap-2.5 text-xs ${
          dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.status === 'ERROR'
            ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
            : dnsLeak?.status === 'PASS'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-slate-950/80 border-slate-800 text-slate-200'
        }`}>
          {dnsLeak?.status === 'PASS' ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.status === 'ERROR' ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="leading-relaxed flex-1">
            <div className="flex items-center justify-between gap-2 mb-0.5">
              <span className="font-bold text-white">
                {isFa ? '۱. تست نشت Authoritative DNS:' : '1. Authoritative DNS Test:'}
              </span>
              <span className={`font-extrabold ${statusBadge.colorClass}`}>
                {statusBadge.text}
              </span>
            </div>
            <p className="text-slate-300 text-[11px]">
              {dnsLeak
                ? isFa
                  ? dnsLeak.messageFa
                  : dnsLeak.messageEn
                : isFa
                  ? 'در انتظار اجرای آزمون...'
                  : 'Awaiting test execution...'}
            </p>
          </div>
        </div>

        {/* Observed Authoritative Resolvers List */}
        {dnsLeak && dnsLeak.resolvers.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-semibold">
              <span>{isFa ? 'IPهای Resolver مشاهده‌شده (پس از حذف تکراری):' : 'Observed Resolver IPs (Deduplicated):'}</span>
              <span>{dnsLeak.detectedResolversCount}</span>
            </div>
            <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
              {dnsLeak.resolvers.map(res => (
                <div key={res.id} className="bg-slate-950/80 border border-slate-800/80 p-2.5 rounded-xl flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <div>
                      <span className="font-bold text-slate-100 block">{res.name}</span>
                      <span dir="ltr" className="font-mono text-[11px] text-cyan-300">{res.primaryIp}</span>
                    </div>
                  </div>
                  <div className="text-left font-mono">
                    <span className="text-slate-400 block text-[10px]">{res.location}</span>
                    <span className="text-emerald-400 font-bold text-[11px]">
                      {res.responseTimeMs !== null ? `${res.responseTimeMs} ms` : res.observationMethod}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* PART 2: Independent Zero-Cost Browser DNS & Edge Trace Comparison (Strictly Separated) */}
        <div className="bg-slate-950/75 border border-slate-800/90 rounded-2xl p-3.5 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-xs font-bold text-slate-200">
                {isFa
                  ? '۲. مقایسهٔ مستقل DNS قابل مشاهده از مرورگر (رایگان)'
                  : '2. Independent Browser-Observable DNS Check'}
              </span>
            </div>
            <span className={`px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-900 border border-slate-800 ${browserObsBadge.colorClass}`}>
              {browserObsBadge.text}
            </span>
          </div>

          <p className="text-[11px] text-slate-300 leading-relaxed">
            {browserObs
              ? isFa
                ? browserObs.summaryFa
                : browserObs.summaryEn
              : isFa
                ? 'در حال استعلام از منابع عمومی مستقل...'
                : 'Querying independent public endpoints...'}
          </p>

          {browserObs && browserObs.entries.length > 0 ? (
            <div className="space-y-1.5">
              {browserObs.entries.map((entry, idx) => (
                <div
                  key={`${entry.sourceName}-${idx}`}
                  className="bg-slate-900/90 border border-slate-800/80 px-2.5 py-2 rounded-xl flex items-center justify-between text-[11px]"
                >
                  <div>
                    <span className="text-slate-200 font-semibold block">{entry.sourceName}</span>
                    <span className="text-[10px] text-slate-400">{entry.locationOrGeo}</span>
                  </div>
                  <div className="text-left font-mono">
                    <span dir="ltr" className="text-cyan-300 font-bold block">{entry.observedIp}</span>
                    <span dir="ltr" className="text-[10px] text-slate-400">{entry.responseTimeMs} ms</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[11px] text-slate-400 bg-slate-900/60 border border-dashed border-slate-800 rounded-xl p-2.5 text-center">
              {isFa
                ? 'هیچ پاسخ مستقلی از سرویس‌های EDNS/Trace مرورگر دریافت نشد (بدون تولید داده ساختگی).'
                : 'No independent browser EDNS/Trace response received (no fake data generated).'}
            </div>
          )}
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {dnsLeak?.completedAt ? new Date(dnsLeak.completedAt).toLocaleTimeString('fa-IR') : '---'}
            </span>
            <span>اطمینان Authoritative: {dnsLeak?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'محدودیت فنی: بررسی DNS از طریق مرورگر با تست Authoritative DNS یکسان نیست؛ مرورگر ممکن است از DoH مجزا استفاده کند و استعلام تک‌نقطه‌ای، Resolverهای چرخشی سطح سیستم‌عامل را اثبات نمی‌کند.'
                : 'Browser DNS checks are not equivalent to Authoritative DNS leak tests and cannot prove OS-wide DNS security.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

