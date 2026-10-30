import React from 'react';
import { Server, AlertTriangle, ShieldCheck, Lock, HelpCircle, Clock, Info } from 'lucide-react';
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
                {isFa ? 'بررسی مبتنی بر شناسه یکتای رمزنگارانه و Authoritative DNS' : 'Cryptographic nonce & Authoritative DNS inspection'}
              </p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold bg-slate-950 border border-slate-800 ${statusBadge.colorClass}`}>
            {statusBadge.text}
          </span>
        </div>

        {/* Cryptographic Run Token */}
        <div className="bg-slate-950/80 border border-slate-800 p-3 rounded-xl flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">{isFa ? 'شناسه یکتای آزمون (Run Token):' : 'Run Token:'}</span>
          <span className="text-cyan-300 truncate max-w-[180px]" title={dnsLeak?.runId || ''}>
            {dnsLeak?.runId || '---'}
          </span>
        </div>

        {/* Status Callout Banner */}
        <div className={`p-3.5 rounded-2xl border flex items-start gap-2.5 text-xs ${
          dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.status === 'ERROR'
            ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
            : dnsLeak?.status === 'PASS'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-amber-950/40 border-amber-800/60 text-amber-200'
        }`}>
          {dnsLeak?.status === 'PASS' ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : dnsLeak?.status === 'LEAK_DETECTED' || dnsLeak?.status === 'ERROR' ? (
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="leading-relaxed">
            <span className="font-bold block mb-0.5">
              {statusBadge.text}
            </span>
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

        {/* Observed Resolvers List (Only real observed resolvers, never hardcoded defaults) */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-semibold">
            <span>{isFa ? 'سرورهای Resolver مشاهده‌شده با شواهد واقعی:' : 'Observed Resolvers:'}</span>
            <span>{dnsLeak?.detectedResolversCount ?? 0}</span>
          </div>

          {dnsLeak && dnsLeak.resolvers.length > 0 ? (
            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {dnsLeak.resolvers.map(res => (
                <div key={res.id} className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-xl flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <div>
                      <span className="font-bold text-slate-100 block">{res.name}</span>
                      <span className="font-mono text-[11px] text-cyan-300">{res.primaryIp}</span>
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
          ) : (
            <div className="bg-slate-950/60 border border-dashed border-slate-800 p-3.5 rounded-xl text-[11px] text-slate-400 text-center">
              {dnsLeak?.status === 'NOT_CONFIGURED'
                ? isFa
                  ? 'دامنهٔ Authoritative DNS (متغیر DNS_LEAK_DOMAIN) تنظیم نشده است. هیچ Resolver فرضی نمایش داده نمی‌شود.'
                  : 'Authoritative DNS domain not configured. No synthetic resolvers shown.'
                : isFa
                  ? 'هیچ سرور DNS از روی لاگ واقعی ثبت نشد.'
                  : 'No verified DNS resolvers captured.'}
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
            <span>اطمینان: {dnsLeak?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'محدودیت فنی: مشاهدهٔ کوئری در Authoritative DNS فقط آخرین Resolver خروجی را نشان می‌دهد (نه کل زنجیرهٔ DoH/پروکسی) و وضعیت DNS سطح سیستم‌عامل خارج از مرورگر را اثبات نمی‌کند.'
                : 'Authoritative DNS only sees the final egress resolver and cannot prove OS-wide DNS outside the browser.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
