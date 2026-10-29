import React from 'react';
import { Server, AlertTriangle, ShieldCheck, Lock } from 'lucide-react';
import { DnsLeakResult, Language } from '../types/network';
import { translations } from '../i18n/translations';

interface DnsLeakCardProps {
  dnsLeak: DnsLeakResult | null;
  lang: Language;
}

export const DnsLeakCard: React.FC<DnsLeakCardProps> = ({ dnsLeak, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const isLeaking = dnsLeak?.isLeaking ?? false;

  const accentBarClass = isLeaking 
    ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_12px_rgba(244,63,94,0.6)]' 
    : 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 group flex flex-col justify-between">
      
      {/* Top Live Risk Indicator Accent Bar */}
      <div className={`h-1.5 w-full ${accentBarClass} transition-all duration-500`} />

      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl text-emerald-400 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.dnsLeakTitle}</h3>
              <p className="text-xs text-slate-400">{t.dnsExplanation}</p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold ${
            isLeaking 
              ? 'bg-rose-950/80 text-rose-400 border border-rose-800/60 shadow-md' 
              : 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shadow-md'
          }`}>
            {isLeaking ? t.statusLeakDetected : t.statusPass}
          </span>
        </div>

        {/* Leak Result Banner */}
        <div className={`p-4 rounded-2xl border mb-5 flex items-start gap-3 shadow-inner ${
          isLeaking 
            ? 'bg-rose-950/40 border-rose-800/60 text-rose-200' 
            : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
        }`}>
          {isLeaking ? (
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5 animate-bounce" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div className="text-xs leading-relaxed">
            <span className="font-bold block mb-0.5">
              {isLeaking ? (isFa ? 'هشدار نشت DNS!' : 'DNS Leak Detected!') : (isFa ? 'وضعیت امن' : 'Secure Configuration')}
            </span>
            <p className="text-slate-300">
              {dnsLeak ? (isFa ? dnsLeak.messageFa : dnsLeak.messageEn) : (isFa ? 'آزمایش در حال دسترسی...' : 'Awaiting test execution...')}
            </p>
          </div>
        </div>

        {/* Resolvers Table */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-semibold">
            <span>{t.dnsServerList}</span>
            <span>{isFa ? `${dnsLeak?.detectedResolversCount || 0} سرور فعال` : `${dnsLeak?.detectedResolversCount || 0} Resolvers`}</span>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {dnsLeak?.resolvers.map((res) => (
              <div key={res.id} className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-xl flex items-center justify-between text-xs hover:border-slate-700 transition-colors">
                <div className="flex items-center gap-2.5">
                  <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <div>
                    <span className="font-bold text-slate-100 block">{res.name}</span>
                    <span className="font-mono text-[11px] text-cyan-300">{res.primaryIp}</span>
                  </div>
                </div>

                <div className="text-left font-mono">
                  <span className="text-slate-400 block text-[10px]">{res.location}</span>
                  <span className="text-emerald-400 font-bold text-[11px]">{res.responseTimeMs} ms</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/60 text-[11px] text-slate-400">
          <p>
            {isFa
              ? 'تست نشت DNS تضمین می‌کند که درخواست‌های دامنه مرورگر شما از کانال رمزنگاری‌شده DoH عبور می‌کند.'
              : 'DNS leak test ensures domain lookups route through encrypted DoH resolvers.'}
          </p>
        </div>
      </div>
    </div>
  );
};
