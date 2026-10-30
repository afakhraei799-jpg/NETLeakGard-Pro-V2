import React from 'react';
import { Cpu, ShieldCheck, AlertOctagon, HelpCircle, Clock, Info } from 'lucide-react';
import { WebRtcLeakResult, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface WebRtcCardProps {
  webRtcLeak: WebRtcLeakResult | null;
  lang: Language;
}

export const WebRtcCard: React.FC<WebRtcCardProps> = ({ webRtcLeak, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const statusBadge = formatStatusBadgeFa(webRtcLeak?.status, isFa);

  const accentBarClass =
    webRtcLeak?.status === 'LEAK_DETECTED' || webRtcLeak?.status === 'ERROR'
      ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600'
      : webRtcLeak?.status === 'PASS'
        ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
        : 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4 flex-1">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 rounded-2xl text-purple-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.webRtcTitle}</h3>
              <p className="text-[11px] text-slate-400">
                {isFa ? 'جمع‌آوری واقعی نامزدهای ICE (host / srflx / relay / mDNS)' : 'Real ICE candidate gathering (host / srflx / relay)'}
              </p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold bg-slate-950 border border-slate-800 ${statusBadge.colorClass}`}>
            {statusBadge.text}
          </span>
        </div>

        {/* Status Callout */}
        <div className={`p-3.5 rounded-2xl border flex items-start gap-2.5 text-xs ${
          webRtcLeak?.status === 'LEAK_DETECTED' || webRtcLeak?.status === 'ERROR'
            ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
            : webRtcLeak?.status === 'PASS'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
              : 'bg-amber-950/40 border-amber-800/60 text-amber-200'
        }`}>
          {webRtcLeak?.status === 'PASS' ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : webRtcLeak?.status === 'LEAK_DETECTED' || webRtcLeak?.status === 'ERROR' ? (
            <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          ) : (
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="leading-relaxed">
            <span className="font-bold block mb-0.5">{statusBadge.text}</span>
            <p className="text-slate-300 text-[11px]">
              {webRtcLeak
                ? isFa
                  ? webRtcLeak.messageFa
                  : webRtcLeak.messageEn
                : isFa
                  ? 'در انتظار اجرای آزمون...'
                  : 'Awaiting test execution...'}
            </p>
          </div>
        </div>

        {/* Candidate Breakdown */}
        <div className="space-y-2.5 text-xs">
          <div className="bg-slate-950/70 border border-slate-800/80 p-3 rounded-2xl flex items-center justify-between">
            <span className="text-slate-400 font-semibold">{isFa ? 'آدرس‌های شبکه محلی (host LAN):' : 'Local LAN IPs (host):'}</span>
            <span className="font-mono text-cyan-300 font-bold">
              {webRtcLeak
                ? webRtcLeak.localIps.length > 0
                  ? webRtcLeak.localIps.join(', ')
                  : webRtcLeak.mdnsHosts.length > 0
                    ? `پوشش mDNS (${webRtcLeak.mdnsHosts.length} میزبان)`
                    : isFa
                      ? 'مشاهده نشد (۰ مورد)'
                      : 'None observed (0)'
                : '---'}
            </span>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 p-3 rounded-2xl flex items-center justify-between">
            <span className="text-slate-400 font-semibold">{isFa ? 'آدرس‌های عمومی STUN (srflx/relay):' : 'Public STUN IPs (srflx/relay):'}</span>
            <span className="font-mono text-emerald-400 font-bold">
              {webRtcLeak
                ? webRtcLeak.publicCandidates.length > 0
                  ? webRtcLeak.publicCandidates.join(', ')
                  : isFa
                    ? 'دریافت نشد (۰ کاندید)'
                    : 'None received (0)'
                : '---'}
            </span>
          </div>

          {webRtcLeak && webRtcLeak.candidates.length > 0 && (
            <div className="bg-slate-950/90 border border-slate-800 p-3 rounded-xl space-y-1.5 max-h-32 overflow-y-auto font-mono text-[11px]">
              {webRtcLeak.candidates.map((c, idx) => (
                <div key={idx} className="flex items-center justify-between text-slate-300 border-b border-slate-900 pb-1 last:border-0">
                  <span>{c.ip}:{c.port}</span>
                  <span className="text-purple-300">{c.type} ({c.protocol} / {c.version})</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {webRtcLeak?.completedAt ? new Date(webRtcLeak.completedAt).toLocaleTimeString('fa-IR') : '---'}
            </span>
            <span>کاندیداها: {webRtcLeak?.candidates.length ?? 0}</span>
            <span>اطمینان: {webRtcLeak?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'نبود نامزد STUN به معنای اثبات امنیت نیست و در صورت عدم دریافت پاسخ STUN، نتیجه نامشخص (Inconclusive) ثبت می‌شود.'
                : 'Absence of STUN candidates is reported as Inconclusive, never assumed to be Pass.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
