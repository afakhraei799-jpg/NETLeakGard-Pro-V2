import React from 'react';
import { Cpu, ShieldCheck, AlertOctagon } from 'lucide-react';
import { WebRtcLeakResult, Language } from '../types/network';
import { translations } from '../i18n/translations';

interface WebRtcCardProps {
  webRtcLeak: WebRtcLeakResult | null;
  lang: Language;
}

export const WebRtcCard: React.FC<WebRtcCardProps> = ({ webRtcLeak, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const isLeaking = webRtcLeak?.isLeakingRealIp ?? false;

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
            <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 rounded-2xl text-purple-400 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.webRtcTitle}</h3>
              <p className="text-xs text-slate-400">{t.webRtcExplanation}</p>
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

        {/* Status Callout */}
        <div className={`p-4 rounded-2xl border mb-5 flex items-start gap-3 shadow-inner ${
          isLeaking 
            ? 'bg-rose-950/40 border-rose-800/60 text-rose-200' 
            : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
        }`}>
          {isLeaking ? (
            <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5 animate-bounce" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <div className="text-xs leading-relaxed">
            <span className="font-bold block mb-0.5">
              {isLeaking ? (isFa ? 'هشدار افشای IP واقعی WebRTC!' : 'WebRTC IP Leak Warning!') : (isFa ? 'محافظت از WebRTC برقرار است' : 'WebRTC Properly Shielded')}
            </span>
            <p className="text-slate-300">
              {webRtcLeak ? (isFa ? webRtcLeak.messageFa : webRtcLeak.messageEn) : (isFa ? 'آزمایش در حال دسترسی...' : 'Awaiting test execution...')}
            </p>
          </div>
        </div>

        {/* Candidate List */}
        <div className="space-y-3 text-xs">
          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl flex items-center justify-between shadow-inner">
            <span className="text-slate-400 font-semibold">{t.localLanIp}</span>
            <span className="font-mono text-cyan-300 font-bold">
              {webRtcLeak?.localIps[0] || (isFa ? 'پنهان شده' : 'Hidden')}
            </span>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl flex items-center justify-between shadow-inner">
            <span className="text-slate-400 font-semibold">{t.stunCandidates}</span>
            <span className="font-mono text-emerald-400 font-bold">
              {webRtcLeak?.publicCandidates.length ? (isFa ? `${webRtcLeak.publicCandidates.length} گره دریافت شد` : `${webRtcLeak.publicCandidates.length} Candidate Nodes`) : (isFa ? 'هیچ کاندید خامی یافت نشد' : 'No Public Leak')}
            </span>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/60 text-[11px] text-slate-400">
          <p>
            {isFa
              ? 'در صورت بروز نشت WebRTC، افزونه‌های غیرفعال‌سازی WebRTC را در مرورگر فعال کنید.'
              : 'If WebRTC leaks occur, install WebRTC disabling extension in Chrome/Firefox.'}
          </p>
        </div>
      </div>
    </div>
  );
};
