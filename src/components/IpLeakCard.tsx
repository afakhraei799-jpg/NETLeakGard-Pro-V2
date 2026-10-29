import React from 'react';
import { Globe, Shield, MapPin, Building2, Radio, Info, Home, Building, ShieldAlert, Cpu } from 'lucide-react';
import { IpDetails, Language } from '../types/network';
import { translations } from '../i18n/translations';

interface IpLeakCardProps {
  ipDetails: IpDetails | null;
  lang: Language;
}

export const IpLeakCard: React.FC<IpLeakCardProps> = ({ ipDetails, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const riskScore = ipDetails?.fraudRiskScore || 0;
  const isHighRisk = riskScore > 40;
  const isMediumRisk = riskScore > 15 && riskScore <= 40;

  // Determine accent color bar class
  const accentBarClass = isHighRisk 
    ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_12px_rgba(244,63,94,0.6)]' 
    : isMediumRisk 
      ? 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500 shadow-[0_0_12px_rgba(245,158,11,0.6)]' 
      : 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 group flex flex-col justify-between">
      
      {/* Top Live Risk Indicator Accent Bar */}
      <div className={`h-1.5 w-full ${accentBarClass} transition-all duration-500`} />

      <div className="p-6">
        {/* Card Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl text-cyan-400 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.ipGeoTitle}</h3>
              <p className="text-xs text-slate-400">{t.ipExplanation}</p>
            </div>
          </div>
          <span className="font-mono text-xs font-bold text-cyan-300 bg-cyan-950/80 border border-cyan-800/60 px-3 py-1 rounded-xl shadow-md">
            {ipDetails?.version || 'IPv4'}
          </span>
        </div>

        {/* Data Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          {/* Public IP */}
          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl hover:border-cyan-500/30 transition-colors shadow-inner">
            <span className="text-slate-400 font-semibold block mb-1">{t.publicIp}</span>
            <span className="text-base font-bold font-mono text-cyan-300 drop-shadow-[0_0_8px_rgba(6,182,212,0.3)]">
              {ipDetails?.ip || '---'}
            </span>
          </div>

          {/* Location */}
          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl hover:border-slate-700 transition-colors shadow-inner">
            <span className="text-slate-400 font-semibold block mb-1">{t.countryAndCity}</span>
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
              <MapPin className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{ipDetails ? `${ipDetails.countryName} - ${ipDetails.city}` : '---'}</span>
            </div>
          </div>

          {/* IP Classification */}
          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl hover:border-slate-700 transition-colors shadow-inner">
            <span className="text-slate-400 font-semibold block mb-1">{t.ipTypeLabel}</span>
            <div className="flex items-center gap-2 text-xs font-bold text-slate-100">
              {ipDetails?.usageType === 'Residential' || ipDetails?.usageType === 'Mobile' ? (
                <Home className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <Building className="w-4 h-4 text-amber-400 shrink-0" />
              )}
              <span className={ipDetails?.usageType === 'Residential' ? 'text-emerald-300' : 'text-amber-300'}>
                {ipDetails?.usageTypeFa || 'مسکونی (خانگی / همراه)'}
              </span>
            </div>
          </div>

          {/* ISP */}
          <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl hover:border-slate-700 transition-colors shadow-inner">
            <span className="text-slate-400 font-semibold block mb-1">{t.ispCompany}</span>
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100 truncate">
              <Building2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="truncate">{ipDetails?.isp || '---'}</span>
            </div>
          </div>
        </div>

        {/* Fraud Risk Box */}
        <div className="mt-4 bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-3 shadow-inner">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2 text-xs">
            <div className="flex items-center gap-2 font-bold text-slate-200">
              <ShieldAlert className={`w-4 h-4 ${isHighRisk ? 'text-rose-400' : 'text-emerald-400'}`} />
              <span>{t.fraudRiskTitle}</span>
            </div>
            <span className={`font-mono font-bold px-2.5 py-0.5 rounded-lg text-[11px] ${
              isHighRisk 
                ? 'bg-rose-950/90 text-rose-300 border border-rose-800' 
                : 'bg-emerald-950/90 text-emerald-300 border border-emerald-800'
            }`}>
              {ipDetails?.fraudStatusFa || 'پاک و بدون سابقه'}
            </span>
          </div>
        </div>

        {/* Intent Analysis */}
        <div className="mt-3 bg-slate-950/90 border border-slate-800 p-3.5 rounded-2xl text-xs space-y-1">
          <div className="flex items-center gap-1.5 font-bold text-cyan-400">
            <Cpu className="w-3.5 h-3.5" />
            <span>{t.intentAnalysisTitle}</span>
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed">
            {ipDetails?.userIntentAnalysisFa || 'این اتصال متعلق به اینترنت مسکونی/خانگی مستقیم می‌باشد.'}
          </p>
        </div>

        {/* Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/60 flex items-start gap-2 text-[11px] text-slate-400">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <p>
            {isFa 
              ? 'اعتبارسنجی سوابق کلاهبرداری بر اساس استعلام از بانک‌های اطلاعاتی Google Safe Browsing اجرا می‌شود.' 
              : 'Fraud risk & blacklist reputation verified via Google Safe Browsing threat databases.'}
          </p>
        </div>
      </div>
    </div>
  );
};
