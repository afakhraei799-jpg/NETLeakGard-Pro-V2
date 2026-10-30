import React from 'react';
import { Globe, MapPin, Building2, Info, ShieldAlert, Clock, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { IpDetails, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface IpLeakCardProps {
  ipDetails: IpDetails | null;
  lang: Language;
}

export const IpLeakCard: React.FC<IpLeakCardProps> = ({ ipDetails, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const statusBadge = formatStatusBadgeFa(ipDetails?.status, isFa);

  const accentBarClass =
    ipDetails?.status === 'LEAK_DETECTED' || ipDetails?.status === 'ERROR'
      ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600'
      : ipDetails?.status === 'PASS'
        ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
        : 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4 flex-1">
        {/* Card Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl text-cyan-400">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.ipGeoTitle}</h3>
              <p className="text-[11px] text-slate-400">
                {isFa
                  ? 'تفکیک IP مشاهده‌شده در مرورگر کلاینت و سوکت سرور + تخمین GeoIP'
                  : 'Client-observed vs Server-observed IP & GeoIP database estimate'}
              </p>
            </div>
          </div>
          <span className={`font-mono text-xs font-bold bg-slate-950 border border-slate-800 px-3 py-1 rounded-xl shrink-0 whitespace-nowrap ${statusBadge.colorClass}`}>
            {statusBadge.text}
          </span>
        </div>

        {/* Client-Observed IP vs Server-Observed IP Separation */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/80 border border-slate-800 p-3.5 rounded-2xl">
            <span className="text-slate-400 font-semibold block mb-1">
              {isFa ? 'IP عمومی مشاهده‌شده از سمت کلاینت:' : 'Client-Observed Public IP:'}
            </span>
            <span dir="ltr" className="block text-sm font-bold font-mono text-cyan-300 break-all text-right">
              {ipDetails?.clientObservedIp || (isFa ? 'دریافت نشد' : 'Unavailable')}
            </span>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 p-3.5 rounded-2xl">
            <span className="text-slate-400 font-semibold block mb-1">
              {isFa ? 'IP مشاهده‌شده توسط سرور برنامه:' : 'Server-Observed IP:'}
            </span>
            <span dir="ltr" className="block text-sm font-bold font-mono text-emerald-300 break-all text-right">
              {ipDetails?.serverObservedIp || (isFa ? 'دریافت نشد' : 'Unavailable')}
            </span>
            <span className="block text-[10px] text-slate-500 mt-1">
              {ipDetails
                ? ipDetails.proxyHeaderTrusted
                  ? isFa
                    ? 'منبع: هدر پروکسی مورد اعتماد (TRUST_PROXY=true)'
                    : 'Source: Trusted Proxy Header'
                  : isFa
                    ? 'منبع: سوکت مستقیم سرور (X-Forwarded-For غیرمعتبر تلقی شد)'
                    : 'Source: Direct Socket (XFF untrusted)'
                : '---'}
            </span>
          </div>
        </div>

        {/* Mismatch Alert if Client & Server IPs differ */}
        {ipDetails?.ipMismatchDetected && (
          <div className="bg-rose-950/50 border border-rose-800 p-3 rounded-2xl flex items-start gap-2.5 text-xs text-rose-200">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold block">
                {isFa ? 'عدم تطابق بین آدرس IP کلاینت و سرور!' : 'Client / Server IP Mismatch Detected!'}
              </span>
              <p className="text-[11px] text-rose-300/90 mt-0.5">
                {isFa
                  ? 'مسیر ترافیک به سرویس‌های خارجی با مسیر ترافیک به سرور برنامه متفاوت است (احتمال فعال بودن Split-Tunneling یا قوانین پروکسی انتخابی).'
                  : 'Traffic to external endpoints uses a different IP than traffic to this server.'}
              </p>
            </div>
          </div>
        )}

        {/* GeoIP Estimate & ASN Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="bg-slate-950/70 border border-slate-800/80 p-3 rounded-2xl">
            <span className="text-slate-400 font-semibold block mb-1">
              {isFa ? 'تخمین موقعیت پایگاه داده GeoIP:' : 'GeoIP Database Estimate:'}
            </span>
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-100">
              <MapPin className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                {ipDetails?.countryName
                  ? `${ipDetails.countryName}${ipDetails.city ? ` - ${ipDetails.city}` : ''}`
                  : isFa
                    ? 'نامشخص (بدون جایگزینی مقدار ثابت)'
                    : 'Unknown'}
              </span>
            </div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800/80 p-3 rounded-2xl">
            <span className="text-slate-400 font-semibold block mb-1">{t.ispCompany} / ASN:</span>
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-100 truncate">
              <Building2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="truncate">
                {ipDetails?.isp || ipDetails?.asn
                  ? `${ipDetails.isp || ''} ${ipDetails.asn ? `(${ipDetails.asn})` : ''}`
                  : isFa
                    ? 'نامشخص'
                    : 'Unknown'}
              </span>
            </div>
          </div>
        </div>

        {/* Honest Reputation & Blacklist Verification Box */}
        <div className="bg-slate-950/90 border border-slate-800 p-3.5 rounded-2xl space-y-2 text-xs">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2 font-bold text-slate-200">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>{t.fraudRiskTitle}</span>
            </div>
            <span className="font-mono text-[11px] text-slate-300 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded-lg">
              {ipDetails?.fraudRiskScore !== null && ipDetails?.fraudRiskScore !== undefined
                ? `امتیاز ریسک: ${ipDetails.fraudRiskScore}%`
                : isFa
                  ? 'امتیاز ریسک: محاسبه‌نشده'
                  : 'Risk Score: N/A'}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-1.5 text-[11px] text-slate-400">
            <div className="flex items-center justify-between">
              <span>AbuseIPDB API:</span>
              <span className="font-mono text-slate-300">
                {ipDetails?.blacklistDetails.abuseIpDbStatus === 'not_configured'
                  ? isFa
                    ? 'پیکربندی نشده (not_configured)'
                    : 'not_configured'
                  : ipDetails?.blacklistDetails.abuseIpDbStatus || '---'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Google Safe Browsing / Spamhaus:</span>
              <span className="font-mono text-slate-400">
                {isFa ? 'پیکربندی نشده (عدم ادعای پاک بودن بدون کلید API)' : 'not_configured'}
              </span>
            </div>
          </div>
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {ipDetails?.completedAt ? new Date(ipDetails.completedAt).toLocaleTimeString('fa-IR') : '---'}
            </span>
            <span>منبع: {ipDetails?.source || '---'}</span>
            <span>اطمینان: {ipDetails?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
            <p>
              {ipDetails?.limitations?.[0] ||
                (isFa
                  ? 'موقعیت جغرافیایی صرفاً تخمین پایگاه داده GeoIP است و مشاهدهٔ IP مرورگر کل سیستم‌عامل را اثبات نمی‌کند.'
                  : 'GeoIP is a database estimate and does not prove OS-wide routing.')}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
