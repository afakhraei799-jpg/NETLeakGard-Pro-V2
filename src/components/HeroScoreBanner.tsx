import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Activity,
  Globe,
  Lock,
  Cpu,
  Server,
  Radio,
  HelpCircle,
  AlertOctagon
} from 'lucide-react';
import {
  Language,
  TestStatus,
  IpDetails,
  DnsLeakResult,
  WebRtcLeakResult,
  VpnProxyResult
} from '../types/network';
import { translations } from '../i18n/translations';

interface HeroScoreBannerProps {
  lang: Language;
  privacyScore: number | null;
  isScoreCalculable: boolean;
  overallStatus: TestStatus;
  scoreReasonsFa?: string[];
  ipDetails: IpDetails | null;
  dnsLeak: DnsLeakResult | null;
  webRtcLeak: WebRtcLeakResult | null;
  vpnProxy: VpnProxyResult | null;
  onStartTest: () => void;
  isTesting: boolean;
}

export function formatStatusBadgeFa(status: TestStatus | undefined, isFa: boolean): {
  text: string;
  colorClass: string;
} {
  switch (status) {
    case 'PASS':
      return {
        text: isFa ? 'موفق' : 'Pass',
        colorClass: 'text-emerald-400',
      };
    case 'LEAK_DETECTED':
      return {
        text: isFa ? 'نشت شناسایی شد' : 'Leak Detected',
        colorClass: 'text-rose-400',
      };
    case 'WARNING':
      return {
        text: isFa ? 'هشدار' : 'Warning',
        colorClass: 'text-amber-400',
      };
    case 'NOT_CONFIGURED':
      return {
        text: isFa ? 'پیکربندی نشده' : 'Not Configured',
        colorClass: 'text-slate-400',
      };
    case 'INCONCLUSIVE':
      return {
        text: isFa ? 'نامشخص' : 'Inconclusive',
        colorClass: 'text-amber-300',
      };
    case 'UNSUPPORTED':
      return {
        text: isFa ? 'پشتیبانی نشده' : 'Unsupported',
        colorClass: 'text-slate-400',
      };
    case 'ERROR':
      return {
        text: isFa ? 'خطا در آزمون' : 'Error',
        colorClass: 'text-rose-400',
      };
    case 'TESTING':
      return {
        text: isFa ? 'در حال آزمایش...' : 'Testing...',
        colorClass: 'text-cyan-400',
      };
    default:
      return {
        text: isFa ? 'اجرا نشده' : 'Idle',
        colorClass: 'text-slate-500',
      };
  }
}

export const HeroScoreBanner: React.FC<HeroScoreBannerProps> = ({
  lang,
  privacyScore,
  isScoreCalculable,
  overallStatus,
  scoreReasonsFa = [],
  ipDetails,
  dnsLeak,
  webRtcLeak,
  vpnProxy,
}) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const getBadgeConfig = () => {
    switch (overallStatus) {
      case 'PASS':
        return {
          icon: ShieldCheck,
          label: isFa ? 'بدون نشت در تست‌های بررسی‌شده' : 'No Leaks in Verified Tests',
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          desc: isFa
            ? 'آزمون‌های دارای شواهد معتبر بدون مشاهدهٔ مغایرت IP یا نشت تکمیل شدند.'
            : 'Verified tests completed with no observed IP/DNS/WebRTC leaks.',
          strokeColor: '#10b981',
        };
      case 'WARNING':
        return {
          icon: ShieldAlert,
          label: t.statusWarning,
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          desc: isFa
            ? 'برخی نشانگرهای ریسک (مانند اتصال مستقیم ISP یا مشاهدهٔ IP محلی) ثبت شد.'
            : 'Warning indicators observed in network egress.',
          strokeColor: '#f59e0b',
        };
      case 'LEAK_DETECTED':
        return {
          icon: ShieldX,
          label: t.statusLeakDetected,
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          desc: t.dangerEnvironment,
          strokeColor: '#f43f5e',
        };
      case 'ERROR':
        return {
          icon: AlertOctagon,
          label: isFa ? 'خطا در اجرای تست‌های پایه' : 'Test Execution Error',
          color: 'text-rose-400 bg-rose-950/60 border-rose-800',
          desc: isFa
            ? 'یک یا چند آزمون به علت خطای شبکه یا عدم پاسخ سرویس کامل نشدند.'
            : 'One or more core tests failed due to network or API errors.',
          strokeColor: '#ef4444',
        };
      case 'INCONCLUSIVE':
      case 'NOT_CONFIGURED':
        return {
          icon: HelpCircle,
          label: isFa ? 'شواهد ناکافی برای امتیازدهی قطعی' : 'Inconclusive / Unconfigured',
          color: 'text-amber-300 bg-amber-950/50 border-amber-700/60',
          desc: isFa
            ? 'به دلیل تنظیم نبودن زیرساخت Authoritative DNS یا عدم دریافت پاسخ STUN، امتیاز عددی امنیت محاسبه نمی‌شود.'
            : 'Score is not calculated when authoritative DNS or STUN evidence is incomplete.',
          strokeColor: '#eab308',
        };
      case 'TESTING':
        return {
          icon: Activity,
          label: t.statusTesting,
          color: 'text-cyan-400 bg-cyan-950/50 border-cyan-700/60',
          desc: isFa
            ? 'در حال جمع‌آوری شواهد واقعی از لایه‌های شبکه...'
            : 'Collecting real network measurements...',
          strokeColor: '#06b6d4',
        };
      default:
        return {
          icon: Activity,
          label: t.statusNotTested,
          color: 'text-slate-400 bg-slate-800 border-slate-700',
          desc: isFa
            ? 'جهت اجرای پایش مبتنی بر شواهد، روی دکمه شروع آزمایش کلیک کنید.'
            : 'Click start to execute evidence-based network diagnostics.',
          strokeColor: '#475569',
        };
    }
  };

  const badge = getBadgeConfig();
  const BadgeIcon = badge.icon;

  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const effectiveScore = isScoreCalculable && privacyScore !== null ? privacyScore : 0;
  const strokeDashoffset = circumference - (effectiveScore / 100) * circumference;

  const ipStatus = formatStatusBadgeFa(ipDetails?.status, isFa);
  const dnsStatus = formatStatusBadgeFa(dnsLeak?.status, isFa);
  const webrtcStatus = formatStatusBadgeFa(webRtcLeak?.status, isFa);
  const vpnStatus = formatStatusBadgeFa(vpnProxy?.status, isFa);

  return (
    <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-[#0a1224] to-slate-950 border border-slate-800/80 rounded-3xl p-6 md:p-8 shadow-2xl mb-8 transition-all duration-300">
      <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        
        {/* Left Section: Score or "امتیاز قابل محاسبه نیست" */}
        <div className="lg:col-span-5 flex flex-col items-center lg:items-start text-center lg:text-right space-y-4">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-3.5 py-1.5 rounded-xl">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            <span>{t.privacyScoreTitle}</span>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-6">
            <div className="relative w-36 h-36 flex items-center justify-center shrink-0">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="72"
                  cy="72"
                  r={radius}
                  className="text-slate-800"
                  strokeWidth="10"
                  stroke="currentColor"
                  fill="transparent"
                />
                {isScoreCalculable && privacyScore !== null && (
                  <circle
                    cx="72"
                    cy="72"
                    r={radius}
                    stroke={badge.strokeColor}
                    strokeWidth="10"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-700 ease-out"
                  />
                )}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center px-3 text-center">
                {isScoreCalculable && privacyScore !== null ? (
                  <>
                    <span className="text-4xl font-extrabold font-mono text-white tracking-tight">
                      {privacyScore}
                    </span>
                    <span className="text-[10px] font-bold text-slate-400 uppercase">از ۱۰۰</span>
                  </>
                ) : (
                  <>
                    <span className="text-xs font-extrabold text-amber-300 leading-snug">
                      {isFa ? 'امتیاز قابل محاسبه نیست' : 'Score N/A'}
                    </span>
                    <span className="text-[10px] text-slate-400 mt-1">
                      {isFa ? 'نیازمند شواهد کامل' : 'Incomplete Evidence'}
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="space-y-2 text-center sm:text-right">
              <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl border font-bold text-xs ${badge.color}`}>
                <BadgeIcon className="w-4 h-4 shrink-0" />
                <span>{badge.label}</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed max-w-sm">
                {badge.desc}
              </p>
              {scoreReasonsFa.length > 0 && (
                <ul className="text-[11px] text-slate-400 space-y-1 list-disc list-inside pt-1">
                  {scoreReasonsFa.slice(0, 2).map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Right Section: 4 Evidence KPI Cards */}
        <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
          
          {/* Card 1: Public IP */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Globe className="w-4 h-4 text-cyan-400" />
                {t.publicIp}
              </span>
              <span className={`text-[11px] font-bold ${ipStatus.colorClass}`}>
                {ipStatus.text}
              </span>
            </div>
            <div dir="ltr" className="text-base font-bold font-mono text-cyan-300 truncate text-right">
              {ipDetails?.ip || (isFa ? 'تأیید نشده / بدون داده' : 'Unverified / No Data')}
            </div>
            <div className="text-[11px] text-slate-400 mt-2 truncate">
              {ipDetails?.ip
                ? `${ipDetails.countryName || 'کشور نامشخص'} · ${ipDetails.isp || 'ISP نامشخص'}`
                : isFa
                  ? 'هیچ IP ساختگی نمایش داده نمی‌شود'
                  : 'No fallback IP used'}
            </div>
          </div>

          {/* Card 2: DNS Leak */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Server className="w-4 h-4 text-emerald-400" />
                {t.dnsLeakTitle}
              </span>
              <span className={`text-[11px] font-bold ${dnsStatus.colorClass}`}>
                {dnsStatus.text}
              </span>
            </div>
            <div className="text-sm font-bold text-white">
              {dnsLeak?.status === 'NOT_CONFIGURED'
                ? isFa
                  ? 'نیازمند تنظیم Authoritative DNS'
                  : 'Authoritative DNS Not Configured'
                : dnsLeak
                  ? isFa
                    ? `${dnsLeak.detectedResolversCount} Resolver مشاهده شد`
                    : `${dnsLeak.detectedResolversCount} Observed Resolvers`
                  : '---'}
            </div>
            <div className="text-[11px] text-slate-400 mt-2 truncate">
              {dnsLeak ? `درجه اطمینان: ${dnsLeak.confidence}` : '---'}
            </div>
          </div>

          {/* Card 3: WebRTC */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Cpu className="w-4 h-4 text-purple-400" />
                {t.webRtcTitle}
              </span>
              <span className={`text-[11px] font-bold ${webrtcStatus.colorClass}`}>
                {webrtcStatus.text}
              </span>
            </div>
            <div className="text-sm font-bold text-white font-mono truncate">
              {webRtcLeak
                ? webRtcLeak.publicCandidates.length > 0
                  ? webRtcLeak.publicCandidates.join(', ')
                  : isFa
                    ? 'بدون نامزد عمومی STUN'
                    : 'No Public STUN Candidate'
                : '---'}
            </div>
            <div className="text-[11px] text-slate-400 mt-2 truncate">
              {webRtcLeak ? `درجه اطمینان: ${webRtcLeak.confidence}` : '---'}
            </div>
          </div>

          {/* Card 4: VPN Heuristic */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Lock className="w-4 h-4 text-teal-400" />
                {t.vpnTunnelLabel}
              </span>
              <span className={`text-[11px] font-bold ${vpnStatus.colorClass}`}>
                {vpnStatus.text}
              </span>
            </div>
            <div className="text-sm font-bold text-white truncate">
              {vpnProxy
                ? vpnProxy.isDatacenterIp === null
                  ? isFa
                    ? 'نامشخص'
                    : 'Unknown'
                  : vpnProxy.isDatacenterIp
                    ? isFa
                      ? 'احتمالاً شبکه دیتاسنتر / هاستینگ'
                      : 'Probable Datacenter Egress'
                    : isFa
                      ? 'احتمالاً اتصال مستقیم ISP'
                      : 'Probable Direct ISP'
                : '---'}
            </div>
            <div className="text-[11px] text-slate-400 mt-2 truncate">
              {vpnProxy ? `سطح اطمینان طبقه‌بندی: ${vpnProxy.confidence}` : '---'}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
