import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Activity, Globe, Lock, Cpu, Server, Zap, Radio } from 'lucide-react';
import { Language, TestStatus, IpDetails, DnsLeakResult, WebRtcLeakResult, VpnProxyResult } from '../types/network';
import { translations } from '../i18n/translations';

interface HeroScoreBannerProps {
  lang: Language;
  privacyScore: number;
  overallStatus: TestStatus;
  ipDetails: IpDetails | null;
  dnsLeak: DnsLeakResult | null;
  webRtcLeak: WebRtcLeakResult | null;
  vpnProxy: VpnProxyResult | null;
  onStartTest: () => void;
  isTesting: boolean;
}

export const HeroScoreBanner: React.FC<HeroScoreBannerProps> = ({
  lang,
  privacyScore,
  overallStatus,
  ipDetails,
  dnsLeak,
  webRtcLeak,
  vpnProxy,
  onStartTest,
  isTesting,
}) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const getBadgeConfig = () => {
    switch (overallStatus) {
      case 'PASS':
        return {
          icon: ShieldCheck,
          label: t.statusPass,
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.2)]',
          desc: t.secureEnvironment,
          strokeColor: '#10b981',
        };
      case 'WARNING':
        return {
          icon: ShieldAlert,
          label: t.statusWarning,
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/30 shadow-[0_0_20px_rgba(245,158,11,0.2)]',
          desc: t.warningEnvironment,
          strokeColor: '#f59e0b',
        };
      case 'LEAK_DETECTED':
        return {
          icon: ShieldX,
          label: t.statusLeakDetected,
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-[0_0_20px_rgba(244,63,94,0.2)]',
          desc: t.dangerEnvironment,
          strokeColor: '#f43f5e',
        };
      default:
        return {
          icon: Activity,
          label: t.statusNotTested,
          color: 'text-slate-400 bg-slate-800 border-slate-700',
          desc: isFa ? 'جهت اجرای پایش کامل لایه‌های امنیتی، روی دکمه شروع کلیک کنید.' : 'Click start to execute multi-layered network leak diagnostic.',
          strokeColor: '#06b6d4',
        };
    }
  };

  const badge = getBadgeConfig();
  const BadgeIcon = badge.icon;

  // Calculate SVG Circle circumference
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (privacyScore / 100) * circumference;

  return (
    <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-[#0a1224] to-slate-950 border border-slate-800/80 rounded-3xl p-6 md:p-8 shadow-2xl mb-8 group hover:border-slate-700 transition-all duration-300">
      
      {/* Background Neon Flares */}
      <div className="absolute -top-32 -right-32 w-96 h-96 bg-cyan-500/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-purple-500/15 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        
        {/* Left Section: Circular 3D-Style Radial Gauge & Score */}
        <div className="lg:col-span-5 flex flex-col items-center lg:items-start text-center lg:text-right space-y-4">
          
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-3.5 py-1.5 rounded-xl shadow-lg">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>{t.privacyScoreTitle}</span>
          </div>

          <div className="flex items-center gap-6">
            {/* SVG Radial Gauge Meter */}
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
                  className="transition-all duration-1000 ease-out drop-shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center">
                <span className="text-4xl font-extrabold font-mono text-white tracking-tight">
                  {privacyScore}
                </span>
                <span className="text-[10px] font-bold text-slate-400 uppercase">از ۱۰۰</span>
              </div>
            </div>

            {/* Score Text and Badge */}
            <div className="space-y-2 text-right">
              <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl border font-bold text-xs ${badge.color}`}>
                <BadgeIcon className="w-4 h-4" />
                <span>{badge.label}</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed max-w-xs">
                {badge.desc}
              </p>
            </div>
          </div>

        </div>

        {/* Right Section: 4 High-Tech KPI Glass Cards */}
        <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
          
          {/* Card 1: Public IP */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between hover:border-cyan-500/40 hover:shadow-[0_0_20px_rgba(6,182,212,0.1)] transition-all">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Globe className="w-4 h-4 text-cyan-400" />
                {t.publicIp}
              </span>
              <span className="font-mono text-[10px] bg-slate-800 px-2 py-0.5 rounded text-cyan-300">
                {ipDetails?.version || 'IPv4'}
              </span>
            </div>
            <div className="text-lg font-bold font-mono text-cyan-300 truncate">
              {ipDetails?.ip || (isFa ? 'در حال پایش...' : 'Probing...')}
            </div>
            <div className="text-xs text-slate-400 mt-2 truncate">
              {ipDetails ? `${ipDetails.countryName} · ${ipDetails.isp}` : '---'}
            </div>
          </div>

          {/* Card 2: DNS Leak */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between hover:border-emerald-500/40 hover:shadow-[0_0_20px_rgba(16,185,129,0.1)] transition-all">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Server className="w-4 h-4 text-emerald-400" />
                {t.dnsLeakTitle}
              </span>
              <span className={`text-[11px] font-bold ${dnsLeak?.isLeaking ? 'text-rose-400' : 'text-emerald-400'}`}>
                {dnsLeak ? (dnsLeak.isLeaking ? t.statusLeakDetected : t.statusPass) : '---'}
              </span>
            </div>
            <div className="text-base font-bold text-white">
              {dnsLeak ? (isFa ? `${dnsLeak.detectedResolversCount} سرور DNS فعال` : `${dnsLeak.detectedResolversCount} Active Resolvers`) : '---'}
            </div>
            <div className="text-xs text-slate-400 mt-2 truncate">
              {dnsLeak?.isLeaking ? (isFa ? 'نشت موقعیت مکانی' : 'Location Mismatch') : (isFa ? 'کانال رمزنگاری‌شده DoH' : 'Encrypted DoH Tunnel')}
            </div>
          </div>

          {/* Card 3: WebRTC */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between hover:border-purple-500/40 hover:shadow-[0_0_20px_rgba(168,85,247,0.1)] transition-all">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Cpu className="w-4 h-4 text-purple-400" />
                {t.webRtcTitle}
              </span>
              <span className={`text-[11px] font-bold ${webRtcLeak?.isLeakingRealIp ? 'text-rose-400' : 'text-emerald-400'}`}>
                {webRtcLeak ? (webRtcLeak.isLeakingRealIp ? t.statusLeakDetected : t.statusPass) : '---'}
              </span>
            </div>
            <div className="text-base font-bold text-white font-mono truncate">
              {webRtcLeak?.localIps[0] || (isFa ? 'پنهان / ایزوله' : 'Shielded')}
            </div>
            <div className="text-xs text-slate-400 mt-2 truncate">
              {webRtcLeak?.isLeakingRealIp ? (isFa ? 'افشای IP واقعی' : 'Real IP Exposed') : (isFa ? 'ایزوله مرورگر' : 'Browser Protected')}
            </div>
          </div>

          {/* Card 4: VPN Tunnel */}
          <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-2xl flex flex-col justify-between hover:border-teal-500/40 hover:shadow-[0_0_20px_rgba(20,184,166,0.1)] transition-all">
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                <Lock className="w-4 h-4 text-teal-400" />
                {t.vpnTunnelLabel}
              </span>
              <span className={`text-[11px] font-bold ${vpnProxy?.isDatacenterIp ? 'text-emerald-400' : 'text-amber-400'}`}>
                {vpnProxy ? (vpnProxy.isDatacenterIp ? (isFa ? 'پوشش VPN' : 'VPN Active') : (isFa ? 'اتصال مستقیم' : 'Direct ISP')) : '---'}
              </span>
            </div>
            <div className="text-base font-bold text-white">
              {vpnProxy?.protocolType || (isFa ? 'اتصال مستقیم ISP' : 'Direct Link')}
            </div>
            <div className="text-xs text-slate-400 mt-2 truncate">
              {vpnProxy ? `${isFa ? 'اعتبار تونل:' : 'Score:'} ${vpnProxy.score}%` : '---'}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
