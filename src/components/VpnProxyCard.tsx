import React from 'react';
import { Lock, Shield, AlertTriangle, KeyRound, Server, Cpu, ShieldCheck, Radio, Layers } from 'lucide-react';
import { VpnProxyResult, Language } from '../types/network';
import { translations } from '../i18n/translations';

interface VpnProxyCardProps {
  vpnProxy: VpnProxyResult | null;
  lang: Language;
}

export const VpnProxyCard: React.FC<VpnProxyCardProps> = ({ vpnProxy, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const isDatacenter = vpnProxy?.isDatacenterIp ?? false;
  const protoDetails = vpnProxy?.protocolDetails;

  const accentBarClass = isDatacenter 
    ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]' 
    : 'bg-gradient-to-r from-amber-400 via-yellow-500 to-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.6)]';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 group flex flex-col justify-between">
      
      {/* Top Live Risk Indicator Accent Bar */}
      <div className={`h-1.5 w-full ${accentBarClass} transition-all duration-500`} />

      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-teal-500/10 border border-teal-500/20 rounded-2xl text-teal-400 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.vpnAnalysisTitle}</h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'شناسایی و تشخیص دقیق پروتکل‌های VPN و تونلینگ' : 'Accurate VPN Protocol & Tunnel Fingerprinting'}
              </p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold ${
            isDatacenter 
              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shadow-md' 
              : 'bg-amber-950/80 text-amber-400 border border-amber-800/60 shadow-md'
          }`}>
            {isDatacenter ? (isFa ? 'پوشش VPN فعال' : 'VPN Active') : (isFa ? 'اتصال مستقیم ISP' : 'Direct ISP')}
          </span>
        </div>

        {/* Status Callout */}
        <div className={`p-4 rounded-2xl border mb-5 flex items-start gap-3 shadow-inner ${
          isDatacenter 
            ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200' 
            : 'bg-amber-950/40 border-amber-800/60 text-amber-200'
        }`}>
          {isDatacenter ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="text-xs leading-relaxed">
            <span className="font-bold block mb-0.5">
              {isDatacenter ? (isFa ? 'پروتکل تونل رمزشده شناسایی شد' : 'Encrypted Tunnel Protocol Detected') : (isFa ? 'عدم استفاده از VPN' : 'Direct Unprotected Connection')}
            </span>
            <p className="text-slate-300">
              {vpnProxy ? (isFa ? vpnProxy.messageFa : vpnProxy.messageEn) : (isFa ? 'در حال تحلیل...' : 'Analyzing...')}
            </p>
          </div>
        </div>

        {/* Protocol Fingerprint Inspection Grid */}
        <div className="space-y-3">
          
          {/* Main Detected Protocol Badge */}
          <div className="bg-slate-950/80 border border-slate-800/80 p-3.5 rounded-2xl flex items-center justify-between shadow-inner">
            <div className="flex items-center gap-2.5">
              <Layers className="w-4 h-4 text-teal-400 shrink-0" />
              <div>
                <span className="text-slate-400 text-[11px] block">{isFa ? 'پروتکل بستر ارتباطی:' : 'Detected Substrate:'}</span>
                <span className="text-sm font-bold text-white font-mono">{protoDetails?.name || vpnProxy?.protocolType || '---'}</span>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-teal-300 bg-teal-950/80 border border-teal-800 px-2.5 py-1 rounded-xl">
              {protoDetails?.code?.toUpperCase() || 'VPN'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            {/* Encryption Algorithm */}
            <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl shadow-inner">
              <span className="text-slate-400 font-semibold block mb-1">{t.encryptionLevel}</span>
              <div className="flex items-center gap-2 text-xs font-bold text-slate-100">
                <KeyRound className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="text-cyan-300">{protoDetails?.encryptionNameFa || vpnProxy?.encryptionStrength || '---'}</span>
              </div>
            </div>

            {/* Estimated MTU Header Overhead */}
            <div className="bg-slate-950/70 border border-slate-800/80 p-3.5 rounded-2xl shadow-inner">
              <span className="text-slate-400 font-semibold block mb-1">{isFa ? 'تخمین اندازه MTU:' : 'Estimated MTU:'}</span>
              <div className="flex items-center gap-2 text-xs font-bold text-slate-100 font-mono">
                <Radio className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{protoDetails ? `${protoDetails.estimatedMtu} Bytes` : '1500 Bytes'}</span>
              </div>
            </div>
          </div>

          {/* Obfuscation & Camouflage Status */}
          <div className="bg-slate-950/90 border border-slate-800 p-3.5 rounded-2xl text-xs space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-teal-400">
              <Cpu className="w-3.5 h-3.5" />
              <span>{isFa ? 'تحلیل پنهان‌سازی و خصیصه تونل:' : 'Tunnel Obfuscation Analysis:'}</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              {protoDetails?.descriptionFa || 'اتصال مستقیم شبکه بدون عبور از تونل‌های رمزشده VPN.'}
            </p>
          </div>

        </div>

      </div>

      {/* Footer */}
      <div className="mt-5 pt-3 border-t border-slate-800/60 text-[11px] text-slate-400">
        <p>
          {isFa
            ? 'شناسایی پروتکل بر اساس تحلیل الگوی MTU، پورت‌های خروجی و ساختار شبکه انجام گرفته است.'
            : 'Protocol identification analyzed via MTU packet overhead, egress ports, and network signatures.'}
        </p>
      </div>
    </div>
  );
};
