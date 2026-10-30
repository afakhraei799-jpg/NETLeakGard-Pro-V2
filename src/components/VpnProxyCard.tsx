import React from 'react';
import { Lock, AlertTriangle, ShieldCheck, Layers, HelpCircle, Clock, Info } from 'lucide-react';
import { VpnProxyResult, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface VpnProxyCardProps {
  vpnProxy: VpnProxyResult | null;
  lang: Language;
}

export const VpnProxyCard: React.FC<VpnProxyCardProps> = ({ vpnProxy, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const statusBadge = formatStatusBadgeFa(vpnProxy?.status, isFa);
  const isDatacenter = vpnProxy?.isDatacenterIp === true;

  const accentBarClass =
    vpnProxy?.status === 'PASS'
      ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
      : 'bg-gradient-to-r from-amber-400 via-yellow-500 to-amber-500';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4 flex-1">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-teal-500/10 border border-teal-500/20 rounded-2xl text-teal-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.vpnAnalysisTitle}</h3>
              <p className="text-[11px] text-slate-400">
                {isFa ? 'طبقه‌بندی احتمالی شبکه خروجی (بدون ادعای قطعی پروتکل تونل)' : 'Probabilistic ASN classification & browser boundary disclosure'}
              </p>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-xl text-xs font-bold bg-slate-950 border border-slate-800 shrink-0 whitespace-nowrap ${statusBadge.colorClass}`}>
            {statusBadge.text}
          </span>
        </div>

        {/* Status Callout */}
        <div className={`p-3.5 rounded-2xl border flex items-start gap-2.5 text-xs ${
          isDatacenter
            ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
            : 'bg-amber-950/40 border-amber-800/60 text-amber-200'
        }`}>
          {vpnProxy?.status === 'INCONCLUSIVE' ? (
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          ) : isDatacenter ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="leading-relaxed">
            <span className="font-bold block mb-0.5">
              {vpnProxy?.isDatacenterIp === null
                ? isFa
                  ? 'طبقه‌بندی نامشخص'
                  : 'Inconclusive Classification'
                : isDatacenter
                  ? isFa
                    ? 'احتمالاً خروجی دیتاسنتر / هاستینگ (سطح اطمینان: متوسط)'
                    : 'Probable Datacenter Egress (Medium Confidence)'
                  : isFa
                    ? 'احتمالاً اتصال مستقیم ISP (سطح اطمینان: متوسط)'
                    : 'Probable Direct ISP (Medium Confidence)'}
            </span>
            <p className="text-slate-300 text-[11px]">
              {vpnProxy
                ? isFa
                  ? vpnProxy.messageFa
                  : vpnProxy.messageEn
                : isFa
                  ? 'در انتظار اجرای آزمون...'
                  : 'Awaiting test execution...'}
            </p>
          </div>
        </div>

        {/* Honest Protocol Boundary Disclosure */}
        <div className="space-y-2.5 text-xs">
          <div className="bg-slate-950/80 border border-slate-800/80 p-3.5 rounded-2xl flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Layers className="w-4 h-4 text-teal-400 shrink-0" />
              <div>
                <span className="text-slate-400 text-[11px] block">
                  {isFa ? 'نوع پروتکل تونل (WireGuard / OpenVPN / ...):' : 'Tunnel Protocol:'}
                </span>
                <span className="text-xs font-bold text-amber-300">
                  {isFa
                    ? 'غیرقابل اثبات از طریق مرورگر (Unprovable via Web)'
                    : 'Unprovable from Browser HTTP Layer'}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-slate-950/90 border border-slate-800 p-3.5 rounded-2xl text-[11px] text-slate-300 leading-relaxed">
            {vpnProxy?.protocolDetails.descriptionFa ||
              (isFa
                ? 'مرورگر وب فقط به لایهٔ کاربرد (HTTP/WebRTC) دسترسی دارد و نمی‌تواند هدر بسته‌های سطح هستهٔ سیستم‌عامل یا اندازهٔ واقعی MTU تونل VPN را مشاهده و اثبات کند.'
                : 'Web browsers only see application-layer traffic and cannot prove kernel-level VPN tunnel protocols or MTU.')}
          </div>
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {vpnProxy?.completedAt ? new Date(vpnProxy.completedAt).toLocaleTimeString('fa-IR') : '---'}
            </span>
            <span>اطمینان طبقه‌بندی: {vpnProxy?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-teal-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'صرفاً از روی نام ISP یا ASN نمی‌توان روشن یا خاموش بودن VPN را به صورت قطعی اثبات کرد.'
                : 'ISP/ASN name alone cannot conclusively prove whether a VPN is active.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
