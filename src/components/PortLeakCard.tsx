import React from 'react';
import {
  Router,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Clock,
  Info,
  RefreshCw,
  Lock,
  Unlock
} from 'lucide-react';
import { Language, PortLeakResult, PortProbeState } from '../types/network';
import { translations } from '../i18n/translations';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface PortLeakCardProps {
  portLeak: PortLeakResult | null;
  onRetestPorts?: () => void;
  isTesting?: boolean;
  lang: Language;
}

function formatPortStateBadge(state: PortProbeState, isFa: boolean): {
  label: string;
  badgeClass: string;
} {
  switch (state) {
    case 'open':
      return {
        label: isFa ? 'پورت باز (پاسخ TCP)' : 'OPEN (TCP)',
        badgeClass: 'bg-rose-950/80 border-rose-700/80 text-rose-300',
      };
    case 'closed':
      return {
        label: isFa ? 'بسته (Closed)' : 'CLOSED',
        badgeClass: 'bg-emerald-950/70 border-emerald-700/70 text-emerald-300',
      };
    case 'filtered_timeout':
      return {
        label: isFa ? 'فیلتر / فایروال' : 'FILTERED',
        badgeClass: 'bg-cyan-950/60 border-cyan-800/70 text-cyan-300',
      };
    default:
      return {
        label: isFa ? 'بررسی‌نشده' : 'NOT TESTED',
        badgeClass: 'bg-slate-900 border-slate-800 text-slate-400',
      };
  }
}

export const PortLeakCard: React.FC<PortLeakCardProps> = ({
  portLeak,
  onRetestPorts,
  isTesting = false,
  lang,
}) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  const statusBadge = formatStatusBadgeFa(portLeak?.status, isFa);

  const accentBarClass =
    portLeak?.status === 'LEAK_DETECTED' || portLeak?.status === 'ERROR'
      ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600'
      : portLeak?.status === 'PASS'
        ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
        : 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500';

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4 flex-1 flex flex-col justify-between">
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-2xl text-amber-400">
                <Router className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-extrabold text-white">{t.portLeakTitle}</h3>
                <p className="text-[11px] text-slate-400">
                  {isFa
                    ? 'بررسی هندشیک TCP روی پورت‌های متداول (۸۰، ۴۴۳، ۸۰۸۰، ۸۲۹۱، ۲۲، ۲۳، ۲۱، ۱۰۸۰)'
                    : 'Public Egress TCP Handshake Probe on Common Service Ports'}
                </p>
              </div>
            </div>
            <span
              className={`px-3 py-1 rounded-xl text-xs font-bold bg-slate-950 border border-slate-800 shrink-0 whitespace-nowrap ${statusBadge.colorClass}`}
            >
              {statusBadge.text}
            </span>
          </div>

          {/* Target Socket IP & Summary Counter */}
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="bg-slate-950/80 border border-slate-800 p-3 rounded-xl">
              <span className="text-slate-400 block text-[10px] mb-0.5">
                {isFa ? 'IP سوکت هدف در سرور:' : 'Target Socket IP:'}
              </span>
              <span dir="ltr" className="font-mono font-bold text-cyan-300 text-xs block truncate">
                {portLeak?.targetIp || (isFa ? 'محلی / غیرعمومی' : 'Local / Non-Public')}
              </span>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 p-3 rounded-xl flex items-center justify-between">
              <div>
                <span className="text-slate-400 block text-[10px] mb-0.5">
                  {isFa ? 'پورت‌های باز حساس:' : 'Open Sensitive Ports:'}
                </span>
                <span
                  className={`font-mono font-extrabold text-sm ${
                    portLeak && portLeak.openPortsCount > 0 ? 'text-rose-400' : 'text-slate-200'
                  }`}
                >
                  {portLeak?.canScanFromServer
                    ? `${portLeak.openPortsCount} / ${portLeak.scannedPortsCount}`
                    : isFa
                      ? 'نامشخص'
                      : 'N/A'}
                </span>
              </div>
              {onRetestPorts && (
                <button
                  onClick={onRetestPorts}
                  disabled={isTesting}
                  title={isFa ? 'تکرار بررسی پورت‌ها' : 'Retest Ports'}
                  className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 transition-colors cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
                </button>
              )}
            </div>
          </div>

          {/* Status Callout */}
          <div
            className={`p-3.5 rounded-2xl border flex items-start gap-2.5 text-xs ${
              portLeak?.status === 'LEAK_DETECTED' || portLeak?.status === 'ERROR'
                ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
                : portLeak?.status === 'PASS'
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
                  : 'bg-amber-950/30 border-amber-800/50 text-amber-200'
            }`}
          >
            {portLeak?.status === 'PASS' ? (
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : portLeak?.status === 'LEAK_DETECTED' || portLeak?.status === 'ERROR' ? (
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            ) : (
              <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            )}
            <div className="leading-relaxed">
              <span className="font-bold block mb-0.5">{statusBadge.text}</span>
              <p className="text-slate-300 text-[11px]">
                {portLeak
                  ? isFa
                    ? portLeak.messageFa
                    : portLeak.messageEn
                  : isFa
                    ? 'در حال بررسی پورت‌های مدیریت روتر و سرویس‌های حساس...'
                    : 'Probing sensitive router and proxy ports...'}
              </p>
            </div>
          </div>

          {/* Sensitive Ports Table */}
          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
            {(portLeak?.ports || []).map(entry => {
              const badge = formatPortStateBadge(entry.state, isFa);
              return (
                <div
                  key={entry.port}
                  className="bg-slate-950/85 border border-slate-800/80 px-3 py-2 rounded-xl flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {entry.state === 'open' ? (
                      <Unlock className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : (
                      <Lock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    )}
                    <div className="truncate">
                      <div className="flex items-center gap-1.5">
                        <span dir="ltr" className="font-mono font-extrabold text-cyan-300">
                          TCP/{entry.port}
                        </span>
                        <span className="text-slate-200 font-bold truncate">
                          {entry.serviceName}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-400 block truncate">
                        {isFa ? entry.descriptionFa : entry.descriptionEn}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {entry.responseTimeMs !== null && (
                      <span dir="ltr" className="font-mono text-[10px] text-slate-400">
                        {entry.responseTimeMs}ms
                      </span>
                    )}
                    <span
                      className={`px-2 py-0.5 rounded-lg border text-[10px] font-bold ${badge.badgeClass}`}
                    >
                      {badge.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {portLeak?.completedAt
                ? new Date(portLeak.completedAt).toLocaleTimeString('fa-IR')
                : '---'}
            </span>
            <span>اطمینان: {portLeak?.confidence || 'none'}</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'محدودیت فنی: برای جلوگیری از حملات SSRF، سرور تنها سوکت عمومی تأییدشدهٔ کلاینت را بررسی می‌کند. در محیط لوکال یا پشت CGNAT، نتیجه به صورت «نامشخص» گزارش می‌شود.'
                : 'To prevent SSRF, only verified public client socket IPs are probed. Localhost or CGNAT connections are reported as Inconclusive.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
