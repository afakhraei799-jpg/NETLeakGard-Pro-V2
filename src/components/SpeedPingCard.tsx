import React, { useState, useRef } from 'react';
import { Activity, Gauge, RefreshCw, Zap, ArrowDownCircle, Waves, XCircle, Clock, Info } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { NetworkMetrics, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { measurePingAndSpeed } from '../services/networkTester';
import { formatStatusBadgeFa } from './HeroScoreBanner';

interface SpeedPingCardProps {
  metrics: NetworkMetrics | null;
  onUpdateMetrics: (newMetrics: NetworkMetrics) => void;
  lang: Language;
}

export const SpeedPingCard: React.FC<SpeedPingCardProps> = ({ metrics, onUpdateMetrics, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';
  const [isRunning, setIsRunning] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);

  const handleRunSpeedTest = async () => {
    if (isRunning) {
      abortControllerRef.current?.abort();
      setIsRunning(false);
      return;
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;
    setIsRunning(true);
    try {
      const newM = await measurePingAndSpeed(controller.signal);
      onUpdateMetrics(newM);
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
    }
  };

  const statusBadge = formatStatusBadgeFa(metrics?.status, isFa);

  // Strictly use real measured samples — NEVER substitute fallback array [24, 28, ...]
  const realSamples = metrics?.pingSamples || [];
  const pingSamplesData = realSamples.map((val, idx) => ({
    packet: `#${idx + 1}`,
    ping: val,
  }));

  const accentBarClass =
    metrics?.status === 'ERROR'
      ? 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600'
      : metrics?.status === 'PASS'
        ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500'
        : 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500';

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-slate-950/90 border border-amber-500/50 p-2 rounded-xl text-xs shadow-xl font-mono text-amber-300">
          <span>{data.packet}: </span>
          <span className="font-bold text-white">{data.ping} ms (HTTP RTT)</span>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 flex flex-col justify-between">
      <div className={`h-1.5 w-full ${accentBarClass}`} />

      <div className="p-6 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-2xl text-amber-400">
              <Gauge className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">
                {isFa ? 'زمان پاسخ HTTP RTT، جیتر و سرعت' : 'HTTP RTT Latency, Jitter & Speed'}
              </h3>
              <p className="text-[11px] text-slate-400">
                {isFa ? 'اندازه‌گیری واقعی زمان رفت‌وبرگشت HTTP (نه پینگ ICMP)' : 'Real HTTP Round-Trip Time (not ICMP Ping)'}
              </p>
            </div>
          </div>

          <button
            onClick={handleRunSpeedTest}
            className="flex items-center gap-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs px-3 py-1.5 rounded-xl border border-slate-700 transition-all font-semibold cursor-pointer"
          >
            {isRunning ? (
              <>
                <XCircle className="w-3.5 h-3.5 text-rose-400" />
                <span>{isFa ? 'لغو تست' : 'Cancel'}</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
                <span>{t.startSpeedTest}</span>
              </>
            )}
          </button>
        </div>

        {/* 4 Real Metric Gauges (No hardcoded fallback numbers!) */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-center">
          <div className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-2xl flex flex-col items-center justify-center">
            <Zap className="w-4 h-4 text-amber-400 mb-1" />
            <span className="text-slate-400 text-[10px] font-semibold">HTTP RTT</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-lg font-extrabold font-mono text-white">
                {metrics?.pingMs !== null && metrics?.pingMs !== undefined ? metrics.pingMs : '---'}
              </span>
              {metrics?.pingMs !== null && metrics?.pingMs !== undefined && (
                <span className="text-[10px] text-slate-400">ms</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-2xl flex flex-col items-center justify-center">
            <Activity className="w-4 h-4 text-cyan-400 mb-1" />
            <span className="text-slate-400 text-[10px] font-semibold">{t.jitterMs}</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-lg font-extrabold font-mono text-white">
                {metrics?.jitterMs !== null && metrics?.jitterMs !== undefined ? metrics.jitterMs : '---'}
              </span>
              {metrics?.jitterMs !== null && metrics?.jitterMs !== undefined && (
                <span className="text-[10px] text-slate-400">ms</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-2xl flex flex-col items-center justify-center">
            <ArrowDownCircle className="w-4 h-4 text-emerald-400 mb-1" />
            <span className="text-slate-400 text-[10px] font-semibold">{t.downloadSpeed}</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-lg font-extrabold font-mono text-white">
                {metrics?.downloadMbps !== null && metrics?.downloadMbps !== undefined ? metrics.downloadMbps : '---'}
              </span>
              {metrics?.downloadMbps !== null && metrics?.downloadMbps !== undefined && (
                <span className="text-[10px] text-slate-400">Mbps</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-3 rounded-2xl flex flex-col items-center justify-center">
            <Waves className="w-4 h-4 text-rose-400 mb-1" />
            <span className="text-slate-400 text-[10px] font-semibold">{t.packetLoss}</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className="text-lg font-extrabold font-mono text-white">
                {metrics?.packetLossPercent !== null && metrics?.packetLossPercent !== undefined
                  ? `${metrics.packetLossPercent}%`
                  : '---'}
              </span>
            </div>
          </div>
        </div>

        {/* Connection Stability & Real Samples Chart */}
        <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
              <Waves className="w-4 h-4 text-amber-400" />
              <span>{isFa ? 'نمودار نوسانات HTTP RTT (بدون داده ساختگی)' : 'Measured HTTP RTT Samples'}</span>
            </div>
            <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded-lg ${statusBadge.colorClass}`}>
              {metrics?.stabilityStatusFa || statusBadge.text}
            </span>
          </div>

          {pingSamplesData.length > 0 ? (
            <div className="h-24 w-full pt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={pingSamplesData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorJitter" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="packet" stroke="#475569" tick={{ fill: '#64748b', fontSize: 10 }} />
                  <YAxis stroke="#475569" tick={{ fill: '#64748b', fontSize: 10 }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="ping"
                    stroke="#f59e0b"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#colorJitter)"
                    dot={{ r: 3, fill: '#f59e0b' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-20 flex items-center justify-center text-[11px] text-slate-500 border border-dashed border-slate-800 rounded-xl">
              {metrics?.status === 'ERROR'
                ? isFa
                  ? 'خطا در اندازه‌گیری: هیچ نمونهٔ معتبری ثبت نشد.'
                  : 'Measurement error: No valid samples recorded.'
                : isFa
                  ? 'هنوز نمونهٔ HTTP RTT ثبت نشده است.'
                  : 'No HTTP RTT samples recorded yet.'}
            </div>
          )}

          <div className="flex items-center justify-between text-[10px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
            <span>
              {isFa
                ? `نمونه‌های موفق: ${metrics?.probesReceived ?? 0} از ${metrics?.probesSent ?? 0}`
                : `Probes: ${metrics?.probesReceived ?? 0}/${metrics?.probesSent ?? 0}`}
            </span>
            <span>
              {isFa
                ? `حجم تست دانلود: ${metrics?.bytesTransferred ? `${Math.round(metrics.bytesTransferred / 1024)} KB` : '0 KB'}`
                : `Payload: ${metrics?.bytesTransferred ? `${Math.round(metrics.bytesTransferred / 1024)} KB` : '0 KB'}`}
            </span>
          </div>
        </div>

        {/* Metadata & Limitations Footer */}
        <div className="pt-2 border-t border-slate-800/60 space-y-1.5 text-[11px] text-slate-400">
          <div className="flex items-center justify-between font-mono text-[10px] text-slate-500">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {metrics?.completedAt ? new Date(metrics.completedAt).toLocaleTimeString('fa-IR') : '---'}
            </span>
            <span>روش: HTTP_RTT</span>
          </div>
          <div className="flex items-start gap-1.5">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
            <p>
              {isFa
                ? 'به دلیل عدم دسترسی مرورگر به سوکت خام ICMP، تاخیر بر اساس درخواست HTTP به سرور برنامه اندازه‌گیری شده است.'
                : 'Measured via HTTP request timing to the app endpoint, not raw ICMP Echo.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
