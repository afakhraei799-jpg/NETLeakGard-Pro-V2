import React, { useState } from 'react';
import { Activity, Gauge, RefreshCw, Zap, ArrowDownCircle, Waves } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { NetworkMetrics, Language } from '../types/network';
import { translations } from '../i18n/translations';
import { measurePingAndSpeed } from '../services/networkTester';

interface SpeedPingCardProps {
  metrics: NetworkMetrics | null;
  onUpdateMetrics: (newMetrics: NetworkMetrics) => void;
  lang: Language;
}

export const SpeedPingCard: React.FC<SpeedPingCardProps> = ({ metrics, onUpdateMetrics, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';
  const [isRunning, setIsRunning] = useState(false);

  const handleRunSpeedTest = async () => {
    setIsRunning(true);
    try {
      const newM = await measurePingAndSpeed();
      onUpdateMetrics(newM);
    } catch (e) {
      console.warn('Speed test error', e);
    } finally {
      setIsRunning(false);
    }
  };

  const pingSamplesData = (metrics?.pingSamples || [24, 28, 22, 31, 25, 29, 23, 27]).map((val, idx) => ({
    packet: `پکت ${idx + 1}`,
    ping: val,
  }));

  const stabilityScore = metrics?.stabilityScore ?? 98;
  const stabilityStatusFa = metrics?.stabilityStatusFa ?? 'پایدار و عالی';

  const accentBarClass = stabilityScore >= 85 
    ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]' 
    : stabilityScore >= 60 
      ? 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500 shadow-[0_0_12px_rgba(245,158,11,0.6)]' 
      : 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_12px_rgba(244,63,94,0.6)]';

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-slate-950/90 border border-amber-500/50 p-2 rounded-xl text-xs shadow-xl font-mono text-amber-300">
          <span>{data.packet}: </span>
          <span className="font-bold text-white">{data.ping} ms</span>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 group flex flex-col justify-between">
      
      {/* Top Live Risk Indicator Accent Bar */}
      <div className={`h-1.5 w-full ${accentBarClass} transition-all duration-500`} />

      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-2xl text-amber-400 group-hover:scale-105 transition-transform">
              <Gauge className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white">{t.speedDiagnosticsTitle}</h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'سنجش پینگ، نوسان Jitter و ثبات پایداری اتصال' : 'Latency, Jitter & Connection Stability Benchmark'}
              </p>
            </div>
          </div>

          <button
            onClick={handleRunSpeedTest}
            disabled={isRunning}
            className="flex items-center gap-1.5 bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs px-3.5 py-1.5 rounded-xl border border-slate-700 transition-all font-semibold"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin text-amber-400' : ''}`} />
            <span>{t.startSpeedTest}</span>
          </button>
        </div>

        {/* 3 Metric Gauges */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center mb-5">
          <div className="bg-slate-950/80 border border-slate-800/80 p-3.5 rounded-2xl flex flex-col items-center justify-center hover:border-amber-500/30 transition-colors shadow-inner">
            <Zap className="w-4 h-4 text-amber-400 mb-1" />
            <span className="text-slate-400 text-[11px] font-semibold mb-0.5">{t.pingMs}</span>
            <div className="flex items-baseline gap-1">
              <span className="text-xl font-extrabold font-mono text-white">
                {metrics?.pingMs ?? 28}
              </span>
              <span className="text-[10px] text-slate-400">ms</span>
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-3.5 rounded-2xl flex flex-col items-center justify-center hover:border-cyan-500/30 transition-colors shadow-inner">
            <Activity className="w-4 h-4 text-cyan-400 mb-1" />
            <span className="text-slate-400 text-[11px] font-semibold mb-0.5">{t.jitterMs}</span>
            <div className="flex items-baseline gap-1">
              <span className="text-xl font-extrabold font-mono text-white">
                {metrics?.jitterMs ?? 3}
              </span>
              <span className="text-[10px] text-slate-400">ms</span>
            </div>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-3.5 rounded-2xl flex flex-col items-center justify-center hover:border-emerald-500/30 transition-colors shadow-inner">
            <ArrowDownCircle className="w-4 h-4 text-emerald-400 mb-1" />
            <span className="text-slate-400 text-[11px] font-semibold mb-0.5">{t.downloadSpeed}</span>
            <div className="flex items-baseline gap-1">
              <span className="text-xl font-extrabold font-mono text-white">
                {metrics?.downloadMbps ?? 22.4}
              </span>
              <span className="text-[10px] text-slate-400">Mbps</span>
            </div>
          </div>
        </div>

        {/* Connection Stability */}
        <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-3 shadow-inner">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
              <Waves className="w-4 h-4 text-amber-400" />
              <span>{isFa ? 'تحلیل ثبات پایداری اتصال (Jitter Fluctuation)' : 'Connection Stability & Jitter Chart'}</span>
            </div>
            <span className="font-mono text-[11px] font-bold text-amber-300 bg-amber-950/80 border border-amber-800/60 px-2.5 py-0.5 rounded-lg">
              {stabilityStatusFa}
            </span>
          </div>

          <div className="h-28 w-full pt-1">
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

          <div className="flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
            <span>{isFa ? 'شاخص پایداری خط:' : 'Stability Score:'}</span>
            <span className="text-amber-300 font-bold">{stabilityScore}%</span>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 pt-3 border-t border-slate-800/60 text-[11px] text-slate-400">
          <p>
            {isFa
              ? 'نمودار نوسانات تاخیر (Jitter) پایداری پکت‌های متوالی شبکه را ارزیابی می‌کند.'
              : 'Latency Jitter chart evaluates packet delivery stability over 8 consecutive probes.'}
          </p>
        </div>
      </div>
    </div>
  );
};
