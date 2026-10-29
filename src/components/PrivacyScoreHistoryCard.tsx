import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { TrendingUp, History, Trash2, ShieldCheck } from 'lucide-react';
import { Language } from '../types/network';

export interface ScoreHistoryPoint {
  id: string;
  timestamp: string;
  fullDate: string;
  score: number;
  ip: string;
  statusFa: string;
}

interface PrivacyScoreHistoryCardProps {
  history: ScoreHistoryPoint[];
  onClearHistory: () => void;
  lang: Language;
}

export const PrivacyScoreHistoryCard: React.FC<PrivacyScoreHistoryCardProps> = ({
  history,
  onClearHistory,
  lang,
}) => {
  const isFa = lang === 'fa';

  const latestScore = history.length > 0 ? history[history.length - 1].score : 100;
  const accentBarClass = latestScore >= 80 
    ? 'bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]' 
    : latestScore >= 50 
      ? 'bg-gradient-to-r from-amber-400 via-amber-500 to-yellow-500 shadow-[0_0_12px_rgba(245,158,11,0.6)]' 
      : 'bg-gradient-to-r from-rose-500 via-red-500 to-rose-600 shadow-[0_0_12px_rgba(244,63,94,0.6)]';

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data: ScoreHistoryPoint = payload[0].payload;
      return (
        <div className="bg-slate-950/95 border border-cyan-800/80 p-3 rounded-2xl shadow-2xl text-xs space-y-1 z-50">
          <div className="flex items-center justify-between gap-4 font-bold border-b border-slate-800 pb-1 text-slate-200">
            <span>{isFa ? 'زمان تست:' : 'Test Time:'} {data.timestamp}</span>
            <span className="font-mono text-cyan-400">{data.score} / 100</span>
          </div>
          <div className="text-slate-300 font-mono text-[11px]">
            <span>IP: {data.ip}</span>
          </div>
          <div className="text-[11px] font-semibold text-emerald-400">
            <span>{data.statusFa}</span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card transition-all duration-300 group hover:border-cyan-500/40">
      
      {/* Top Live Risk Indicator Accent Bar */}
      <div className={`h-1.5 w-full ${accentBarClass} transition-all duration-500`} />

      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-2xl text-cyan-400 group-hover:scale-110 transition-transform">
              <TrendingUp className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white flex items-center gap-2">
                <span>{isFa ? 'روند تغییرات امتیاز امنیت' : 'Privacy Score Trend'}</span>
                <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded-md font-semibold">
                  Recharts
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'تاریخچه و نمودار خطی تغییرات شاخص حریم خصوصی در هر بار اجرای آزمایش' : 'Historical privacy score progression per diagnostic run'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {history.length > 0 && (
              <button
                onClick={onClearHistory}
                className="p-2 text-slate-400 hover:text-rose-400 bg-slate-950/80 hover:bg-rose-950/40 border border-slate-800 hover:border-rose-800 rounded-xl transition-colors"
                title={isFa ? 'پاکسازی تاریخچه' : 'Clear History'}
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
            <span className="font-mono text-xs font-bold text-cyan-300 bg-cyan-950/80 border border-cyan-800/60 px-3 py-1 rounded-xl shadow-md">
              {isFa ? `${history.length} نوبت تست` : `${history.length} Runs`}
            </span>
          </div>
        </div>

        {/* Chart Canvas */}
        <div className="h-64 w-full">
          {history.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="timestamp"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={{ stroke: '#334155' }}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={{ stroke: '#334155' }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#06b6d4"
                  strokeWidth={3}
                  fillOpacity={1}
                  fill="url(#colorScore)"
                  dot={{ r: 4, fill: '#06b6d4', stroke: '#083344', strokeWidth: 2 }}
                  activeDot={{ r: 7, fill: '#10b981', stroke: '#ffffff', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="w-full h-full flex flex-col items-center justify-center text-slate-500 space-y-2 border border-dashed border-slate-800 rounded-2xl">
              <History className="w-8 h-8 text-slate-600" />
              <span className="text-xs font-medium">
                {isFa ? 'هنوز هیچ داده‌ای برای ثبت در نمودار ذخیره نشده است.' : 'No score history recorded yet.'}
              </span>
            </div>
          )}
        </div>

        {/* Footer Info */}
        <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isFa ? 'ذخیره‌سازی خودکار در حافظه مرورگر (LocalStorage)' : 'Auto-saved locally in browser storage'}</span>
          </div>
        </div>
      </div>

    </div>
  );
};
