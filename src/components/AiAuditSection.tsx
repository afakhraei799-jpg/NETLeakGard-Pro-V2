import React, { useState } from 'react';
import { Sparkles, ShieldCheck, AlertTriangle, CheckCircle, ArrowLeft, Navigation, Zap, Lock, Server, Copy, Check } from 'lucide-react';
import { AiAuditReport, Language } from '../types/network';
import { translations } from '../i18n/translations';

interface AiAuditSectionProps {
  aiAudit: AiAuditReport | null;
  lang: Language;
}

export const AiAuditSection: React.FC<AiAuditSectionProps> = ({ aiAudit, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!aiAudit) return null;

  const node = aiAudit.optimalNodeSuggestion;
  const dnsList = aiAudit.dnsRecommendations || [];

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-gradient-to-br from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl mb-8 space-y-6">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 rounded-2xl text-cyan-400">
            <Sparkles className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span>{t.aiAuditTitle}</span>
              <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded-md font-semibold">
                {aiAudit.aiAvailable ? 'Gemini 3 Flash' : (isFa ? 'تحلیل قواعد محلی' : 'Rule-based Analysis')}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              {isFa ? 'تحلیل خودکار شواهد شبکه و ارائه سرورهای DNS رمزنگاری‌شده' : 'Automated network evidence analysis & encrypted DNS recommendations'}
            </p>
          </div>
        </div>

        {/* Risk Score Pill */}
        <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 px-3.5 py-1.5 rounded-xl">
          <span className="text-xs text-slate-400 font-medium">{isFa ? 'شاخص ریسک:' : 'Risk Index:'}</span>
          {aiAudit.riskScore !== null ? (
            <span className={`font-mono font-extrabold text-sm ${aiAudit.riskScore > 30 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {aiAudit.riskScore}%
            </span>
          ) : (
            <span className="font-mono font-bold text-xs text-amber-400">
              {isFa ? 'نامشخص (شواهد ناکافی)' : 'N/A (Incomplete)'}
            </span>
          )}
        </div>
      </div>

      {/* Summary Box */}
      <div className="bg-slate-950/80 border border-slate-800/90 p-5 rounded-2xl">
        <p className="text-sm text-slate-200 leading-relaxed font-medium">
          {aiAudit.summaryFa}
        </p>
      </div>

      {/* Optimal VPN Node Suggestion Card */}
      {node && (
        <div className="bg-slate-950/90 border border-cyan-500/30 p-5 rounded-2xl space-y-3 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5 text-cyan-400 font-bold text-sm">
              <Navigation className="w-5 h-5 text-cyan-400" />
              <span>{isFa ? 'پیشنهاد نقطه اتصال بهینه (Optimal VPN Node)' : 'Optimal VPN Node Suggestion'}</span>
            </div>
            <span className="text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 px-2.5 py-0.5 rounded-lg">
              {node.privacyRatingFa}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="bg-slate-900 border border-slate-800 p-3 rounded-xl">
              <span className="text-slate-400 block mb-1 font-semibold">{isFa ? 'کشور و شهر پیشنهادی:' : 'Suggested Location:'}</span>
              <span className="text-sm font-bold text-white">{node.recommendedCountryNameFa} - {node.recommendedCityFa}</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-xl">
              <span className="text-slate-400 block mb-1 font-semibold">{isFa ? 'تخمین تاخیر پینگ:' : 'Estimated Ping:'}</span>
              <div className="flex items-center gap-1.5 text-sm font-bold text-emerald-400 font-mono">
                <Zap className="w-4 h-4" />
                <span>
                  {node.estimatedPingMs !== null
                    ? `~ ${node.estimatedPingMs} ms`
                    : (isFa ? 'برآورد نشده' : 'Not measured')}
                </span>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-xl">
              <span className="text-slate-400 block mb-1 font-semibold">{isFa ? 'پروتکل‌های پیشنهادی:' : 'Suggested Protocols:'}</span>
              <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300 font-mono">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                <span>{node.recommendedProtocolsFa.join(' / ')}</span>
              </div>
            </div>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed pt-1">
            {node.recommendationReasonFa}
          </p>
        </div>
      )}

      {/* Encrypted & Unfiltered DoH DNS Recommendations */}
      {dnsList.length > 0 && (
        <div className="bg-slate-950/90 border border-purple-500/30 p-5 rounded-2xl space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5 text-purple-400 font-bold text-sm">
              <Server className="w-5 h-5 text-purple-400" />
              <span>{isFa ? 'سرورهای DNS رمزنگاری‌شده پیشنهادی (Encrypted DoH)' : 'Recommended Encrypted DoH DNS Resolvers'}</span>
            </div>
            <span className="text-xs font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800 px-2.5 py-0.5 rounded-lg">
              {isFa ? 'DoH / DoT رمزنگاری‌شده' : 'DoH / DoT Encrypted'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {dnsList.map((dns) => (
              <div key={dns.id} className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl space-y-2 flex flex-col justify-between hover:border-purple-500/40 transition-colors">
                <div>
                  <div className="flex items-center justify-between font-bold text-white mb-1">
                    <span>{dns.nameFa}</span>
                    <span className="font-mono text-slate-400 text-[11px]">
                      {dns.estimatedPingMs !== null ? `${dns.estimatedPingMs} ms` : (isFa ? 'مرجع عمومی' : 'Public DoH')}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mb-2">{dns.unfilteredStatusFa}</p>
                </div>

                {/* DoH Copy URL Box */}
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between font-mono text-[11px] text-cyan-300">
                  <span className="truncate mr-2">{dns.dohUrl}</span>
                  <button
                    onClick={() => handleCopy(dns.id, dns.dohUrl)}
                    className="p-1.5 text-slate-400 hover:text-white bg-slate-800 rounded-md shrink-0 transition-colors cursor-pointer"
                    title={isFa ? 'کپی آدرس DoH' : 'Copy DoH URL'}
                  >
                    {copiedId === dns.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detailed Analysis & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        <div className="bg-slate-950/60 border border-slate-800/70 p-5 rounded-2xl space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2 mb-3">
            <ShieldCheck className="w-4 h-4" />
            <span>{isFa ? 'ارزیابی لایه‌های امنیتی شبکه' : 'Layered Security Analysis'}</span>
          </h4>

          <ul className="space-y-2.5 text-xs text-slate-300">
            {aiAudit.detailedAnalysisFa.map((item, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{item}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/70 p-5 rounded-2xl space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4" />
            <span>{isFa ? 'دستورالعمل‌ها و راهکارهای پیشنهادی' : 'Actionable Security Recommendations'}</span>
          </h4>

          <ul className="space-y-2.5 text-xs text-slate-300">
            {aiAudit.recommendationsFa.map((rec, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <ArrowLeft className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{rec}</span>
              </li>
            ))}
          </ul>
        </div>

      </div>
    </div>
  );
};
