import React from 'react';
import { X, Download, Smartphone, Monitor, ShieldCheck, Sparkles, Check } from 'lucide-react';
import { AppLogoIcon } from './AppLogoIcon';
import { Language } from '../types/network';

interface LogoDownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const LogoDownloadModal: React.FC<LogoDownloadModalProps> = ({ isOpen, onClose, lang }) => {
  const isFa = lang === 'fa';
  const [downloaded, setDownloaded] = React.useState<string | null>(null);

  if (!isOpen) return null;

  const handleDownloadSvg = (formatName: string) => {
    // Generate SVG string for logo download
    const svgContent = `<svg width="512" height="512" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
<defs>
  <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="#0f172a" />
    <stop offset="50%" stop-color="#082f49" />
    <stop offset="100%" stop-color="#020617" />
  </linearGradient>
  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="#06b6d4" />
    <stop offset="50%" stop-color="#00f5d4" />
    <stop offset="100%" stop-color="#10b981" />
  </linearGradient>
</defs>
<rect x="4" y="4" width="92" height="92" rx="24" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="3" />
<path d="M50 18 L76 28 V52 C76 68 64 80 50 85 C36 80 24 68 24 52 V28 L50 18 Z" fill="url(#shieldGrad)" fill-opacity="0.2" stroke="url(#shieldGrad)" stroke-width="4.5" stroke-linejoin="round" />
<path d="M32 50 Q50 60 68 50" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round" />
<polygon points="50,38 58,50 50,62 42,50" fill="#00f5d4" />
</svg>`;

    const blob = new Blob([svgContent], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `LeakGuard-AppIcon-${formatName}.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloaded(formatName);
    setTimeout(() => setDownloaded(null), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <AppLogoIcon className="w-10 h-10" size={40} />
            <div>
              <h3 className="text-lg font-bold text-white">
                {isFa ? 'دانلود لوگوی رسمی برنامه (Android & Windows)' : 'Official App Logo Assets'}
              </h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'لوگوی برداری با ابعاد استاندارد برای آیکون اندروید و ویندوز' : 'High resolution vector logo assets for Android APK & Windows'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-xl transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Logo Preview Showcase Box */}
        <div className="bg-slate-950/90 border border-slate-800 p-6 rounded-2xl flex flex-col items-center justify-center space-y-3 text-center shadow-inner">
          <AppLogoIcon className="w-24 h-24" size={96} />
          <div>
            <span className="text-sm font-extrabold text-white block">LeakGuard Persian Security</span>
            <span className="text-xs text-cyan-400 font-mono">Vector SVG / 512x512 High Quality Icon</span>
          </div>
        </div>

        {/* Platform Downloads */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          
          {/* Android Icon Asset */}
          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-2xl space-y-2 flex flex-col justify-between hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <Smartphone className="w-4 h-4" />
              <span>{isFa ? 'آیکون اندروید (Android Adaptive)' : 'Android Launcher Icon'}</span>
            </div>
            <p className="text-[11px] text-slate-400">
              {isFa ? 'فرمت SVG استاندارد با لبه‌های Squircle مناسب APK اندروید' : 'Squircle vector icon for Android app launcher'}
            </p>
            <button
              onClick={() => handleDownloadSvg('Android-Squircle')}
              className="w-full mt-2 py-2 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 font-bold rounded-xl flex items-center justify-center gap-1.5 transition-colors"
            >
              {downloaded === 'Android-Squircle' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
              <span>{downloaded === 'Android-Squircle' ? (isFa ? 'دانلود شد!' : 'Downloaded!') : (isFa ? 'دانلود SVG اندروید' : 'Download Android SVG')}</span>
            </button>
          </div>

          {/* Windows Icon Asset */}
          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-2xl space-y-2 flex flex-col justify-between hover:border-cyan-500/40 transition-colors">
            <div className="flex items-center gap-2 text-cyan-400 font-bold">
              <Monitor className="w-4 h-4" />
              <span>{isFa ? 'آیکون ویندوز (Windows Desktop)' : 'Windows Taskbar Icon'}</span>
            </div>
            <p className="text-[11px] text-slate-400">
              {isFa ? 'آیکون با وضوح بالا مناسب دسکتاپ و Taskbar ویندوز' : 'High resolution vector icon for Windows Taskbar & Desktop'}
            </p>
            <button
              onClick={() => handleDownloadSvg('Windows-Desktop')}
              className="w-full mt-2 py-2 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-bold rounded-xl flex items-center justify-center gap-1.5 transition-colors"
            >
              {downloaded === 'Windows-Desktop' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
              <span>{downloaded === 'Windows-Desktop' ? (isFa ? 'دانلود شد!' : 'Downloaded!') : (isFa ? 'دانلود SVG ویندوز' : 'Download Windows SVG')}</span>
            </button>
          </div>

        </div>

        {/* Footer info */}
        <div className="pt-2 text-center text-[11px] text-slate-500 flex items-center justify-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          <span>{isFa ? 'طراحی شده طبق استانداردهای رسمی Material You و Fluent Design' : 'Designed according to Material You & Fluent Design guidelines'}</span>
        </div>

      </div>
    </div>
  );
};
