import React from 'react';
import { RefreshCw, Languages, HelpCircle, FileText, Settings as SettingsIcon, Radio } from 'lucide-react';
import { Language } from '../types/network';
import { translations } from '../i18n/translations';
import { AppLogoIcon } from './AppLogoIcon';

interface HeaderProps {
  lang: Language;
  onToggleLang: () => void;
  onStartFullTest: () => void;
  isTesting: boolean;
  onOpenHelp: () => void;
  onOpenExport: () => void;
  onOpenSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  lang,
  onToggleLang,
  onStartFullTest,
  isTesting,
  onOpenHelp,
  onOpenExport,
  onOpenSettings,
}) => {
  const t = translations[lang];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/85 backdrop-blur-xl border-b border-slate-800/80 px-4 md:px-8 py-3.5 transition-all shadow-xl">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-6">
        
        {/* Zone 1: Single Element Brand Wordmark lockup with AppLogoIcon */}
        <div className="flex items-center gap-3 shrink-0">
          <AppLogoIcon className="w-11 h-11" size={44} />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-extrabold tracking-tight text-white whitespace-nowrap">
                {t.brandName}
              </h1>
              <span className="hidden sm:inline-flex items-center gap-1 bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 text-[10px] font-bold px-2 py-0.5 rounded-full">
                <Radio className="w-2.5 h-2.5 text-cyan-400 animate-pulse" />
                <span>Android & Windows App</span>
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block whitespace-nowrap">
              {t.brandTagline}
            </p>
          </div>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden lg:flex items-center gap-6 text-sm font-semibold text-slate-300">
          <a href="#test-results" className="hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0">
            {lang === 'fa' ? 'نتایج آزمایش‌ها' : 'Test Results'}
          </a>
          <a href="#globe-section" className="hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0">
            {lang === 'fa' ? 'کره ۳ بعدی' : '3D Network Map'}
          </a>
          <button 
            onClick={onOpenHelp}
            className="hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <HelpCircle className="w-4 h-4 text-slate-400" />
            <span>{t.helpGuide}</span>
          </button>
          <button 
            onClick={onOpenExport}
            className="hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <FileText className="w-4 h-4 text-slate-400" />
            <span>{t.exportReport}</span>
          </button>
        </nav>

        {/* Zone 3: Key Primary Action Controls */}
        <div className="flex items-center gap-2.5 shrink-0">
          
          <button
            onClick={onStartFullTest}
            disabled={isTesting}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 via-teal-400 to-cyan-500 hover:from-cyan-400 hover:to-teal-300 text-slate-950 text-xs font-black rounded-2xl shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_25px_rgba(6,182,212,0.6)] hover:scale-105 active:scale-95 transition-all disabled:opacity-50 uppercase tracking-wide cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isTesting ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">{isTesting ? t.testingProgress : t.startFullTest}</span>
            <span className="sm:hidden">{isTesting ? '...' : (lang === 'fa' ? 'تست شبکه' : 'TEST')}</span>
          </button>

          <button
            onClick={onToggleLang}
            className="p-2.5 bg-slate-900/90 hover:bg-slate-800 text-cyan-300 rounded-2xl border border-slate-800 transition-all font-bold text-xs"
            title="تغییر زبان / Language"
          >
            <Languages className="w-4 h-4" />
          </button>

          <button
            onClick={onOpenSettings}
            className="p-2.5 bg-slate-900/90 hover:bg-slate-800 text-slate-300 hover:text-white rounded-2xl border border-slate-800 transition-all"
            title={t.settings}
          >
            <SettingsIcon className="w-4 h-4" />
          </button>

        </div>

      </div>
    </header>
  );
};
