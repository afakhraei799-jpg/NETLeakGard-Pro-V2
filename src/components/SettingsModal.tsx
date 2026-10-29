import React from 'react';
import { X, Settings as SettingsIcon, Languages, Volume2, Play, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Language } from '../types/network';
import { translations } from '../i18n/translations';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  onToggleLang: () => void;
  autoRun: boolean;
  onToggleAutoRun: () => void;
  soundEnabled: boolean;
  onToggleSound: () => void;
  onTestAlarm?: () => void;
  onTestSuccess?: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  lang,
  onToggleLang,
  autoRun,
  onToggleAutoRun,
  soundEnabled,
  onToggleSound,
  onTestAlarm,
  onTestSuccess,
}) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">
              <SettingsIcon className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{t.settings}</h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'تنظیمات شخصی‌سازی زبان، پوسته و هشدار صوتی' : 'Personalization & application preferences'}
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

        {/* Options List */}
        <div className="space-y-4 text-xs">
          
          {/* 1. Language Toggle */}
          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-2xl flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Languages className="w-5 h-5 text-cyan-400 shrink-0" />
              <div>
                <span className="font-bold text-slate-100 block">زبان برنامه / Interface Language</span>
                <span className="text-slate-400 text-[11px]">
                  {isFa ? 'فارسی (پیش‌فرض) / English' : 'Persian (Default) / English'}
                </span>
              </div>
            </div>

            <button
              onClick={onToggleLang}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-cyan-300 font-bold transition-colors"
            >
              {t.languageName}
            </button>
          </div>

          {/* 2. Auto Run Test */}
          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-2xl flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Play className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <span className="font-bold text-slate-100 block">{t.autoRunOnStart}</span>
                <span className="text-slate-400 text-[11px]">
                  {isFa ? 'اجرای خودکار تست با هربار باز شدن صفحه' : 'Automatically run diagnostic on page load'}
                </span>
              </div>
            </div>

            <button
              onClick={onToggleAutoRun}
              className={`w-12 h-6 rounded-full p-1 transition-colors flex items-center ${
                autoRun ? 'bg-cyan-500 justify-end' : 'bg-slate-800 justify-start'
              }`}
            >
              <div className="w-4 h-4 bg-white rounded-full shadow-md" />
            </button>
          </div>

          {/* 3. Sound Effects */}
          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-2xl flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Volume2 className="w-5 h-5 text-purple-400 shrink-0" />
                <div>
                  <span className="font-bold text-slate-100 block">{t.soundEffects}</span>
                  <span className="text-slate-400 text-[11px]">
                    {isFa ? 'پخش افکت صوتی هنگام شناسایی نشت یا پایان آزمایش' : 'Audio chime / alert siren on completion'}
                  </span>
                </div>
              </div>

              <button
                onClick={onToggleSound}
                className={`w-12 h-6 rounded-full p-1 transition-colors flex items-center ${
                  soundEnabled ? 'bg-purple-500 justify-end' : 'bg-slate-800 justify-start'
                }`}
              >
                <div className="w-4 h-4 bg-white rounded-full shadow-md" />
              </button>
            </div>

            {/* Audio Test Preview Buttons */}
            {soundEnabled && (
              <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80">
                {onTestAlarm && (
                  <button
                    onClick={onTestAlarm}
                    className="flex-1 flex items-center justify-center gap-1.5 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/80 text-rose-300 py-2 rounded-xl text-[11px] font-bold transition-colors"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                    <span>{isFa ? 'تست هشدار نشت (اخطار)' : 'Test Leak Alarm'}</span>
                  </button>
                )}

                {onTestSuccess && (
                  <button
                    onClick={onTestSuccess}
                    className="flex-1 flex items-center justify-center gap-1.5 bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800/80 text-emerald-300 py-2 rounded-xl text-[11px] font-bold transition-colors"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{isFa ? 'تست صدای امن' : 'Test Secure Chime'}</span>
                  </button>
                )}
              </div>
            )}
          </div>

        </div>

        {/* Action Button */}
        <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs transition-colors"
          >
            {t.saveSettings}
          </button>
        </div>

      </div>
    </div>
  );
};
