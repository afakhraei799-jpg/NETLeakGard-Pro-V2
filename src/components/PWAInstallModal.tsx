import React, { useState } from 'react';
import {
  X,
  Download,
  Smartphone,
  Monitor,
  CheckCircle2,
  Keyboard,
  WifiOff,
  Cpu,
  ShieldCheck,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { Language } from '../types/network';
import { usePWAInstall } from '../hooks/usePWAInstall';
import { AppLogoIcon } from './AppLogoIcon';

interface PWAInstallModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const PWAInstallButton: React.FC<{
  lang: Language;
  onOpenInstallModal: () => void;
}> = ({ lang, onOpenInstallModal }) => {
  const { isInstallable, isInstalled, install } = usePWAInstall();
  const isFa = lang === 'fa';

  if (isInstalled) {
    return null;
  }

  const handleClick = async () => {
    if (isInstallable) {
      const accepted = await install();
      if (!accepted) {
        onOpenInstallModal();
      }
    } else {
      onOpenInstallModal();
    }
  };

  return (
    <button
      onClick={handleClick}
      className="flex items-center gap-2 px-3.5 py-2 bg-emerald-950/90 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/80 rounded-2xl text-xs font-bold transition-all shadow-[0_0_15px_rgba(16,185,129,0.25)] hover:scale-105 active:scale-95 cursor-pointer shrink-0"
      title={isFa ? 'نصب مستقیم نرم‌افزار روی ویندوز و اندروید' : 'Install App on Windows & Android'}
    >
      <Download className="w-4 h-4 text-emerald-400 animate-bounce" />
      <span className="hidden md:inline">
        {isFa ? 'نصب برنامه (ویندوز / اندروید)' : 'Install App'}
      </span>
    </button>
  );
};

export const PWAInstallModal: React.FC<PWAInstallModalProps> = ({ isOpen, onClose, lang }) => {
  const isFa = lang === 'fa';
  const { isInstallable, isInstalled, detectedOS, install } = usePWAInstall();
  const [activeTab, setActiveTab] = useState<'windows' | 'android'>(
    detectedOS === 'android' ? 'android' : 'windows'
  );

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl space-y-6 my-8">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <AppLogoIcon className="w-11 h-11" size={44} />
            <div>
              <h3 className="text-lg font-extrabold text-white flex items-center gap-2">
                <span>{isFa ? 'نصب و بهینه‌سازی ویژه ویندوز و اندروید' : 'Windows & Android Native Optimization'}</span>
                <span className="text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-lg font-mono">
                  PWA v3.2
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                {isFa
                  ? 'اجرای مستقل بدون نوار مرورگر، پشتیبانی آفلاین، کلیدهای میانبر ویندوز و منوی لمسی اندروید'
                  : 'Standalone desktop window, Android WebAPK launcher, offline cache & hotkeys'}
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

        {/* Direct Native Install Banner if Prompt Available */}
        {isInstallable && !isInstalled && (
          <div className="bg-gradient-to-r from-emerald-950/90 via-teal-950/90 to-cyan-950/90 border border-emerald-600/60 p-4 rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-4 shadow-lg">
            <div className="flex items-center gap-3">
              <Sparkles className="w-6 h-6 text-emerald-400 shrink-0" />
              <div className="text-xs">
                <span className="font-bold text-white block text-sm">
                  {isFa ? 'آماده نصب مستقیم با یک کلیک!' : 'Ready for 1-Click Native Installation!'}
                </span>
                <span className="text-slate-300">
                  {isFa
                    ? 'مرورگر شما از نصب مستقیم نرم‌افزار پشتیبانی می‌کند.'
                    : 'Your browser supports direct standalone installation.'}
                </span>
              </div>
            </div>
            <button
              onClick={install}
              className="w-full sm:w-auto px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-black text-xs rounded-xl shadow-md transition-all shrink-0 cursor-pointer"
            >
              {isFa ? 'نصب فوری نرم‌افزار' : 'Install Now'}
            </button>
          </div>
        )}

        {/* Platform Switcher Tabs */}
        <div className="grid grid-cols-2 gap-3 bg-slate-950 p-1.5 rounded-2xl border border-slate-800">
          <button
            onClick={() => setActiveTab('windows')}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-extrabold transition-all cursor-pointer ${
              activeTab === 'windows'
                ? 'bg-cyan-500 text-slate-950 shadow-md'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Monitor className="w-4 h-4" />
            <span>{isFa ? 'نسخه دسکتاپ ویندوز (۱۰ / ۱۱)' : 'Windows 10 / 11 Desktop'}</span>
          </button>

          <button
            onClick={() => setActiveTab('android')}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-extrabold transition-all cursor-pointer ${
              activeTab === 'android'
                ? 'bg-emerald-500 text-slate-950 shadow-md'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>{isFa ? 'نسخه موبایل اندروید (Android)' : 'Android Mobile App'}</span>
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'windows' ? (
          <div className="space-y-4 text-xs">
            {/* Windows Installation Guide */}
            <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                <Monitor className="w-4 h-4" />
                <span>{isFa ? 'نحوه نصب به عنوان برنامه مستقل ویندوز (Standalone EXE/App):' : 'How to install as a Standalone Windows App:'}</span>
              </div>
              <ol className="space-y-2 text-slate-300 list-decimal list-inside leading-relaxed">
                <li>
                  {isFa
                    ? 'در مرورگر Chrome یا Microsoft Edge ویندوز، روی آیکون «نصب / Install LeakGuard» در سمت راست نوار آدرس (Address Bar) کلیک کنید.'
                    : 'In Chrome or Microsoft Edge on Windows, click the "Install LeakGuard" icon inside the right side of the Address Bar.'}
                </li>
                <li>
                  {isFa
                    ? 'گزینه «Pin to Taskbar» و «Create Desktop Shortcut» را فعال کنید تا نرم‌افزار در منوی Start و نوار وظیفه ویندوز قرار گیرد.'
                    : 'Enable "Pin to Taskbar" and "Create Desktop Shortcut" to launch directly from Windows Start Menu.'}
                </li>
                <li>
                  {isFa
                    ? 'نرم‌افزار در یک پنجره اختصاصی ویندوز (بدون تب‌های مرورگر) همراه با شتاب‌دهنده سخت‌افزاری WebGL اجرا خواهد شد.'
                    : 'The app runs in its own native Windows window with full WebGL hardware acceleration.'}
                </li>
              </ol>
            </div>

            {/* Windows Keyboard Shortcuts */}
            <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-3">
              <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
                <Keyboard className="w-4 h-4" />
                <span>{isFa ? 'کلیدهای میانبر اختصاصی ویندوز (Windows Hotkeys):' : 'Windows Keyboard Shortcuts:'}</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div className="flex items-center justify-between bg-slate-900 border border-slate-800 px-3 py-2 rounded-xl">
                  <span className="text-slate-300">{isFa ? 'شروع تست کامل نشت' : 'Start Full Leak Test'}</span>
                  <kbd className="px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-cyan-300 font-mono text-[11px]">Alt + R</kbd>
                </div>
                <div className="flex items-center justify-between bg-slate-900 border border-slate-800 px-3 py-2 rounded-xl">
                  <span className="text-slate-300">{isFa ? 'خروجی گزارش PDF/JSON' : 'Export Report'}</span>
                  <kbd className="px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-cyan-300 font-mono text-[11px]">Alt + E</kbd>
                </div>
                <div className="flex items-center justify-between bg-slate-900 border border-slate-800 px-3 py-2 rounded-xl">
                  <span className="text-slate-300">{isFa ? 'باز کردن تنظیمات' : 'Open Settings'}</span>
                  <kbd className="px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-cyan-300 font-mono text-[11px]">Alt + S</kbd>
                </div>
                <div className="flex items-center justify-between bg-slate-900 border border-slate-800 px-3 py-2 rounded-xl">
                  <span className="text-slate-300">{isFa ? 'راهنمای جامع امنیت' : 'Security Guide'}</span>
                  <kbd className="px-2 py-0.5 bg-slate-950 border border-slate-700 rounded text-cyan-300 font-mono text-[11px]">Alt + H</kbd>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-4 text-xs">
            {/* Android Installation Guide */}
            <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <Smartphone className="w-4 h-4" />
                <span>{isFa ? 'نحوه نصب روی گوشی‌های اندروید (Android WebAPK):' : 'How to Install on Android Phones:'}</span>
              </div>
              <ol className="space-y-2 text-slate-300 list-decimal list-inside leading-relaxed">
                <li>
                  {isFa
                    ? 'در مرورگر Chrome اندروید، روی منوی سه نقطه (⋮) در بالا سمت چپ/راست ضربه بزنید.'
                    : 'In Chrome on Android, tap the three-dot menu (⋮) in the top corner.'}
                </li>
                <li>
                  {isFa
                    ? 'گزینه «Install App / نصب برنامه» یا «Add to Home Screen» را انتخاب نمایید.'
                    : 'Tap "Install App" or "Add to Home Screen".'}
                </li>
                <li>
                  {isFa
                    ? 'آیکون تطبیقی (Adaptive Squircle Icon) برنامه به صفحه اصلی و لیست برنامه‌های اندروید شما اضافه شده و تمام‌صفحه اجرا می‌شود.'
                    : 'The Adaptive Squircle icon will be added to your Android app drawer with full-screen navigation.'}
                </li>
              </ol>
            </div>

            {/* Android Optimizations List */}
            <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-2xl space-y-2.5">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm mb-1">
                <Cpu className="w-4 h-4" />
                <span>{isFa ? 'بهینه‌سازی‌های فعال‌شده برای اندروید:' : 'Active Android Optimizations:'}</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{isFa ? 'نوار ناوبری لمسی پایین صفحه (Bottom Bar)' : 'Touch Bottom Navigation Bar'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{isFa ? 'آیکون Maskable استاندارد اندروید ۱۴' : 'Android 14 Maskable Icon'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{isFa ? 'تنظیم خودکار فریم‌ریت ۳D برای مصرف بهینه باتری' : 'Battery-aware 3D WebGL DPI scaling'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{isFa ? 'کش آفلاین سرویس‌ورکر (Service Worker)' : 'Offline Service Worker Caching'}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>
              {isFa
                ? 'تمامی استانداردهای PWA، کش آفلاین و میانبرهای دسکتاپ فعال هستند.'
                : 'Full PWA manifest, service worker & desktop shortcuts enabled.'}
            </span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl font-bold transition-colors"
          >
            {isFa ? 'بستن' : 'Close'}
          </button>
        </div>

      </div>
    </div>
  );
};
