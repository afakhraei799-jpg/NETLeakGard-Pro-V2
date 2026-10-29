import React from 'react';
import { X, HelpCircle, Shield, Globe, Cpu, Server, Key, CheckCircle } from 'lucide-react';
import { Language } from '../types/network';
import { translations } from '../i18n/translations';

interface EduGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const EduGuideModal: React.FC<EduGuideModalProps> = ({ isOpen, onClose, lang }) => {
  const t = translations[lang];
  const isFa = lang === 'fa';

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 rounded-xl text-purple-400">
              <HelpCircle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{t.helpGuide}</h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'آموزش مفاهیم نشت شبکه، DNS، WebRTC و نحوه رفع آسیب‌پذیری‌ها' : 'Comprehensive guide to network leak detection & mitigation'}
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

        {/* Content Articles */}
        <div className="space-y-6 text-xs text-slate-300 leading-relaxed">
          
          {/* Article 1: IP Leak */}
          <div className="bg-slate-950/70 border border-slate-800 p-5 rounded-2xl space-y-2">
            <h4 className="text-sm font-bold text-cyan-400 flex items-center gap-2">
              <Globe className="w-4 h-4" />
              <span>{isFa ? '۱. نشت آدرس IP (IP Leak) چیست؟' : '1. What is an IP Leak?'}</span>
            </h4>
            <p>
              {isFa
                ? 'آدرس IP شناسه منحصر به فرد شما در دنیای اینترنت است که کشور، شهر و شرکت ارائه دهنده اینترنت (ISP) شما را مشخص می‌کند. هنگامی که از VPN استفاده می‌کنید، آدرس IP اصلی شما باید کاملاً پنهان شده و آی‌پی دیتاسنتر جایگزین گردد.'
                : 'An IP address uniquely identifies your connection. An IP leak occurs when your VPN fails to mask your real IP address.'}
            </p>
          </div>

          {/* Article 2: DNS Leak */}
          <div className="bg-slate-950/70 border border-slate-800 p-5 rounded-2xl space-y-2">
            <h4 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
              <Server className="w-4 h-4" />
              <span>{isFa ? '۲. نشت DNS چگونه اتفاق می‌افتد؟' : '2. How does a DNS Leak occur?'}</span>
            </h4>
            <p>
              {isFa
                ? 'سرویس DNS نام وب‌سایت‌ها (مانند google.com) را به آدرس‌های عددی تبدیل می‌کند. اگر مرورگر شما درخواست‌های DNS را خارج از تونل رمزشده VPN به ارائه‌دهنده اینترنت محلی بفرستد، تمام وب‌سایت‌های بازدیدشده افشا می‌گردند.'
                : 'A DNS leak occurs when domain name queries route outside the encrypted VPN tunnel directly to your local ISP.'}
            </p>
          </div>

          {/* Article 3: WebRTC Leak */}
          <div className="bg-slate-950/70 border border-slate-800 p-5 rounded-2xl space-y-2">
            <h4 className="text-sm font-bold text-purple-400 flex items-center gap-2">
              <Cpu className="w-4 h-4" />
              <span>{isFa ? '۳. نشت WebRTC چیست و چطور آن را مسدود کنیم؟' : '3. What is WebRTC leak and how to block it?'}</span>
            </h4>
            <p>
              {isFa
                ? 'پروتکل WebRTC برای برقراری تماس تصویری و صوتی مستقیم در مرورگرها استفاده می‌شود. این پروتکل به دلیل عملکرد مستقیم، می‌تواند آدرس IP واقعی سیستم را حتی هنگام اتصال به VPN فاش کند. راه حل: نصب افزونه WebRTC Control در کروم/فایرفاکس.'
                : 'WebRTC can expose your real LAN/WAN IP address via browser ICE candidate queries. Disable WebRTC via browser extensions.'}
            </p>
          </div>

          {/* Article 4: Kill Switch & Fix Steps */}
          <div className="bg-slate-950/70 border border-slate-800 p-5 rounded-2xl space-y-2">
            <h4 className="text-sm font-bold text-amber-400 flex items-center gap-2">
              <Key className="w-4 h-4" />
              <span>{isFa ? '۴. راهکارهای کلیدی افزایش امنیت VPN' : '4. Essential Steps to Secure your VPN'}</span>
            </h4>
            <ul className="space-y-1.5 pl-4 list-disc text-slate-300">
              <li>{isFa ? 'فعال‌سازی قابلیت Kill Switch در تنظیمات نرم‌افزار VPN' : 'Enable Kill Switch in VPN client settings'}</li>
              <li>{isFa ? 'استفاده از پروتکل جدید WireGuard یا OpenVPN TUN' : 'Use modern WireGuard or OpenVPN protocols'}</li>
              <li>{isFa ? 'تنظیم DNS رمزنگاری‌شده (DoH) مانند 1.1.1.1 در مرورگر' : 'Set Encrypted DNS (DoH) like 1.1.1.1 in browser settings'}</li>
            </ul>
          </div>

        </div>

      </div>
    </div>
  );
};
