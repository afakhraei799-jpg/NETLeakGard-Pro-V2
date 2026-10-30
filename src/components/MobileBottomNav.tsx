import React from 'react';
import {
  ShieldCheck,
  Globe,
  RefreshCw,
  Sparkles,
  Gauge,
  Download
} from 'lucide-react';
import { Language } from '../types/network';

interface MobileBottomNavProps {
  lang: Language;
  isTesting: boolean;
  onStartTest: () => void;
  onOpenInstallModal: () => void;
}

export const MobileBottomNav: React.FC<MobileBottomNavProps> = ({
  lang,
  isTesting,
  onStartTest,
  onOpenInstallModal,
}) => {
  const isFa = lang === 'fa';

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  return (
    <nav
      aria-label="Android Bottom Navigation"
      className="md:hidden fixed bottom-0 inset-x-0 z-40 bg-slate-950/95 backdrop-blur-xl border-t border-slate-800/90 px-2 pb-[env(safe-area-inset-bottom,8px)] pt-2 shadow-[0_-10px_30px_rgba(0,0,0,0.6)]"
    >
      <div className="grid grid-cols-5 items-center max-w-md mx-auto text-[10px] font-bold text-slate-400">
        
        {/* 1. Dashboard Top */}
        <button
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          className="flex flex-col items-center justify-center gap-1 py-1 hover:text-cyan-400 active:scale-95 transition-all"
        >
          <ShieldCheck className="w-5 h-5 text-cyan-400" />
          <span>{isFa ? 'داشبورد' : 'Status'}</span>
        </button>

        {/* 2. 3D Globe */}
        <button
          onClick={() => scrollToSection('globe-section')}
          className="flex flex-col items-center justify-center gap-1 py-1 hover:text-cyan-400 active:scale-95 transition-all"
        >
          <Globe className="w-5 h-5 text-emerald-400" />
          <span>{isFa ? 'کره ۳D' : '3D Globe'}</span>
        </button>

        {/* 3. Center Floating Action Button: Run Full Test */}
        <div className="flex justify-center -mt-5">
          <button
            onClick={onStartTest}
            disabled={isTesting}
            className="w-13 h-13 rounded-2xl bg-gradient-to-tr from-cyan-500 to-emerald-400 text-slate-950 flex flex-col items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.5)] active:scale-90 transition-all border-2 border-slate-950"
            title={isFa ? 'شروع تست کامل' : 'Run Full Test'}
          >
            <RefreshCw className={`w-6 h-6 ${isTesting ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* 4. Test Cards & Speed */}
        <button
          onClick={() => scrollToSection('test-results')}
          className="flex flex-col items-center justify-center gap-1 py-1 hover:text-cyan-400 active:scale-95 transition-all"
        >
          <Gauge className="w-5 h-5 text-amber-400" />
          <span>{isFa ? 'پینگ و نشت' : 'Tests'}</span>
        </button>

        {/* 5. Install / Platform Optimization */}
        <button
          onClick={onOpenInstallModal}
          className="flex flex-col items-center justify-center gap-1 py-1 hover:text-emerald-400 active:scale-95 transition-all"
        >
          <Download className="w-5 h-5 text-purple-400" />
          <span>{isFa ? 'نصب اپ' : 'Install'}</span>
        </button>

      </div>
    </nav>
  );
};
