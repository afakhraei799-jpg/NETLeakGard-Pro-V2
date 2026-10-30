import React, { useState, useEffect, useCallback } from 'react';
import {
  Language,
  TestStatus,
  IpDetails,
  DnsLeakResult,
  WebRtcLeakResult,
  VpnProxyResult,
  NetworkMetrics,
  AiAuditReport,
  FullNetworkTestReport
} from './types/network';
import { translations } from './i18n/translations';
import {
  fetchIpDetails,
  performDnsLeakTest,
  performWebRtcLeakTest,
  performVpnAnalysis,
  measurePingAndSpeed,
  fetchAiAudit
} from './services/networkTester';
import { Header } from './components/Header';
import { HeroScoreBanner } from './components/HeroScoreBanner';
import { Globe3D } from './components/Globe3D';
import { IpLeakCard } from './components/IpLeakCard';
import { DnsLeakCard } from './components/DnsLeakCard';
import { WebRtcCard } from './components/WebRtcCard';
import { VpnProxyCard } from './components/VpnProxyCard';
import { SpeedPingCard } from './components/SpeedPingCard';
import { PrivacyScoreHistoryCard, ScoreHistoryPoint } from './components/PrivacyScoreHistoryCard';
import { AiAuditSection } from './components/AiAuditSection';
import { ExportModal } from './components/ExportModal';
import { EduGuideModal } from './components/EduGuideModal';
import { SettingsModal } from './components/SettingsModal';
import { LogoDownloadModal } from './components/LogoDownloadModal';
import { PWAInstallModal } from './components/PWAInstallModal';
import { MobileBottomNav } from './components/MobileBottomNav';
import { useOnlineStatus } from './hooks/useOnlineStatus';
import {
  ShieldCheck,
  Sparkles,
  Image as ImageIcon,
  Monitor,
  Smartphone,
  WifiOff,
  Keyboard,
  Download
} from 'lucide-react';

const LOCAL_STORAGE_HISTORY_KEY = 'leakguard_score_history';

export default function App() {
  const [lang, setLang] = useState<Language>('fa');
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [autoRun, setAutoRun] = useState<boolean>(true);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  const isOnline = useOnlineStatus();

  // Modal states
  const [isHelpOpen, setIsHelpOpen] = useState<boolean>(false);
  const [isExportOpen, setIsExportOpen] = useState<boolean>(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false);
  const [isLogoOpen, setIsLogoOpen] = useState<boolean>(false);
  const [isInstallOpen, setIsInstallOpen] = useState<boolean>(false);

  // Network State
  const [ipDetails, setIpDetails] = useState<IpDetails | null>(null);
  const [dnsLeak, setDnsLeak] = useState<DnsLeakResult | null>(null);
  const [webRtcLeak, setWebRtcLeak] = useState<WebRtcLeakResult | null>(null);
  const [vpnProxy, setVpnProxy] = useState<VpnProxyResult | null>(null);
  const [metrics, setMetrics] = useState<NetworkMetrics | null>(null);
  const [aiAudit, setAiAudit] = useState<AiAuditReport | null>(null);

  const [overallStatus, setOverallStatus] = useState<TestStatus>('IDLE');
  const [privacyScore, setPrivacyScore] = useState<number>(100);

  // Privacy Score History State
  const [scoreHistory, setScoreHistory] = useState<ScoreHistoryPoint[]>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem(LOCAL_STORAGE_HISTORY_KEY);
        if (saved) return JSON.parse(saved);
      } catch (e) {
        // Fallback
      }
    }
    return [];
  });

  // Sync HTML dir attribute
  useEffect(() => {
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
  }, [lang]);

  // Save history to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_HISTORY_KEY, JSON.stringify(scoreHistory));
    } catch (e) {
      // Storage full
    }
  }, [scoreHistory]);

  const handleClearHistory = () => {
    setScoreHistory([]);
    try {
      localStorage.removeItem(LOCAL_STORAGE_HISTORY_KEY);
    } catch (e) {
      // Storage error
    }
  };

  // 1. Success Chime Sound
  const playSuccessSound = useCallback(() => {
    if (!soundEnabled || typeof window === 'undefined') return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const now = ctx.currentTime;

      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(523.25, now);
      gain1.gain.setValueAtTime(0.12, now);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
      osc1.connect(gain1);
      gain1.connect(ctx.destination);
      osc1.start(now);
      osc1.stop(now + 0.3);

      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(659.25, now + 0.1);
      gain2.gain.setValueAtTime(0.12, now + 0.1);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
      osc2.connect(gain2);
      gain2.connect(ctx.destination);
      osc2.start(now + 0.1);
      osc2.stop(now + 0.4);

      const osc3 = ctx.createOscillator();
      const gain3 = ctx.createGain();
      osc3.type = 'sine';
      osc3.frequency.setValueAtTime(783.99, now + 0.2);
      gain3.gain.setValueAtTime(0.15, now + 0.2);
      gain3.gain.exponentialRampToValueAtTime(0.001, now + 0.55);
      osc3.connect(gain3);
      gain3.connect(ctx.destination);
      osc3.start(now + 0.2);
      osc3.stop(now + 0.55);
    } catch (e) {
      // Audio context policy
    }
  }, [soundEnabled]);

  // 2. Distinct Leak Warning Alarm Sound
  const playLeakAlarmSound = useCallback(() => {
    if (!soundEnabled || typeof window === 'undefined') return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const now = ctx.currentTime;

      for (let i = 0; i < 3; i++) {
        const startTime = now + i * 0.18;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, startTime);
        osc.frequency.exponentialRampToValueAtTime(440, startTime + 0.14);

        gain.gain.setValueAtTime(0.2, startTime);
        gain.gain.exponentialRampToValueAtTime(0.001, startTime + 0.15);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start(startTime);
        osc.stop(startTime + 0.15);
      }
    } catch (e) {
      // Audio context policy
    }
  }, [soundEnabled]);

  // Main Test Execution Flow
  const runFullLeakSuite = useCallback(async () => {
    setIsTesting(true);
    setOverallStatus('TESTING');

    try {
      const ipData = await fetchIpDetails();
      setIpDetails(ipData);

      const dnsRes = await performDnsLeakTest(ipData);
      setDnsLeak(dnsRes);

      const webRtcRes = await performWebRtcLeakTest(ipData.ip);
      setWebRtcLeak(webRtcRes);

      const vpnRes = performVpnAnalysis(ipData, dnsRes);
      setVpnProxy(vpnRes);

      const speedRes = await measurePingAndSpeed();
      setMetrics(speedRes);

      let score = 100;
      let finalStatus: TestStatus = 'PASS';

      if (webRtcRes.isLeakingRealIp) {
        score -= 40;
        finalStatus = 'LEAK_DETECTED';
      }
      if (dnsRes.isLeaking) {
        score -= 30;
        finalStatus = 'LEAK_DETECTED';
      }
      if (!ipData.isDatacenter) {
        score -= 20;
        if (finalStatus !== 'LEAK_DETECTED') {
          finalStatus = 'WARNING';
        }
      }

      const calculatedScore = Math.max(10, Math.min(100, score));
      setPrivacyScore(calculatedScore);
      setOverallStatus(finalStatus);

      // Add to Score History Chart
      const nowObj = new Date();
      const timeStr = nowObj.toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' });
      const dateStr = nowObj.toLocaleDateString('fa-IR');

      const historyPoint: ScoreHistoryPoint = {
        id: Date.now().toString(),
        timestamp: timeStr,
        fullDate: dateStr,
        score: calculatedScore,
        ip: ipData.ip,
        statusFa: finalStatus === 'PASS' ? 'اتصال امن' : 'هشدار / نشت',
      };

      setScoreHistory(prev => [...prev.slice(-14), historyPoint]);

      // Step 6: Gemini AI Audit Synthesis
      const auditRes = await fetchAiAudit({
        ip: ipData.ip,
        ipDetails: ipData,
        countryName: ipData.countryName,
        city: ipData.city,
        isp: ipData.isp,
        asn: ipData.asn,
        isVpnOrProxyDetected: ipData.isVpnOrProxyDetected,
        dnsLeakStatus: dnsRes.isLeaking ? 'نشت شناسایی شد' : 'بدون نشت',
        dnsServerCount: dnsRes.detectedResolversCount,
        webRtcLeakStatus: webRtcRes.isLeakingRealIp ? 'نشت شدید IP' : 'محافظت‌شده',
        localWebRtcIp: webRtcRes.localIps[0] || 'پنهان',
        pingMs: speedRes.pingMs,
        fraudRiskScore: ipData.fraudRiskScore,
        fraudStatusFa: ipData.fraudStatusFa,
        usageTypeFa: ipData.usageTypeFa,
        userIntentAnalysisFa: ipData.userIntentAnalysisFa,
      });

      setAiAudit(auditRes);

      if (finalStatus === 'LEAK_DETECTED' || finalStatus === 'WARNING') {
        playLeakAlarmSound();
      } else {
        playSuccessSound();
      }

    } catch (e) {
      console.error('Leak test execution error', e);
      setOverallStatus('INCONCLUSIVE');
    } finally {
      setIsTesting(false);
    }
  }, [playLeakAlarmSound, playSuccessSound]);

  // Windows Desktop Keyboard Shortcuts (Alt + R, Alt + E, Alt + S, Alt + H)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.altKey && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        if (!isTesting) runFullLeakSuite();
      } else if (e.altKey && e.key.toLowerCase() === 'e') {
        e.preventDefault();
        setIsExportOpen(prev => !prev);
      } else if (e.altKey && e.key.toLowerCase() === 's') {
        e.preventDefault();
        setIsSettingsOpen(prev => !prev);
      } else if (e.altKey && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        setIsHelpOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isTesting, runFullLeakSuite]);

  // Initial Auto-run on boot
  useEffect(() => {
    if (autoRun) {
      runFullLeakSuite();
    }
  }, []);

  const fullReport: FullNetworkTestReport = {
    timestamp: new Date().toLocaleString('fa-IR'),
    ipDetails,
    dnsLeak,
    webRtcLeak,
    vpnProxy,
    metrics,
    aiAudit,
    overallStatus,
    privacyScore,
  };

  const t = translations[lang];
  const isFa = lang === 'fa';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950 pb-20 md:pb-0">
      
      {/* Offline Connectivity Banner */}
      {!isOnline && (
        <div className="bg-amber-500 text-slate-950 px-4 py-2 text-xs font-extrabold flex items-center justify-center gap-2 z-50 shadow-lg">
          <WifiOff className="w-4 h-4 animate-pulse" />
          <span>
            {isFa
              ? 'حالت آفلاین فعال است — اتصال اینترنت برقرار نیست؛ آخرین گزارش ذخیره شده در کش نمایش داده می‌شود.'
              : 'Offline Mode — Using cached network security report.'}
          </span>
        </div>
      )}

      {/* Top Header */}
      <Header
        lang={lang}
        onToggleLang={() => setLang(lang === 'fa' ? 'en' : 'fa')}
        onStartFullTest={runFullLeakSuite}
        isTesting={isTesting}
        onOpenHelp={() => setIsHelpOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenInstallModal={() => setIsInstallOpen(true)}
      />

      {/* Windows & Android Native Optimization Bar */}
      <div className="bg-slate-900/70 border-b border-slate-800/80 px-4 md:px-8 py-2">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-300">
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 text-cyan-400 font-bold">
              <Monitor className="w-3.5 h-3.5" />
              <span>{isFa ? 'نسخه ویندوز ۱۰/۱۱' : 'Windows 10/11 Ready'}</span>
            </span>
            <span className="text-slate-700">|</span>
            <span className="inline-flex items-center gap-1.5 text-emerald-400 font-bold">
              <Smartphone className="w-3.5 h-3.5" />
              <span>{isFa ? 'نسخه موبایل اندروید (WebAPK)' : 'Android WebAPK Ready'}</span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-1.5 text-slate-400">
              <Keyboard className="w-3.5 h-3.5 text-amber-400" />
              <span>{isFa ? 'میانبرهای ویندوز: Alt+R (تست) • Alt+E (خروجی) • Alt+S (تنظیمات)' : 'Hotkeys: Alt+R (Test) • Alt+E (Export) • Alt+S (Settings)'}</span>
            </div>
            <button
              onClick={() => setIsInstallOpen(true)}
              className="text-cyan-300 hover:text-cyan-200 underline font-bold cursor-pointer"
            >
              {isFa ? 'راهنمای نصب ویندوز و اندروید' : 'Install Guide'}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 md:px-8 py-6 md:py-8 space-y-6 md:space-y-8">
        
        {/* Hero Privacy Score Banner */}
        <HeroScoreBanner
          lang={lang}
          privacyScore={privacyScore}
          overallStatus={overallStatus}
          ipDetails={ipDetails}
          dnsLeak={dnsLeak}
          webRtcLeak={webRtcLeak}
          vpnProxy={vpnProxy}
          onStartTest={runFullLeakSuite}
          isTesting={isTesting}
        />

        {/* 3D Interactive Globe Visualizer */}
        <section id="globe-section">
          <Globe3D ipDetails={ipDetails} dnsResolvers={dnsLeak?.resolvers || []} lang={lang} overallStatus={overallStatus} />
        </section>

        {/* Recharts Privacy Score Trend Chart Card */}
        <section id="chart-section">
          <PrivacyScoreHistoryCard
            history={scoreHistory}
            onClearHistory={handleClearHistory}
            lang={lang}
          />
        </section>

        {/* Leak Test Cards Grid */}
        <section id="test-results" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 md:gap-6">
          <IpLeakCard ipDetails={ipDetails} lang={lang} />
          <DnsLeakCard dnsLeak={dnsLeak} lang={lang} />
          <WebRtcCard webRtcLeak={webRtcLeak} lang={lang} />
          <VpnProxyCard vpnProxy={vpnProxy} lang={lang} />
          <SpeedPingCard metrics={metrics} onUpdateMetrics={setMetrics} lang={lang} />
          
          {/* Windows & Android Branding & App Center Card */}
          <div className="relative bg-slate-900/90 border border-slate-800/80 rounded-3xl overflow-hidden shadow-3d-card flex flex-col justify-between hover:border-cyan-500/40 transition-colors">
            <div className="h-1.5 w-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-500" />
            <div className="p-6 flex-1 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2.5 text-cyan-400 mb-3 font-extrabold text-sm">
                  <Sparkles className="w-5 h-5 text-cyan-400" />
                  <span>{isFa ? 'مرکز نصب و آیکون (ویندوز و اندروید)' : 'Windows & Android App Center'}</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed mb-4">
                  {isFa 
                    ? 'نرم‌افزار LeakGuard برای اجرای مستقل روی دسکتاپ ویندوز ۱۰/۱۱ (همراه با کلیدهای میانبر) و گوشی‌های اندروید (با نوار ناوبری لمسی پایین صفحه و آیکون تطبیقی) بهینه‌سازی شده است.'
                    : 'LeakGuard is optimized for standalone Windows 10/11 desktop execution and Android mobile devices with touch navigation.'}
                </p>
              </div>
              
              <div className="space-y-2.5">
                <button
                  onClick={() => setIsInstallOpen(true)}
                  className="w-full py-2.5 bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-slate-950 rounded-xl text-xs font-black transition-all flex items-center justify-center gap-2 shadow-md cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  <span>{isFa ? 'نصب مستقیم روی ویندوز و اندروید' : 'Install on Windows & Android'}</span>
                </button>

                <button
                  onClick={() => setIsLogoOpen(true)}
                  className="w-full py-2.5 bg-slate-950 hover:bg-slate-800 text-cyan-300 rounded-xl text-xs font-bold transition-all border border-slate-800 flex items-center justify-center gap-2 cursor-pointer"
                >
                  <ImageIcon className="w-4 h-4 text-cyan-400" />
                  <span>{isFa ? 'دریافت آیکون SVG (Android & Windows)' : 'Download App Icons (SVG)'}</span>
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* AI Powered Security Audit Section */}
        <AiAuditSection aiAudit={aiAudit} lang={lang} />

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-4 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>{t.brandName} © {new Date().getFullYear()} - {isFa ? 'بهینه‌سازی شده برای ویندوز و اندروید' : 'Optimized for Windows & Android'}</span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-4 text-slate-400">
            <button onClick={() => setIsInstallOpen(true)} className="hover:text-emerald-400 transition-colors cursor-pointer">{isFa ? 'نصب برنامه' : 'Install App'}</button>
            <button onClick={() => setIsLogoOpen(true)} className="hover:text-cyan-400 transition-colors cursor-pointer">{isFa ? 'لوگوی برنامه' : 'App Logo'}</button>
            <button onClick={() => setIsHelpOpen(true)} className="hover:text-white transition-colors cursor-pointer">{t.helpGuide}</button>
            <button onClick={() => setIsSettingsOpen(true)} className="hover:text-white transition-colors cursor-pointer">{t.settings}</button>
            <button onClick={() => setIsExportOpen(true)} className="hover:text-white transition-colors cursor-pointer">{t.exportReport}</button>
          </div>
        </div>
      </footer>

      {/* Android Mobile Bottom Navigation Bar */}
      <MobileBottomNav
        lang={lang}
        isTesting={isTesting}
        onStartTest={runFullLeakSuite}
        onOpenInstallModal={() => setIsInstallOpen(true)}
      />

      {/* Modals */}
      <ExportModal
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        report={fullReport}
        lang={lang}
      />

      <EduGuideModal
        isOpen={isHelpOpen}
        onClose={() => setIsHelpOpen(false)}
        lang={lang}
      />

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        lang={lang}
        onToggleLang={() => setLang(lang === 'fa' ? 'en' : 'fa')}
        autoRun={autoRun}
        onToggleAutoRun={() => setAutoRun(!autoRun)}
        soundEnabled={soundEnabled}
        onToggleSound={() => setSoundEnabled(!soundEnabled)}
        onTestAlarm={playLeakAlarmSound}
        onTestSuccess={playSuccessSound}
      />

      <LogoDownloadModal
        isOpen={isLogoOpen}
        onClose={() => setIsLogoOpen(false)}
        lang={lang}
      />

      <PWAInstallModal
        isOpen={isInstallOpen}
        onClose={() => setIsInstallOpen(false)}
        lang={lang}
      />

    </div>
  );
}
