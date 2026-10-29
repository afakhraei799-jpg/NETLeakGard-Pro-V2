import React, { useState } from 'react';
import { X, FileText, Download, Code, Table, Check } from 'lucide-react';
import { FullNetworkTestReport, Language } from '../types/network';
import { translations } from '../i18n/translations';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: FullNetworkTestReport | null;
  lang: Language;
}

export const ExportModal: React.FC<ExportModalProps> = ({ isOpen, onClose, report, lang }) => {
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const t = translations[lang];
  const isFa = lang === 'fa';

  if (!isOpen || !report) return null;

  // Export JSON
  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `LeakGuard_Report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Export CSV
  const handleExportCsv = () => {
    const rows = [
      ['پارامتر / Parameter', 'مقدار / Value'],
      ['زمان آزمایش / Timestamp', report.timestamp],
      ['آدرس IP عمومی / Public IP', report.ipDetails?.ip || 'N/A'],
      ['کشور / Country', report.ipDetails?.countryName || 'N/A'],
      ['شهر / City', report.ipDetails?.city || 'N/A'],
      ['سرویس دهنده / ISP', report.ipDetails?.isp || 'N/A'],
      ['وضعیت نشت DNS / DNS Leak', report.dnsLeak?.isLeaking ? 'نشت شناسایی شد' : 'موفق (امن)'],
      ['وضعیت نشت WebRTC / WebRTC Leak', report.webRtcLeak?.isLeakingRealIp ? 'نشت شناسایی شد' : 'موفق (امن)'],
      ['وضعیت VPN / VPN Status', report.vpnProxy?.isDatacenterIp ? 'VPN فعال' : 'اتصال مستقیم'],
      ['امتیاز کلی امنیت / Privacy Score', `${report.privacyScore}/100`],
    ];

    const csvContent = 'data:text/csv;charset=utf-8,\uFEFF' + rows.map(e => e.join(',')).join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `LeakGuard_Summary_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Export PDF
  const handleExportPdf = async () => {
    setIsExportingPdf(true);
    try {
      const element = document.getElementById('pdf-export-content');
      if (!element) return;

      const canvas = await html2canvas(element, {
        scale: 2,
        backgroundColor: '#090d16',
        useCORS: true,
      });

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;

      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`LeakGuard_Security_Report_${Date.now()}.pdf`);
    } catch (e) {
      console.error('PDF export error', e);
    } finally {
      setIsExportingPdf(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 shadow-2xl max-h-[90vh] overflow-y-auto">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{t.exportReport}</h3>
              <p className="text-xs text-slate-400">
                {isFa ? 'دریافت نسخه چاپی PDF یا فایل داده‌های خام آزمایش' : 'Download PDF report or raw dataset'}
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

        {/* Export Buttons */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
          
          <button
            onClick={handleExportPdf}
            disabled={isExportingPdf}
            className="flex flex-col items-center justify-center p-5 bg-gradient-to-b from-cyan-950/80 to-slate-950 border border-cyan-800/60 hover:border-cyan-500 rounded-2xl text-center transition-colors group"
          >
            <Download className="w-6 h-6 text-cyan-400 mb-2 group-hover:scale-110 transition-transform" />
            <span className="text-xs font-bold text-white">{t.exportPdf}</span>
            <span className="text-[10px] text-slate-400 mt-1">گزارش تصویری PDF</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex flex-col items-center justify-center p-5 bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-2xl text-center transition-colors group"
          >
            <Code className="w-6 h-6 text-emerald-400 mb-2 group-hover:scale-110 transition-transform" />
            <span className="text-xs font-bold text-white">{t.exportJson}</span>
            <span className="text-[10px] text-slate-400 mt-1">ساختار کد JSON</span>
          </button>

          <button
            onClick={handleExportCsv}
            className="flex flex-col items-center justify-center p-5 bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-2xl text-center transition-colors group"
          >
            <Table className="w-6 h-6 text-purple-400 mb-2 group-hover:scale-110 transition-transform" />
            <span className="text-xs font-bold text-white">{t.exportCsv}</span>
            <span className="text-[10px] text-slate-400 mt-1">جدول داده اکسل CSV</span>
          </button>

        </div>

        {/* Printable Preview Area for html2canvas PDF capture */}
        <div id="pdf-export-content" className="bg-slate-950 p-6 rounded-2xl border border-slate-800 text-xs space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <h4 className="font-bold text-sm text-cyan-400">{t.brandName} - گزارش ارزیابی امنیتی</h4>
            <span className="text-slate-400 font-mono text-[10px]">{report.timestamp}</span>
          </div>

          <div className="grid grid-cols-2 gap-3 font-mono">
            <div>
              <span className="text-slate-400 block">IP عمومی:</span>
              <span className="text-white font-bold">{report.ipDetails?.ip}</span>
            </div>
            <div>
              <span className="text-slate-400 block">کشور و ISP:</span>
              <span className="text-white font-bold">{report.ipDetails?.countryName} ({report.ipDetails?.isp})</span>
            </div>
            <div>
              <span className="text-slate-400 block">آزمایش DNS:</span>
              <span className="text-emerald-400 font-bold">{report.dnsLeak?.isLeaking ? 'نشت شناسایی شد' : 'موفق (امن)'}</span>
            </div>
            <div>
              <span className="text-slate-400 block">آزمایش WebRTC:</span>
              <span className="text-emerald-400 font-bold">{report.webRtcLeak?.isLeakingRealIp ? 'نشت شناسایی شد' : 'موفق (محافظت‌شده)'}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex items-center justify-between font-bold">
            <span className="text-slate-300">امتیاز نهایی حریم خصوصی:</span>
            <span className="text-lg font-mono text-cyan-300">{report.privacyScore} / 100</span>
          </div>
        </div>

      </div>
    </div>
  );
};
