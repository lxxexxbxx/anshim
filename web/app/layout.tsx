import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AnShim 대시보드",
  description: "한국 기업을 위한 로컬 LLM 기반 보안 코드 감사 도구",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body>
        <div className="min-h-screen bg-slate-50">
          <header className="bg-white border-b border-slate-200 shadow-sm">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="flex items-center h-16">
                <a href="/" className="flex items-center gap-2 text-slate-900 hover:text-blue-600 transition-colors">
                  <span className="text-2xl font-bold tracking-tight">안심</span>
                  <span className="text-sm text-slate-500 font-medium">AnShim</span>
                </a>
                <nav className="ml-8 flex gap-6">
                  <a href="/" className="text-sm text-slate-600 hover:text-blue-600 transition-colors">
                    대시보드
                  </a>
                </nav>
              </div>
            </div>
          </header>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
