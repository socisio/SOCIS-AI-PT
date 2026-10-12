import type { Metadata } from 'next';
import './globals.css';
import CsrfFetchGuard from '@/components/CsrfFetchGuard';
import DialogHost from '@/components/ui/DialogHost';

export const metadata: Metadata = {
  title: { default: 'SOCIS-AI-PT', template: '%s | SOCIS-AI-PT' },
  description: 'AI-Powered Penetration Testing Platform — Enterprise Security Operations',
  keywords: ['penetration testing', 'cybersecurity', 'AI', 'vulnerability assessment', 'SOCIS'],
  authors: [{ name: 'SOCIS' }],
  robots: { index: false, follow: false },
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/favicon.png', type: 'image/png' },
    ],
    apple: '/logo.png',
  },
};

// Runs before first paint so a saved light theme never flashes dark.
const THEME_INIT = "try{var t=localStorage.getItem('theme');if(t==='light'||(t==='system'&&window.matchMedia('(prefers-color-scheme: light)').matches))document.documentElement.setAttribute('data-theme','light')}catch(e){}";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
      </head>
      <body><CsrfFetchGuard />{children}<DialogHost /></body>
    </html>
  );
}
