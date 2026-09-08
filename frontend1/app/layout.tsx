import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import './globals.css'
import Providers from './providers'

export const metadata: Metadata = {
  title: 'SIH26145 | Threat Intelligence Console',
  description: 'A premium read-only cybersecurity operations console for network threat intelligence.',
  generator: 'SIH26145',
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#070b14',
  userScalable: false,
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="bg-background">
      <body className="antialiased">
        <Providers>{children}</Providers>
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
