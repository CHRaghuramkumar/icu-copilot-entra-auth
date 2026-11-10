import type { ReactNode } from 'react';
import './globals.css';

export const metadata = {
  title: 'ICU Copilot sign-in',
  description: 'Sign in with Microsoft to use the ICU Clinician Copilot.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
