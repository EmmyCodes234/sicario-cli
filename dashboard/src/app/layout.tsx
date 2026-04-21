import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { ConvexClientProvider } from "@/lib/convex";

export const metadata: Metadata = {
  title: "Sicario Cloud Dashboard",
  description: "Centralized security findings management and analytics",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <ConvexClientProvider>
          <Sidebar />
          <main className="main-content">{children}</main>
        </ConvexClientProvider>
      </body>
    </html>
  );
}
