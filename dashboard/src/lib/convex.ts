"use client";

import { ConvexProvider, ConvexReactClient } from "convex/react";
import { ReactNode, useMemo } from "react";
import React from "react";

const CONVEX_URL = process.env.NEXT_PUBLIC_CONVEX_URL || "https://flexible-terrier-680.convex.cloud";

export function ConvexClientProvider({ children }: { children: ReactNode }) {
  const client = useMemo(() => new ConvexReactClient(CONVEX_URL), []);
  return React.createElement(ConvexProvider, { client }, children);
}

// Re-export for convenience
export { CONVEX_URL };
