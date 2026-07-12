import type { AuthSession } from "./store.ts";

export type FindingSeverity = "info" | "low" | "medium" | "high";

export interface Finding {
  id: string;
  url: string;
  type: string;
  severity: FindingSeverity;
  detail: string;
  evidence?: string;
  foundAt: number;
}

export type { AuthSession };

/** Minimal fetch signature — avoids the heavy `typeof fetch` (which carries static members like `preconnect`). */
export type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;
