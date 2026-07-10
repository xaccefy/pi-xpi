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

/**
 * Every action the single `engage` tool supports.
 * Session + a pdtm-tool bridge — no MITM proxy required: the resolved auth is
 * injected straight into curl / nuclei / httpx / ffuf / etc.
 */
export type EngageAction =
  | "add"
  | "get"
  | "list"
  | "token"
  | "delete"
  | "clear"
  | "run"
  | "send"
  | "spider"
  | "scan";

export type { AuthSession };

/** Minimal fetch signature — avoids the heavy `typeof fetch` (which carries static members like `preconnect`). */
export type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;
