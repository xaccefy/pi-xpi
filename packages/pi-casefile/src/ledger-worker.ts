/**
 * Async offload for the two heavy ledger reads — main-thread side.
 *
 * suggestChains is O(rules × cases²) over the whole ledger; writeCaseContext
 * reads every artifact of every matching scratchpad run and builds a
 * multi-hundred-KB bundle. Both ran synchronously inside async tool handlers,
 * stalling the event loop. Each call here spawns a short-lived worker thread
 * (ledger-worker-entry.ts) and falls back to the inline sync function when
 * the worker cannot run (Node < 22.18 has no default type stripping for the
 * TS entry) or times out. Writes stay sync on the main thread: they are
 * single-row upserts, bounded by the 5s busy_timeout.
 */

import { Worker } from "node:worker_threads";
import {
  type CaseContextResult,
  type ChainSuggestion,
  getCasefilePath,
  suggestChains,
  writeCaseContext,
} from "./ledger.ts";
import { detectWorkspaceRoot } from "./scratchpad.ts";

type WorkerResponse = { ok: true; result: unknown } | { ok: false; error: string };

const WORKER_TIMEOUT_MS = 30_000;

function runInLedgerWorker(
  request:
    | {
        op: "suggestChains";
        caseId?: string;
      }
    | {
        op: "writeCaseContext";
        id: string;
      },
): Promise<unknown> {
  const { promise, resolve, reject } = Promise.withResolvers<unknown>();
  const worker = new Worker(new URL("./ledger-worker-entry.ts", import.meta.url), {
    workerData: { casefilePath: getCasefilePath(), workspaceRoot: detectWorkspaceRoot() },
  });
  const timer = setTimeout(() => {
    void worker.terminate();
    reject(new Error("ledger worker timed out"));
  }, WORKER_TIMEOUT_MS);
  worker.once("message", (msg: WorkerResponse) => {
    clearTimeout(timer);
    void worker.terminate();
    if (msg.ok) resolve(msg.result);
    else reject(new Error(msg.error));
  });
  worker.once("error", (e) => {
    clearTimeout(timer);
    reject(e);
  });
  worker.postMessage(request);
  return promise;
}

/** suggestChains on a worker thread; inline fallback keeps behavior identical. */
export async function suggestChainsAsync(caseId?: string): Promise<ChainSuggestion[]> {
  try {
    return (await runInLedgerWorker({ op: "suggestChains", caseId })) as ChainSuggestion[];
  } catch {
    return suggestChains(caseId);
  }
}

/** writeCaseContext on a worker thread; inline fallback keeps behavior identical. */
export async function writeCaseContextAsync(id: string): Promise<CaseContextResult> {
  try {
    return (await runInLedgerWorker({ op: "writeCaseContext", id })) as CaseContextResult;
  } catch {
    return writeCaseContext(id);
  }
}
