/**
 * Worker-thread entry for heavy ledger reads (suggestChains, writeCaseContext).
 *
 * Runs in a dedicated thread so an O(n²) chain scan or a multi-megabyte
 * context-bundle build never blocks the agent's event loop. Each call spawns
 * a fresh worker — rare operations, no lifecycle to manage, no stale state.
 * The worker opens its OWN connection to the same WAL database (read-mostly
 * work + one small reportPath write); WAL + busy_timeout make multi-connection
 * access safe.
 */

import { parentPort, workerData } from "node:worker_threads";
import { suggestChains, writeCaseContext } from "./ledger.ts";
import { setScratchpadRoot } from "./scratchpad.ts";

process.env.PI_CASEFILE_PATH = workerData.casefilePath as string;
setScratchpadRoot(workerData.workspaceRoot as string | undefined);

type WorkerRequest =
  | { op: "suggestChains"; caseId?: string }
  | { op: "writeCaseContext"; id: string };

parentPort?.on("message", (req: WorkerRequest) => {
  try {
    if (req.op === "suggestChains") {
      parentPort?.postMessage({ ok: true, result: suggestChains(req.caseId) });
    } else if (req.op === "writeCaseContext") {
      parentPort?.postMessage({ ok: true, result: writeCaseContext(req.id) });
    } else {
      parentPort?.postMessage({ ok: false, error: `unknown ledger worker op` });
    }
  } catch (e) {
    parentPort?.postMessage({ ok: false, error: (e as Error).message });
  }
});
