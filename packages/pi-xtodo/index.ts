/**
 * pi-xtodo — Todo list extension for Pi.
 * Registers the `todo` tool and `/todos` slash command.
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "@sinclair/typebox";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
export const TOOL_NAME = "todo";
export const TOOL_LABEL = "Todo";
export const COMMAND_NAME = "todos";

export type TaskStatus = "pending" | "in_progress" | "completed" | "deleted";
export type TaskAction = "create" | "update" | "list" | "get" | "delete" | "clear";

export interface Task {
  id: number;
  subject: string;
  description?: string;
  activeForm?: string;
  status: TaskStatus;
  blockedBy?: number[];
  owner?: string;
  metadata?: Record<string, unknown>;
}

interface TaskState {
  tasks: Task[];
  nextId: number;
}

interface TaskDetails {
  action: TaskAction;
  params: Record<string, unknown>;
  tasks: Task[];
  nextId: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// TypeBox Schema
// ---------------------------------------------------------------------------
export const TodoParamsSchema = Type.Object({
  action: Type.String({
    enum: ["create", "update", "list", "get", "delete", "clear"],
    description: "create | update | list | get | delete | clear",
  }),
  subject: Type.Optional(Type.String({ description: "Task subject (required for create)" })),
  description: Type.Optional(Type.String({ description: "Long-form task description" })),
  activeForm: Type.Optional(
    Type.String({ description: "Spinner label while status is in_progress" }),
  ),
  status: Type.Optional(
    Type.String({
      enum: ["pending", "in_progress", "completed", "deleted"],
      description: "Target status (update) or list filter (list)",
    }),
  ),
  blockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Initial blockedBy ids (create only)" }),
  ),
  addBlockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Task ids to add to blockedBy (update)" }),
  ),
  removeBlockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Task ids to remove from blockedBy (update)" }),
  ),
  owner: Type.Optional(Type.String({ description: "Agent/owner assigned" })),
  metadata: Type.Optional(
    Type.Record(Type.String(), Type.Unknown(), { description: "Arbitrary metadata" }),
  ),
  id: Type.Optional(Type.Number({ description: "Task id (required for update, get, delete)" })),
  includeDeleted: Type.Optional(Type.Boolean({ description: "Include deleted tasks in list" })),
});

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const sessions = new Map<string, TaskState>();
/** Bound in-memory sessions; state is persisted to disk, so eviction loses nothing. */
const MAX_SESSIONS = 200;

const sid = (ctx: any): string => ctx.sessionManager.getSessionId() ?? "";
const freshState = (): TaskState => ({ tasks: [], nextId: 1 });
const getSessionState = (sessionId: string): TaskState =>
  sessions.get(sessionId) ?? restoreState(sessionId) ?? freshState();

function setSessionState(id: string, state: TaskState): void {
  sessions.set(id, state);
  while (sessions.size > MAX_SESSIONS) {
    const oldest = sessions.keys().next().value;
    if (oldest === undefined) break;
    sessions.delete(oldest);
  }
}

function xtodoDir(): string {
  const fromEnv = process.env.PI_XTODO_DIR?.trim();
  return fromEnv || join(homedir(), ".pi", "xtodo");
}
function persistPath(id: string): string {
  return join(
    xtodoDir(),
    `${
      id
        .replace(/[^a-zA-Z0-9._-]+/g, "_")
        .replace(/^\.+/, "")
        .slice(0, 128) || "default"
    }.json`,
  );
}
function saveState(id: string, state: TaskState): void {
  try {
    const dir = xtodoDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(persistPath(id), JSON.stringify(state), "utf8");
  } catch {
    /* best-effort */
  }
}
function restoreState(id: string): TaskState | undefined {
  try {
    if (!existsSync(persistPath(id))) return undefined;
    const p = JSON.parse(readFileSync(persistPath(id), "utf8"));
    if (p && Array.isArray(p.tasks) && typeof p.nextId === "number") return p;
  } catch {
    /* corrupt */
  }
  return undefined;
}

/** Rebuild task state from session history (source of truth). */
function replayFromBranch(ctx: any): TaskState {
  const branch = ctx.sessionManager.getBranch();
  let result = freshState();
  for (const entry of branch) {
    if (entry.type !== "message") continue;
    const msg = entry.message;
    if (msg?.role !== "toolResult" || msg.toolName !== TOOL_NAME) continue;
    const d = msg.details as TaskDetails | undefined;
    if (d && Array.isArray(d.tasks) && typeof d.nextId === "number") {
      result = { tasks: d.tasks.map((t) => ({ ...t })), nextId: d.nextId };
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const VALID_TRANSITIONS: Record<TaskStatus, TaskStatus[]> = {
  pending: ["in_progress", "completed", "deleted"],
  in_progress: ["pending", "completed", "deleted"],
  completed: ["deleted"],
  deleted: [],
};

function coerceId(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isInteger(v) && v > 0) return v;
  if (typeof v === "string") {
    const n = Number(v);
    if (Number.isInteger(n) && n > 0 && String(n) === v.trim()) return n;
  }
  return undefined;
}

function coerceIds(v: unknown): number[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: number[] = [];
  const seen = new Set<number>();
  for (const item of v) {
    const n = coerceId(item);
    if (n === undefined) return undefined;
    if (!seen.has(n)) {
      seen.add(n);
      out.push(n);
    }
  }
  return out;
}

function scrubBlockedBy(tasks: Task[], deletedId: number): void {
  for (let i = 0; i < tasks.length; i++) {
    const t = tasks[i];
    if (!t.blockedBy?.length) continue;
    const next = t.blockedBy.filter((d) => d !== deletedId);
    if (next.length !== t.blockedBy.length) {
      tasks[i] = { ...t, blockedBy: next.length ? next : undefined };
    }
  }
}

/** Simple cycle check: walk blockedBy graph from startId; return true if it reaches targetId. */
function wouldCycle(tasks: Task[], startId: number, newBlockedBy: number[]): boolean {
  const adj = new Map(
    tasks.map((t) => [t.id, t.id === startId ? [...newBlockedBy] : [...(t.blockedBy ?? [])]]),
  );
  const visited = new Set<number>();
  const stack = adj.get(startId) ?? [];
  while (stack.length) {
    const n = stack.pop()!;
    if (n === startId) return true;
    if (visited.has(n)) continue;
    visited.add(n);
    for (const neighbor of adj.get(n) ?? []) stack.push(neighbor);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------
function applyMutation(
  state: TaskState,
  action: TaskAction,
  params: any,
): { state: TaskState; text: string; error?: string } {
  const tasks = state.tasks.map((t) => ({ ...t }));
  let nextId = state.nextId;
  const err = (msg: string) => ({ state, text: `Error: ${msg}`, error: msg });

  switch (action) {
    case "create": {
      if (!params.subject?.trim()) return err("subject required for create");
      const blocked = params.blockedBy === undefined ? [] : (coerceIds(params.blockedBy) ?? null);
      if (blocked === null) return err("blockedBy must be an array of numbers");
      for (const dep of blocked) {
        const d = tasks.find((t) => t.id === dep);
        if (!d) return err(`blockedBy: #${dep} not found`);
        if (d.status === "deleted") return err(`blockedBy: #${dep} is deleted`);
      }
      const task: Task = {
        id: nextId++,
        subject: String(params.subject).trim(),
        status: "pending",
        ...(params.description && { description: params.description }),
        ...(params.activeForm && { activeForm: params.activeForm }),
        ...(blocked.length && { blockedBy: blocked }),
        ...(params.owner && { owner: params.owner }),
        ...(params.metadata && { metadata: { ...params.metadata } }),
      };
      tasks.push(task);
      return { state: { tasks, nextId }, text: `Created #${task.id}: ${task.subject} (pending)` };
    }

    case "update": {
      if (params.id === undefined) return err("id required for update");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const idx = tasks.findIndex((t) => t.id === id);
      if (idx === -1) return err(`#${id} not found`);
      const cur = tasks[idx];
      if (cur.status === "deleted") return err(`#${cur.id} is deleted`);

      const addB = params.addBlockedBy !== undefined ? coerceIds(params.addBlockedBy) : undefined;
      if (params.addBlockedBy !== undefined && addB === undefined)
        return err("addBlockedBy must be array of numbers");
      const rmB =
        params.removeBlockedBy !== undefined ? coerceIds(params.removeBlockedBy) : undefined;
      if (params.removeBlockedBy !== undefined && rmB === undefined)
        return err("removeBlockedBy must be array of numbers");

      const hasMutation =
        params.subject !== undefined ||
        params.description !== undefined ||
        params.activeForm !== undefined ||
        params.status !== undefined ||
        params.owner !== undefined ||
        params.metadata !== undefined ||
        params.addBlockedBy !== undefined ||
        params.removeBlockedBy !== undefined;
      if (!hasMutation) {
        return err(
          `update requires a mutable field (subject, description, activeForm, status, owner, metadata, addBlockedBy, removeBlockedBy); keys: [${Object.keys(
            params ?? {},
          )
            .sort()
            .join(", ")}]`,
        );
      }
      if (
        params.subject !== undefined &&
        (params.subject === null || !String(params.subject).trim())
      ) {
        return err("subject cannot be empty");
      }

      let status = cur.status;
      if (params.status !== undefined) {
        if (params.status === null || typeof params.status !== "string")
          return err("status must be a string");
        if (!VALID_TRANSITIONS[status].includes(params.status))
          return err(`illegal transition ${status} → ${params.status}`);
        status = params.status;
      }

      let blocked = cur.blockedBy ? [...cur.blockedBy] : [];
      if (rmB?.length) {
        const s = new Set(rmB);
        blocked = blocked.filter((d) => !s.has(d));
      }
      if (addB?.length) {
        for (const dep of addB) {
          if (dep === cur.id) return err(`cannot block #${cur.id} on itself`);
          const dt = tasks.find((t) => t.id === dep);
          if (!dt) return err(`addBlockedBy: #${dep} not found`);
          if (dt.status === "deleted") return err(`addBlockedBy: #${dep} is deleted`);
          if (!blocked.includes(dep)) blocked.push(dep);
        }
        if (wouldCycle(tasks, cur.id, blocked)) return err("addBlockedBy would create a cycle");
      }

      let metadata = cur.metadata;
      if (params.metadata !== undefined) {
        const merged = { ...(cur.metadata ?? {}) };
        for (const [k, v] of Object.entries(params.metadata)) {
          if (v === null) delete merged[k];
          else merged[k] = v;
        }
        metadata = Object.keys(merged).length ? merged : undefined;
      }

      const updated: Task = {
        ...cur,
        status,
        ...(params.subject !== undefined && { subject: String(params.subject).trim() }),
        ...(params.description !== undefined && {
          description: params.description === null ? undefined : params.description,
        }),
        ...(params.activeForm !== undefined && {
          activeForm: params.activeForm === null ? undefined : params.activeForm,
        }),
        ...(params.owner !== undefined && {
          owner: params.owner === null ? undefined : params.owner,
        }),
        blockedBy: blocked.length ? blocked : undefined,
        metadata,
      };
      tasks[idx] = updated;
      if (params.status === "deleted") scrubBlockedBy(tasks, cur.id);
      const ts = cur.status !== status ? ` (${cur.status} → ${status})` : "";
      return { state: { tasks, nextId }, text: `Updated #${updated.id}${ts}` };
    }

    case "list": {
      let view = tasks;
      if (!params.includeDeleted) view = view.filter((t) => t.status !== "deleted");
      if (params.status) view = view.filter((t) => t.status === params.status);
      const text =
        view.length === 0
          ? "No tasks"
          : view
              .map((t) => {
                const b = t.blockedBy?.length
                  ? ` ⛓ ${t.blockedBy.map((i) => `#${i}`).join(",")}`
                  : "";
                const f = t.status === "in_progress" && t.activeForm ? ` (${t.activeForm})` : "";
                return `[${t.status}] #${t.id} ${t.subject}${f}${b}`;
              })
              .join("\n");
      return { state, text };
    }

    case "get": {
      if (params.id === undefined) return err("id required for get");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const t = tasks.find((x) => x.id === id);
      if (!t) return err(`#${id} not found`);
      const blockers: number[] = [];
      for (const x of tasks) if (x.blockedBy?.includes(t.id)) blockers.push(x.id);
      const lines = [`#${t.id} [${t.status}] ${t.subject}`];
      if (t.description) lines.push(`  description: ${t.description}`);
      if (t.activeForm) lines.push(`  activeForm: ${t.activeForm}`);
      if (t.blockedBy?.length) lines.push(`  blockedBy: #${t.blockedBy.join(", #")}`);
      if (blockers.length) lines.push(`  blocks: #${blockers.join(", #")}`);
      if (t.owner) lines.push(`  owner: ${t.owner}`);
      return { state, text: lines.join("\n") };
    }

    case "delete": {
      if (params.id === undefined) return err("id required for delete");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const idx = tasks.findIndex((t) => t.id === id);
      if (idx === -1) return err(`#${id} not found`);
      if (tasks[idx].status === "deleted") return err(`#${id} is already deleted`);
      tasks[idx] = { ...tasks[idx], status: "deleted" };
      scrubBlockedBy(tasks, id);
      return { state: { tasks, nextId }, text: `Deleted #${id}: ${tasks[idx].subject}` };
    }

    case "clear":
      return { state: freshState(), text: `Cleared ${tasks.length} tasks` };
  }
}

// ---------------------------------------------------------------------------
// Tool Registration
// ---------------------------------------------------------------------------
export default function registerTodo(pi: ExtensionAPI) {
  const STATUS_GLYPH: Record<TaskStatus, string> = {
    pending: "○",
    in_progress: "◐",
    completed: "●",
    deleted: "⊘",
  };
  const ACTION_GLYPH: Record<TaskAction, string> = {
    create: "+",
    update: "→",
    delete: "×",
    get: "›",
    list: "☰",
    clear: "∅",
  };

  pi.registerTool({
    name: TOOL_NAME,
    label: TOOL_LABEL,
    description: "Manage a task list for tracking multi-step progress.",
    parameters: TodoParamsSchema,
    execute: async (_tid, params: any, _extra: any, _enable: any, ctx: any) => {
      const sessionId = sid(ctx);
      const action = params.action as TaskAction;
      const state = getSessionState(sessionId);
      const result = applyMutation(state, action, params);
      if (!result.error) {
        setSessionState(sessionId, result.state);
        saveState(sessionId, result.state);
      }
      return {
        content: [{ type: "text", text: result.text }],
        details: {
          action,
          params,
          tasks: result.state.tasks,
          nextId: result.state.nextId,
          error: result.error,
        } satisfies TaskDetails,
        isError: !!result.error,
      };
    },
    renderResult: (result: any, _options: any, theme: any) => {
      const d = result.details as TaskDetails | undefined;
      const glyph = d && !d.error ? ACTION_GLYPH[d.action] : "✗";
      const preview = result.content?.[0]?.text ?? "";
      const subject = preview.length > 80 ? preview.slice(0, 80) + "…" : preview;
      return new Text(`${theme.fg("toolTitle", glyph)} ${subject}`, 0, 0);
    },
  });

  pi.registerCommand(COMMAND_NAME, {
    description: "Show todo list",
    handler: async (_args, ctx) => {
      const sessionId = sid(ctx);
      const state = getSessionState(sessionId);
      const stored = restoreState(sessionId);
      const t = stored && stored.tasks.length > 0 ? stored : state;
      const active = t.tasks.filter((x) => x.status !== "deleted" && x.status !== "completed");
      const done = t.tasks.filter((x) => x.status === "completed");
      const lines = active
        .map((x) => `  ${STATUS_GLYPH[x.status]} #${x.id} ${x.subject}`)
        .join("\n");
      const doneLine = done.length ? `\n${done.length} completed.` : "";
      ctx.ui.notify(`Todo (${active.length} active${doneLine}):\n${lines}`, "info");
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    let state = replayFromBranch(ctx);
    if (state.nextId === 1) {
      const stored = restoreState(sid(ctx));
      if (stored) state = stored;
    }
    setSessionState(sid(ctx), state);
  });

  pi.on("session_compact", async (_event, ctx) => {
    const sessionId = sid(ctx);
    const state = sessions.get(sessionId);
    if (!state) return;
    const replayed = replayFromBranch(ctx);
    if (replayed.nextId > 1) {
      setSessionState(sessionId, replayed);
    }
  });
}

// Test helpers
export function __resetState(): void {
  sessions.clear();
  try {
    for (const f of readdirSync(xtodoDir())) {
      if (f.endsWith(".json")) unlinkSync(join(xtodoDir(), f));
    }
  } catch {
    // best-effort
  }
}
