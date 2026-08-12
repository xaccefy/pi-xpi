/**
 * pi-xtodo — Todo list extension for Pi.
 * Registers the `todo` tool and `/todos` slash command.
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DynamicBorder, type ExtensionAPI, keyText } from "@earendil-works/pi-coding-agent";
import { Container, Text, truncateToWidth } from "@earendil-works/pi-tui";
import { Type } from "typebox";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
const TOOL_NAME = "todo";
const TOOL_LABEL = "Todo";
const COMMAND_NAME = "todos";

type TaskStatus = "pending" | "in_progress" | "completed" | "deleted";
type TaskAction = "create" | "update" | "list" | "get" | "delete" | "clear";

interface Task {
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
export const TodoParamsSchema = Type.Object(
  {
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
  },
  { additionalProperties: false },
);

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
  // delete-then-set: Map.set on an existing key does NOT move it to the tail,
  // so eviction would otherwise be FIFO and the long-lived active session
  // would be the first evicted under churn.
  if (sessions.has(id)) sessions.delete(id);
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
  const safe = id
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 128);
  // Sanitization is lossy ("a/b" and "a b" both become "a_b"); distinct
  // session ids must not silently share one state file, so a changed name
  // gets a hash suffix (same disambiguation the scratchpad uses).
  if (safe === id) return join(xtodoDir(), `${safe || "default"}.json`);
  const suffix = createHash("sha256").update(id).digest("hex").slice(0, 12);
  return join(xtodoDir(), `${(safe || "default").slice(0, 80)}-${suffix}.json`);
}
function saveState(id: string, state: TaskState): void {
  try {
    const dir = xtodoDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    // Atomic write (tmp + rename): a crash mid-write must not leave a torn
    // file that restoreState rejects and the whole list is dropped as corrupt.
    const target = persistPath(id);
    const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(tmp, JSON.stringify(state), "utf8");
    renameSync(tmp, target);
  } catch {
    /* best-effort persistence */
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

/**
 * Strip terminal control characters from task text. Task fields are rendered
 * raw into the interactive overlay/widget/notify — an ESC sequence (SGR, clear
 * screen, OSC title, hyperlinks) or C0 control embedded in a subject would be
 * interpreted by the user's terminal (prompt-injected content from a hostile
 * repo is the realistic source). \t \n \r survive; everything else in the C0
 * range plus DEL is removed. Single-line fields (subject/activeForm/owner) also
 * drop \n\r so they cannot split widget rows.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
const CONTROL_CHARS_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
const NEWLINES_RE = /[\r\n]+/g;

function sanitizeText(value: unknown, multiline = false): string {
  let out = String(value ?? "").replace(CONTROL_CHARS_RE, "");
  if (!multiline) out = out.replace(NEWLINES_RE, " ");
  return out;
}

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
      const subject = sanitizeText(params.subject).trim();
      if (!subject) return err("subject required for create");
      const blocked = params.blockedBy === undefined ? [] : (coerceIds(params.blockedBy) ?? null);
      if (blocked === null) return err("blockedBy must be an array of numbers");
      for (const dep of blocked) {
        const d = tasks.find((t) => t.id === dep);
        if (!d) return err(`blockedBy: #${dep} not found`);
        if (d.status === "deleted") return err(`blockedBy: #${dep} is deleted`);
      }
      const task: Task = {
        id: nextId++,
        subject,
        status: "pending",
        ...(params.description && {
          description: sanitizeText(params.description, true),
        }),
        ...(params.activeForm && { activeForm: sanitizeText(params.activeForm) }),
        ...(blocked.length && { blockedBy: blocked }),
        ...(params.owner && { owner: sanitizeText(params.owner) }),
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
        ...(params.subject !== undefined && { subject: sanitizeText(params.subject).trim() }),
        ...(params.description !== undefined && {
          description:
            params.description === null ? undefined : sanitizeText(params.description, true),
        }),
        ...(params.activeForm !== undefined && {
          activeForm: params.activeForm === null ? undefined : sanitizeText(params.activeForm),
        }),
        ...(params.owner !== undefined && {
          owner: params.owner === null ? undefined : sanitizeText(params.owner),
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
// Display
// ---------------------------------------------------------------------------
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

// biome-ignore lint/suspicious/noExplicitAny: theme is provided by the host
function taskLine(t: Task, theme: any): string {
  let line = `${theme.fg("accent", STATUS_GLYPH[t.status])} ${theme.fg("dim", `#${t.id}`)} ${t.subject}`;
  if (t.status === "in_progress" && t.activeForm) line += theme.fg("muted", ` (${t.activeForm})`);
  if (t.blockedBy?.length)
    line += theme.fg("dim", ` ⛓ ${t.blockedBy.map((i) => `#${i}`).join(",")}`);
  return line;
}

// biome-ignore lint/suspicious/noExplicitAny: ctx is provided by the host
async function showTodosOverlay(ctx: any, tasks: Task[]): Promise<void> {
  const active = tasks.filter((t) => t.status !== "completed" && t.status !== "deleted");
  const completed = tasks.filter((t) => t.status === "completed");
  const deleted = tasks.filter((t) => t.status === "deleted");
  const ordered = [...active, ...completed, ...deleted];
  try {
    await ctx.ui.custom(
      // biome-ignore lint/suspicious/noExplicitAny: host-provided values
      (_tui: any, theme: any, _kb: any, done: (v: null) => void) => {
        const container = new Container();
        container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
        container.addChild(
          new Text(
            theme.fg("accent", theme.bold("Todo")) +
              theme.fg("dim", ` — ${active.length} active · ${completed.length} completed`),
            1,
            0,
          ),
        );
        if (ordered.length === 0) {
          container.addChild(new Text(theme.fg("dim", "No tasks"), 1, 0));
        } else {
          for (const t of ordered) container.addChild(new Text(taskLine(t, theme), 1, 0));
        }
        container.addChild(new Text(theme.fg("dim", "esc/q/enter to close"), 1, 0));
        container.addChild(new DynamicBorder((s: string) => theme.fg("accent", s)));
        return {
          render: (w: number) => container.render(w),
          invalidate: () => container.invalidate(),
          handleInput: (data: string) => {
            if (data === "\x1b" || data === "q" || data === "\r" || data === "\n") done(null);
          },
        };
      },
      {
        overlay: true,
        overlayOptions: {
          width: "60%",
          minWidth: 40,
          maxHeight: "80%",
          anchor: "top-center",
          margin: { top: 2 },
        },
      },
    );
  } catch {
    // No interactive UI (or overlays unsupported): fall back to a notification.
    const lines = ordered.map((t) => `${STATUS_GLYPH[t.status]} #${t.id} ${t.subject}`).join("\n");
    ctx.ui?.notify?.(
      `Todo (${active.length} active · ${completed.length} completed):\n${lines || "No tasks"}`,
      "info",
    );
  }
}

// ---------------------------------------------------------------------------
// Persistent widget (above editor)
// ---------------------------------------------------------------------------
const WIDGET_KEY = "pi-xtodo";
/** Max rendered lines before overflow-collapse kicks in. */
const MAX_WIDGET_LINES = 12;

// biome-ignore lint/suspicious/noExplicitAny: host-provided ExtensionUIContext
let widgetUi: any;
// biome-ignore lint/suspicious/noExplicitAny: host-provided TUI
let widgetTui: any;
let widgetRegistered = false;
let widgetSessionId = "";

function widgetTasks(): Task[] {
  // The in-memory map can lose the session under MAX_SESSIONS eviction; the
  // disk file survives, so fall back to it instead of rendering an empty
  // widget until the next event re-reads state.
  const mem = sessions.get(widgetSessionId);
  const state = mem ?? restoreState(widgetSessionId) ?? freshState();
  return state.tasks.filter((t) => t.status !== "deleted");
}

// biome-ignore lint/suspicious/noExplicitAny: theme is provided by the host
function widgetStatusGlyph(status: TaskStatus, theme: any): string {
  switch (status) {
    case "pending":
      return theme.fg("dim", "○");
    case "in_progress":
      return theme.fg("warning", "◐");
    case "completed":
      return theme.fg("success", "✓");
    case "deleted":
      return theme.fg("error", "✗");
  }
}

// biome-ignore lint/suspicious/noExplicitAny: theme is provided by the host
function formatWidgetTask(t: Task, theme: any, showId: boolean): string {
  const glyph = widgetStatusGlyph(t.status, theme);
  const done = t.status === "completed" || t.status === "deleted";
  let subject = theme.fg(done ? "dim" : "text", t.subject);
  if (done) subject = theme.strikethrough(subject);
  let line = `${glyph}`;
  if (showId) line += ` ${theme.fg("accent", `#${t.id}`)}`;
  line += ` ${subject}`;
  if (t.status === "in_progress" && t.activeForm)
    line += ` ${theme.fg("dim", `(${t.activeForm})`)}`;
  if (t.blockedBy?.length)
    line += ` ${theme.fg("dim", `⛓ ${t.blockedBy.map((i) => `#${i}`).join(",")}`)}`;
  return line;
}

/** Build rendered rows. Reads live state at render time via widgetTasks(). */
// biome-ignore lint/suspicious/noExplicitAny: theme is provided by the host
function renderWidgetLines(theme: any, width: number): string[] {
  const all = widgetTasks();
  if (all.length === 0) return [];
  const truncate = (line: string): string => truncateToWidth(line, width);
  const completedCount = all.filter((t) => t.status === "completed").length;
  const hasActive = all.some((t) => t.status === "in_progress" || t.status === "pending");
  // Show per-row ids only when a blockedBy reference needs resolving.
  const showIds = all.some((t) => t.blockedBy?.length);
  const headingColor = hasActive ? "accent" : "dim";
  const heading = truncate(
    theme.fg(headingColor, hasActive ? "●" : "○") +
      " " +
      theme.fg(headingColor, `Todos (${completedCount}/${all.length})`),
  );
  const lines: string[] = [heading];
  const maxBody = MAX_WIDGET_LINES - 1; // heading takes 1 row

  const row = (t: Task, last: boolean): string =>
    truncate(`${theme.fg("dim", last ? "└─" : "├─")} ${formatWidgetTask(t, theme, showIds)}`);

  // Happy path: everything fits in natural order.
  if (all.length <= maxBody) {
    for (let i = 0; i < all.length; i++) lines.push(row(all[i], i === all.length - 1));
    return lines;
  }

  // Overflow: reserve 1 line for the summary, drop completed first (kept in
  // natural order), then truncate the non-completed tail if still overflowing.
  const budget = maxBody - 1;
  const nonCompleted = all.filter((t) => t.status !== "completed");
  let visible: Task[];
  let truncatedTail = 0;
  if (nonCompleted.length <= budget) {
    const kept = new Set<Task>(nonCompleted);
    for (const t of all) {
      if (kept.size >= budget) break;
      if (t.status === "completed") kept.add(t);
    }
    visible = all.filter((t) => kept.has(t));
  } else {
    visible = nonCompleted.slice(0, budget);
    truncatedTail = nonCompleted.length - budget;
  }
  for (const t of visible) lines.push(row(t, false));
  const hiddenCompleted = completedCount - visible.filter((t) => t.status === "completed").length;
  const parts: string[] = [];
  if (hiddenCompleted > 0) parts.push(`${hiddenCompleted} completed`);
  if (truncatedTail > 0) parts.push(`${truncatedTail} pending`);
  const hidden = hiddenCompleted + truncatedTail;
  lines.push(
    truncate(
      `${theme.fg("dim", "└─")} ${theme.fg("dim", `+${hidden} more${parts.length ? ` (${parts.join(", ")})` : ""}`)}`,
    ),
  );
  return lines;
}

/**
 * Idempotent widget refresh. Safe to call from the tool execute and every
 * session event. Registers the factory once, then requestRender() afterwards;
 * unregisters when no visible tasks remain.
 */
// biome-ignore lint/suspicious/noExplicitAny: ctx is provided by the host
function refreshWidget(ctx: any, sessionId?: string): void {
  if (sessionId !== undefined) widgetSessionId = sessionId;
  if (!ctx?.hasUI || !ctx.ui) return;
  if (ctx.ui !== widgetUi) {
    // Fresh UI context (reload/new session) — re-register under it.
    widgetUi = ctx.ui;
    widgetRegistered = false;
    widgetTui = undefined;
  }

  if (widgetTasks().length === 0) {
    if (widgetRegistered) {
      widgetUi.setWidget(WIDGET_KEY, undefined);
      widgetRegistered = false;
      widgetTui = undefined;
    }
    return;
  }

  if (!widgetRegistered) {
    // biome-ignore lint/suspicious/noExplicitAny: host-provided values
    widgetUi.setWidget(WIDGET_KEY, (tui: any, theme: any) => {
      widgetTui = tui;
      return {
        render: (w: number) => renderWidgetLines(theme, w),
        invalidate: () => {
          // Theme changed — force re-registration under a fresh factory.
          widgetRegistered = false;
          widgetTui = undefined;
        },
      };
    });
    widgetRegistered = true;
  } else {
    widgetTui?.requestRender?.();
  }
}

// ---------------------------------------------------------------------------
// Tool Registration
// ---------------------------------------------------------------------------
export default function registerTodo(pi: ExtensionAPI) {
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
      if (result.error) throw new Error(result.error);
      setSessionState(sessionId, result.state);
      saveState(sessionId, result.state);
      refreshWidget(ctx, sessionId);
      return {
        content: [{ type: "text", text: result.text }],
        details: {
          action,
          params,
          tasks: result.state.tasks,
          nextId: result.state.nextId,
        } satisfies TaskDetails,
      };
    },
    renderResult: (result: any, options: any, theme: any, context: any) => {
      const d = result.details as TaskDetails | undefined;
      const text: string = result.content?.[0]?.text ?? "";
      if (context?.isError) {
        return new Text(`${theme.fg("error", "✗")} ${theme.fg("error", text)}`, 0, 0);
      }
      const glyph = d ? ACTION_GLYPH[d.action] : "•";
      const lines = text.split("\n");
      if (lines.length === 1 || options?.expanded) {
        return new Text(`${theme.fg("toolTitle", glyph)} ${text}`, 0, 0);
      }
      const summary = d?.action === "list" ? `${lines.length} tasks` : lines[0];
      const key = keyText("app.tools.expand");
      const hint = key
        ? `${theme.fg("dim", key)}${theme.fg("muted", " to expand")}`
        : theme.fg("dim", "expand for full output");
      return new Text(
        `${theme.fg("toolTitle", glyph)} ${summary} (+${lines.length - 1} lines, ${hint})`,
        0,
        0,
      );
    },
  });

  pi.registerCommand(COMMAND_NAME, {
    description: "Show todo list overlay",
    handler: async (_args, ctx) => {
      const sessionId = sid(ctx);
      // Disk wins when it has tasks; otherwise show whatever is in memory.
      const stored = restoreState(sessionId);
      const t =
        stored && stored.tasks.length > 0 ? stored : (sessions.get(sessionId) ?? freshState());
      await showTodosOverlay(ctx, t.tasks);
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    // Same guard as settleState (session_compact): the branch's last
    // tool-result snapshot can be OLDER than disk after compaction dropped
    // newer results, so disk must win when it has tasks — otherwise a restart
    // resurrects stale state and the next mutation overwrites the newer disk
    // file, silently losing tasks and reusing their IDs.
    settleState(ctx, sid(ctx));
  });

  // After compaction/tree events the last surviving tool-result snapshot in
  // the branch can be OLDER than memory (compaction drops the newer ones),
  // so the branch is NOT unconditionally the source of truth here. Prefer the
  // freshest local source (memory or disk — disk is written on every successful
  // mutation) and only fall back to branch replay when no local state exists.
  const settleState = (ctx: any, sessionId: string) => {
    const replayed = replayFromBranch(ctx);
    const mem = sessions.get(sessionId) ?? freshState();
    const disk = restoreState(sessionId) ?? freshState();
    const local = mem.nextId >= disk.nextId ? mem : disk;
    const next = local.nextId > 1 ? local : replayed.nextId > 1 ? replayed : local;
    setSessionState(sessionId, next);
    refreshWidget(ctx, sessionId);
  };

  pi.on("session_compact", async (_event, ctx) => {
    settleState(ctx, sid(ctx));
  });

  pi.on("session_tree", async (_event, ctx) => {
    settleState(ctx, sid(ctx));
  });

  pi.on("session_shutdown", async () => {
    if (widgetRegistered && widgetUi) {
      try {
        widgetUi.setWidget(WIDGET_KEY, undefined);
      } catch {
        // UI already gone
      }
    }
    widgetUi = undefined;
    widgetTui = undefined;
    widgetRegistered = false;
    widgetSessionId = "";
  });
}

// Test helpers
export function __resetState(): void {
  const dir = xtodoDir();
  // Destructive wipe guard: a test that forgets to point PI_XTODO_DIR at a
  // temp dir would delete every session's real state under ~/.pi/xtodo.
  // Refuse unless the env override is explicitly set.
  if (!process.env.PI_XTODO_DIR?.trim()) {
    throw new Error(
      "__resetState refuses to run against the default todo dir — set PI_XTODO_DIR to a temp dir in tests",
    );
  }
  sessions.clear();
  widgetUi = undefined;
  widgetTui = undefined;
  widgetRegistered = false;
  widgetSessionId = "";
  try {
    for (const f of readdirSync(dir)) {
      if (f.endsWith(".json")) unlinkSync(join(dir, f));
    }
  } catch {
    // best-effort
  }
}
