/**
 * pi-xtodo — Simplified single-file todo list extension for Pi.
 * Registers the `todo` tool, `/todos` slash command, and persistent TodoOverlay.
 */

import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionUIContext, Theme } from "@earendil-works/pi-coding-agent";
import { Text, type TUI, truncateToWidth } from "@earendil-works/pi-tui";
import { type Static, type TSchema, Type } from "@sinclair/typebox";

/**
 * String enum as `{ type: "string", enum: [...] }` (provider-safe + TypeBox Kind "String").
 *
 * Do NOT use Type.Union(Type.Literal...) → anyOf/const (providers drop optional fields).
 * Do NOT use Type.Unsafe → Kind "Unsafe"; Pi's typebox/Compile treats it as unknown.
 * Type.String({ enum }) is Kind "String", works with Value.Convert/Check/Compile,
 * and serializes as plain string enum (same end shape as rpiv-todo StringEnum).
 */
function StringEnum<T extends readonly string[]>(
  values: T,
  options?: { description?: string },
): TSchema {
  return Type.String({
    enum: [...values],
    ...(options?.description ? { description: options.description } : {}),
  }) as unknown as TSchema;
}

// ---------------------------------------------------------------------------
// Identity & Types
// ---------------------------------------------------------------------------
export const TOOL_NAME = "todo";
export const TOOL_LABEL = "Todo";
export const COMMAND_NAME = "todos";
const WIDGET_KEY = "pi-xtodo";

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

export interface TaskState {
  tasks: Task[];
  nextId: number;
}

export interface TaskDetails {
  action: TaskAction;
  params: Record<string, unknown>;
  tasks: Task[];
  nextId: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// TypeBox Schema
// ---------------------------------------------------------------------------
// Use StringEnum (type+enum), NOT Type.Union(Type.Literal...) which compiles to
// anyOf/const — several providers (and Pi's tool arg validation) drop optional
// anyOf fields, so status-only updates arrived as {action,id} and failed with
// "update requires at least one mutable field". Matches rpiv-todo.
export const TodoParamsSchema = Type.Object({
  action: StringEnum(["create", "update", "list", "get", "delete", "clear"] as const, {
    description: "create | update | list | get | delete | clear",
  }),
  subject: Type.Optional(Type.String({ description: "Task subject line (required for create)" })),
  description: Type.Optional(Type.String({ description: "Long-form task description" })),
  activeForm: Type.Optional(
    Type.String({
      description: "Present-continuous spinner label shown while status is in_progress",
    }),
  ),
  status: Type.Optional(
    StringEnum(["pending", "in_progress", "completed", "deleted"] as const, {
      description: "Target status (update) or list filter (list)",
    }),
  ),
  blockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Initial blockedBy ids (create only)" }),
  ),
  addBlockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Task ids to add to blockedBy (update only)" }),
  ),
  removeBlockedBy: Type.Optional(
    Type.Array(Type.Number(), { description: "Task ids to remove from blockedBy (update only)" }),
  ),
  owner: Type.Optional(Type.String({ description: "Agent/owner assigned to this task" })),
  metadata: Type.Optional(
    Type.Record(Type.String(), Type.Unknown(), { description: "Arbitrary metadata" }),
  ),
  id: Type.Optional(Type.Number({ description: "Task id (required for update, get, delete)" })),
  includeDeleted: Type.Optional(
    Type.Boolean({ description: "If true, list returns deleted tasks too" }),
  ),
});

export type TodoParams = Static<typeof TodoParamsSchema>;

// ---------------------------------------------------------------------------
// State Management (Per-Session Store & Replay)
// ---------------------------------------------------------------------------

const sessions = new Map<string, TaskState>();
let activeRenderSession = "";

// Replay cache: avoid rescanning the entire branch message history on every
// session event when nothing has changed (keyed by session id + branch length).
const replayCache = new Map<string, { len: number; state: TaskState }>();

// Test seam: how many times replayFromBranch actually recomputed state (vs. served
// a cache hit). Exposed via __replayComputeCount so tests can assert the cache-skip fires.
let replayComputeCount = 0;

// Disk persistence: survive agent/session restarts. The branch message history
// remains the source of truth; this is a fallback when history isn't replayed yet.
const XTODO_DIR = join(homedir(), ".pi", "xtodo");
/** Reject path separators / traversal so session ids cannot escape XTODO_DIR. */
function safeSessionFileId(id: string): string {
  const cleaned = String(id ?? "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 128);
  return cleaned || "default";
}
function persistPath(id: string): string {
  return join(XTODO_DIR, `${safeSessionFileId(id)}.json`);
}
function saveSessionState(id: string, state: TaskState): void {
  try {
    if (!existsSync(XTODO_DIR)) mkdirSync(XTODO_DIR, { recursive: true });
    writeFileSync(persistPath(id), JSON.stringify(state), "utf8");
  } catch {
    // Best-effort persistence.
  }
}
function restoreSessionState(id: string): TaskState | undefined {
  try {
    if (!existsSync(persistPath(id))) return undefined;
    const parsed = JSON.parse(readFileSync(persistPath(id), "utf8")) as TaskState;
    if (parsed && Array.isArray(parsed.tasks) && typeof parsed.nextId === "number") {
      return { tasks: parsed.tasks, nextId: parsed.nextId };
    }
  } catch {
    // Corrupt or unreadable file — ignore.
  }
  return undefined;
}

const sid = (ctx: any): string => ctx.sessionManager.getSessionId() ?? "";
const freshState = (): TaskState => ({ tasks: [], nextId: 1 });
const getSessionState = (sessionId: string): TaskState => sessions.get(sessionId) ?? freshState();

// Reconstruct tasks state from session messages history
export function replayFromBranch(ctx: any): TaskState {
  const id = sid(ctx);
  const branch = ctx.sessionManager.getBranch();
  const len = branch.length;
  const cached = replayCache.get(id);
  if (cached && cached.len === len) {
    return cached.state;
  }
  replayComputeCount++;
  let result = freshState();
  for (const entry of branch) {
    if (entry.type !== "message") continue;
    const msg = entry.message;
    if (msg?.role !== "toolResult" || msg.toolName !== TOOL_NAME) continue;
    const details = msg.details as TaskDetails | undefined;
    if (details && Array.isArray(details.tasks) && typeof details.nextId === "number") {
      result = {
        tasks: details.tasks.map((t) => ({ ...t })),
        nextId: details.nextId,
      };
    }
  }
  replayCache.set(id, { len, state: result });
  return result;
}

// ---------------------------------------------------------------------------
// Reducer Logic & Cycle Detection
// ---------------------------------------------------------------------------
const VALID_TRANSITIONS: Record<TaskStatus, TaskStatus[]> = {
  pending: ["in_progress", "completed", "deleted"],
  in_progress: ["pending", "completed", "deleted"],
  completed: ["deleted"],
  deleted: [],
};

function hasCycle(tasks: Task[], taskId: number, newBlockedBy: number[]): boolean {
  // newBlockedBy is the full replacement dependency list for taskId (not a delta).
  const adj = new Map(
    tasks.map((t) => [t.id, t.id === taskId ? [...newBlockedBy] : [...(t.blockedBy ?? [])]]),
  );
  const visiting = new Set<number>();
  const visited = new Set<number>();

  const dfs = (node: number): boolean => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    visiting.add(node);
    for (const neighbor of adj.get(node) ?? []) {
      if (dfs(neighbor)) return true;
    }
    visiting.delete(node);
    visited.add(node);
    return false;
  };

  // Only taskId's outbound edges changed; any new cycle must be reachable from it.
  return dfs(taskId);
}

/** Coerce tool-call ids (models often send numeric strings) to positive integers. */
function coerceId(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const n = Number(value);
    // Reject "2.7", "1e2", NaN — only plain positive integers.
    if (Number.isInteger(n) && n > 0 && String(n) === value.trim()) return n;
  }
  return undefined;
}

/** Drop a deleted task id from every other task's blockedBy list. */
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

function coerceIdList(value: unknown): number[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: number[] = [];
  const seen = new Set<number>();
  for (const item of value) {
    const n = coerceId(item);
    if (n === undefined) return undefined;
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

interface ReducerOutput {
  state: TaskState;
  text: string;
  error?: string;
}

function applyMutation(state: TaskState, action: TaskAction, params: any): ReducerOutput {
  const tasks = state.tasks.map((t) => ({ ...t }));
  let nextId = state.nextId;

  const err = (msg: string): ReducerOutput => ({ state, text: `Error: ${msg}`, error: msg });

  switch (action) {
    case "create": {
      if (!params.subject?.trim()) return err("subject required for create");
      const blocked =
        params.blockedBy === undefined ? [] : (coerceIdList(params.blockedBy) ?? null);
      if (blocked === null) return err("blockedBy must be an array of numbers");
      for (const dep of blocked) {
        const depTask = tasks.find((t) => t.id === dep);
        if (!depTask) return err(`blockedBy: #${dep} not found`);
        if (depTask.status === "deleted") return err(`blockedBy: #${dep} is deleted`);
      }
      const newTask: Task = {
        id: nextId++,
        subject: String(params.subject).trim(),
        status: "pending",
        ...(params.description && { description: params.description }),
        ...(params.activeForm && { activeForm: params.activeForm }),
        ...(blocked.length && { blockedBy: blocked }),
        ...(params.owner && { owner: params.owner }),
        ...(params.metadata && { metadata: { ...params.metadata } }),
      };
      tasks.push(newTask);
      return {
        state: { tasks, nextId },
        text: `Created #${newTask.id}: ${newTask.subject} (pending)`,
      };
    }

    case "update": {
      if (params.id === undefined) return err("id required for update");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const idx = tasks.findIndex((t) => t.id === id);
      if (idx === -1) return err(`#${id} not found`);
      const cur = tasks[idx];
      if (cur.status === "deleted") return err(`#${cur.id} is deleted`);

      const addBlockedBy =
        params.addBlockedBy !== undefined ? coerceIdList(params.addBlockedBy) : undefined;
      if (params.addBlockedBy !== undefined && addBlockedBy === undefined) {
        return err("addBlockedBy must be an array of numbers");
      }
      const removeBlockedBy =
        params.removeBlockedBy !== undefined ? coerceIdList(params.removeBlockedBy) : undefined;
      if (params.removeBlockedBy !== undefined && removeBlockedBy === undefined) {
        return err("removeBlockedBy must be an array of numbers");
      }

      // Explicitly-provided fields count even when empty (e.g. addBlockedBy: []).
      // Models often send status-only updates; do not require a second field.
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
        const keys = Object.keys(params ?? {})
          .sort()
          .join(", ");
        return err(
          `update requires at least one mutable field (subject, description, activeForm, status, owner, metadata, addBlockedBy, removeBlockedBy); received keys: [${keys}]`,
        );
      }

      if (params.subject !== undefined && (params.subject === null || !String(params.subject).trim())) {
        return err("subject cannot be empty");
      }

      let status = cur.status;
      if (params.status !== undefined) {
        if (params.status !== null && typeof params.status !== "string") {
          return err("status must be a string");
        }
        if (status !== params.status && !VALID_TRANSITIONS[status].includes(params.status)) {
          return err(`illegal transition ${status} → ${params.status}`);
        }
        status = params.status;
      }

      let blocked = cur.blockedBy ? [...cur.blockedBy] : [];
      if (removeBlockedBy?.length) {
        const rm = new Set(removeBlockedBy);
        blocked = blocked.filter((d) => !rm.has(d));
      }
      if (addBlockedBy?.length) {
        for (const dep of addBlockedBy) {
          if (dep === cur.id) return err(`cannot block #${cur.id} on itself`);
          const depTask = tasks.find((t) => t.id === dep);
          if (!depTask) return err(`addBlockedBy: #${dep} not found`);
          if (depTask.status === "deleted") return err(`addBlockedBy: #${dep} is deleted`);
          if (!blocked.includes(dep)) blocked.push(dep);
        }
        if (hasCycle(tasks, cur.id, blocked)) {
          return err("addBlockedBy would create a cycle in the blockedBy graph");
        }
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
      // Soft-delete via status=deleted must also free dependents (same as delete action).
      // Use params.status: after the early deleted-guard, TS narrows `status` away from "deleted".
      if (params.status === "deleted") {
        scrubBlockedBy(tasks, cur.id);
      }
      const transitionStr = cur.status !== status ? ` (${cur.status} → ${status})` : "";
      return {
        state: { tasks, nextId },
        text: `Updated #${updated.id}${transitionStr}`,
      };
    }

    case "list": {
      let view = tasks;
      if (!params.includeDeleted) view = view.filter((t) => t.status !== "deleted");
      if (params.status) view = view.filter((t) => t.status === params.status);
      const formatted =
        view.length === 0
          ? "No tasks"
          : view
              .map((t) => {
                const block = t.blockedBy?.length
                  ? ` ⛓ ${t.blockedBy.map((id) => `#${id}`).join(",")}`
                  : "";
                const form = t.status === "in_progress" && t.activeForm ? ` (${t.activeForm})` : "";
                return `[${t.status}] #${t.id} ${t.subject}${form}${block}`;
              })
              .join("\n");
      return { state, text: formatted };
    }

    case "get": {
      if (params.id === undefined) return err("id required for get");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const task = tasks.find((t) => t.id === id);
      if (!task) return err(`#${id} not found`);

      const blocks: number[] = [];
      for (const t of tasks) {
        if (t.blockedBy?.includes(task.id)) blocks.push(t.id);
      }

      const lines = [`#${task.id} [${task.status}] ${task.subject}`];
      if (task.description) lines.push(`  description: ${task.description}`);
      if (task.activeForm) lines.push(`  activeForm: ${task.activeForm}`);
      if (task.blockedBy?.length)
        lines.push(`  blockedBy: ${task.blockedBy.map((id) => `#${id}`).join(", ")}`);
      if (blocks.length) lines.push(`  blocks: ${blocks.map((id) => `#${id}`).join(", ")}`);
      if (task.owner) lines.push(`  owner: ${task.owner}`);
      return { state, text: lines.join("\n") };
    }

    case "delete": {
      if (params.id === undefined) return err("id required for delete");
      const id = coerceId(params.id);
      if (id === undefined) return err("id must be a number");
      const idx = tasks.findIndex((t) => t.id === id);
      if (idx === -1) return err(`#${id} not found`);
      const cur = tasks[idx];
      if (cur.status === "deleted") return err(`#${cur.id} is already deleted`);
      tasks[idx] = { ...cur, status: "deleted" };
      // Dependents must not stay blocked on a tombstone forever.
      scrubBlockedBy(tasks, cur.id);
      return {
        state: { tasks, nextId },
        text: `Deleted #${cur.id}: ${cur.subject}`,
      };
    }

    case "clear": {
      return {
        state: freshState(),
        text: `Cleared ${tasks.length} tasks`,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// TUI Rendering & Format Helpers
// ---------------------------------------------------------------------------
const STATUS_GLYPH: Record<TaskStatus, string> = {
  pending: "○",
  in_progress: "◐",
  completed: "●",
  deleted: "⊘",
};
const STATUS_COLOR: Record<TaskStatus, "dim" | "warning" | "success" | "muted"> = {
  pending: "dim",
  in_progress: "warning",
  completed: "success",
  deleted: "muted",
};
const ACTION_GLYPH: Record<TaskAction, string> = {
  create: "+",
  update: "→",
  delete: "×",
  get: "›",
  list: "☰",
  clear: "∅",
};

function formatOverlayTaskLine(t: Task, theme: Theme, showId: boolean): string {
  const glyph =
    t.status === "pending"
      ? theme.fg("dim", "○")
      : t.status === "in_progress"
        ? theme.fg("warning", "◐")
        : t.status === "completed"
          ? theme.fg("success", "✓")
          : theme.fg("error", "✗");
  const sc = t.status === "completed" || t.status === "deleted" ? "dim" : "text";
  let subject = theme.fg(sc, t.subject);
  if (t.status === "completed" || t.status === "deleted") subject = theme.strikethrough(subject);
  let line = `${glyph}`;
  if (showId) line += ` ${theme.fg("accent", `#${t.id}`)}`;
  line += ` ${subject}`;
  if (t.status === "in_progress" && t.activeForm)
    line += ` ${theme.fg("dim", `(${t.activeForm})`)}`;
  if (t.blockedBy?.length)
    line += ` ${theme.fg("dim", `⛓ ${t.blockedBy.map((id) => `#${id}`).join(",")}`)}`;
  return line;
}

// ---------------------------------------------------------------------------
// Todo Overlay Widget
// ---------------------------------------------------------------------------
export class TodoOverlay {
  private uiCtx: ExtensionUIContext | undefined;
  private widgetRegistered = false;
  private tui: TUI | undefined;
  private completedTaskIdsPendingHide = new Set<number>();
  private hiddenCompletedTaskIds = new Set<number>();
  private lastNextId: number | undefined;

  setUICtx(ctx: ExtensionUIContext): void {
    if (ctx !== this.uiCtx) {
      this.uiCtx = ctx;
      this.widgetRegistered = false;
      this.tui = undefined;
    }
  }

  dispose(): void {
    if (this.uiCtx) this.uiCtx.setWidget(WIDGET_KEY, undefined);
    this.widgetRegistered = false;
    this.tui = undefined;
    this.uiCtx = undefined;
    this.resetCompletedDisplayState();
  }

  update(): void {
    if (!this.uiCtx) return;
    const snapshot = getSessionState(activeRenderSession);
    const visible = snapshot.tasks.filter(
      (t) =>
        t.status !== "deleted" &&
        !(t.status === "completed" && this.hiddenCompletedTaskIds.has(t.id)),
    );

    if (visible.length === 0) {
      if (this.widgetRegistered) {
        this.uiCtx.setWidget(WIDGET_KEY, undefined);
        this.widgetRegistered = false;
        this.tui = undefined;
      }
      return;
    }

    if (!this.widgetRegistered) {
      this.uiCtx.setWidget(
        WIDGET_KEY,
        (tui, theme) => {
          this.tui = tui;
          return {
            render: (width: number) => this.renderWidget(theme, width),
            invalidate: () => {
              this.widgetRegistered = false;
              this.tui = undefined;
            },
          };
        },
        { placement: "aboveEditor" },
      );
      this.widgetRegistered = true;
    } else {
      this.tui?.requestRender();
    }
  }

  resetCompletedDisplayState(): void {
    this.completedTaskIdsPendingHide.clear();
    this.hiddenCompletedTaskIds.clear();
    this.lastNextId = undefined;
  }

  hideCompletedTasksFromPreviousTurn(): void {
    if (this.completedTaskIdsPendingHide.size === 0) return;
    for (const id of this.completedTaskIdsPendingHide) {
      this.hiddenCompletedTaskIds.add(id);
    }
    this.completedTaskIdsPendingHide.clear();
    this.tui?.requestRender();
  }

  private renderWidget(theme: Theme, width: number): string[] {
    const state = getSessionState(activeRenderSession);
    if (this.lastNextId !== undefined && state.nextId < this.lastNextId) {
      this.resetCompletedDisplayState();
    }
    this.lastNextId = state.nextId;

    const completedSet = new Set(
      state.tasks.filter((t) => t.status === "completed").map((t) => t.id),
    );
    for (const id of this.completedTaskIdsPendingHide)
      if (!completedSet.has(id)) this.completedTaskIdsPendingHide.delete(id);
    for (const id of this.hiddenCompletedTaskIds)
      if (!completedSet.has(id)) this.hiddenCompletedTaskIds.delete(id);

    const overlayTasks = state.tasks.filter(
      (t) =>
        t.status !== "deleted" &&
        !(t.status === "completed" && this.hiddenCompletedTaskIds.has(t.id)),
    );
    if (overlayTasks.length === 0) return [];

    const truncate = (line: string): string => truncateToWidth(line, width, "…");
    const total = overlayTasks.filter((t) => t.status !== "deleted").length;
    const completed = overlayTasks.filter((t) => t.status === "completed").length;
    const hasActive = overlayTasks.some(
      (t) => t.status === "in_progress" || t.status === "pending",
    );
    const showIds = overlayTasks.some((t) => t.blockedBy && t.blockedBy.length > 0);

    const headingColor = hasActive ? "accent" : "dim";
    const headingIcon = hasActive ? "●" : "○";
    const heading = truncate(
      `${theme.fg(headingColor, headingIcon)} ${theme.fg(headingColor, `Todos (${completed}/${total})`)}`,
    );

    const lines = [heading];
    const budget = 11; // getMaxWidgetLines() - 1, simplified to 11
    const nonCompleted = overlayTasks.filter((t) => t.status !== "completed");
    const totalCompleted = overlayTasks.length - nonCompleted.length;

    let visible: Task[] = [];
    let hiddenCompleted = 0;
    let truncatedTail = 0;

    if (overlayTasks.length <= budget) {
      visible = overlayTasks;
    } else if (nonCompleted.length <= budget) {
      const kept = new Set<Task>(nonCompleted);
      for (const t of overlayTasks) {
        if (kept.size >= budget) break;
        if (t.status === "completed") kept.add(t);
      }
      visible = overlayTasks.filter((t) => kept.has(t));
      hiddenCompleted = totalCompleted - visible.filter((t) => t.status === "completed").length;
    } else {
      visible = nonCompleted.slice(0, budget);
      truncatedTail = nonCompleted.length - budget;
      hiddenCompleted = totalCompleted;
    }

    for (const task of visible) {
      lines.push(
        truncate(`${theme.fg("dim", "├─")} ${formatOverlayTaskLine(task, theme, showIds)}`),
      );
    }

    for (const t of overlayTasks) {
      if (
        t.status === "completed" &&
        !this.completedTaskIdsPendingHide.has(t.id) &&
        !this.hiddenCompletedTaskIds.has(t.id)
      ) {
        this.completedTaskIdsPendingHide.add(t.id);
      }
    }

    if (hiddenCompleted === 0 && truncatedTail === 0) {
      lines[lines.length - 1] = lines[lines.length - 1].replace("├─", "└─");
    } else {
      const overflow: string[] = [];
      if (hiddenCompleted > 0) overflow.push(`${hiddenCompleted} completed`);
      if (truncatedTail > 0) overflow.push(`${truncatedTail} pending`);
      const summary = `+${hiddenCompleted + truncatedTail} more (${overflow.join(", ")})`;
      lines.push(truncate(`${theme.fg("dim", "└─")} ${theme.fg("dim", summary)}`));
    }

    lines.push("");
    return lines;
  }
}

// ---------------------------------------------------------------------------
// Extension Entry Point & Setup
// ---------------------------------------------------------------------------
export default function (pi: ExtensionAPI) {
  let todoOverlay: TodoOverlay | undefined;

  pi.registerTool({
    name: TOOL_NAME,
    label: TOOL_LABEL,
    description: "Manage a task list for tracking multi-step progress.",
    promptSnippet: "Manage a task list to track multi-step progress",
    promptGuidelines: [
      "Use `todo` for complex work with 3+ steps.",
      "Mark a task `in_progress` before beginning, and `completed` immediately when done.",
      "Task status: pending → in_progress → completed, plus deleted as a tombstone.",
    ],
    parameters: TodoParamsSchema,

    // Coerce common LLM shapes before schema validation (string ids, etc.).
    prepareArguments: (args: unknown) => {
      const a = { ...((args ?? {}) as Record<string, unknown>) };
      if (a.id !== undefined && a.id !== null && typeof a.id !== "number") {
        const n = Number(a.id);
        if (Number.isInteger(n) && n > 0) a.id = n;
      }
      for (const key of ["blockedBy", "addBlockedBy", "removeBlockedBy"] as const) {
        if (!Array.isArray(a[key])) continue;
        a[key] = (a[key] as unknown[]).map((v) => {
          if (typeof v === "number") return v;
          const n = Number(v);
          return Number.isInteger(n) ? n : v;
        });
      }
      return a;
    },

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const action = params.action as TaskAction;
      const id = sid(ctx);
      const state = getSessionState(id);
      // Defensive copy: some runtimes pass a frozen/partial params object.
      const raw = { ...((params ?? {}) as Record<string, unknown>) };
      const result = applyMutation(state, action, raw);
      if (!result.error) {
        sessions.set(id, result.state);
        saveSessionState(id, result.state);
        // Branch length may not have advanced yet; drop cache so compact/tree
        // cannot overwrite live state with a stale replay snapshot.
        replayCache.delete(id);
      }

      const details: TaskDetails = {
        action,
        params: raw,
        tasks: result.state.tasks,
        nextId: result.state.nextId,
        ...(result.error && { error: result.error }),
      };

      return {
        content: [{ type: "text" as const, text: result.text }],
        ...(result.error ? { isError: true } : {}),
        details,
      };
    },

    renderCall(args: any, theme, _context) {
      const state = getSessionState(activeRenderSession);
      const glyph = ACTION_GLYPH[args.action as TaskAction] ?? args.action;
      let text = theme.fg("toolTitle", theme.bold("todo ")) + theme.fg("muted", glyph);
      if (args.action === "create" && args.subject) {
        text += ` ${theme.fg("dim", args.subject)}`;
      } else if (
        (args.action === "update" || args.action === "get" || args.action === "delete") &&
        args.id !== undefined
      ) {
        const callId = coerceId(args.id);
        const subj =
          callId !== undefined ? state.tasks.find((t) => t.id === callId)?.subject : undefined;
        text += ` ${theme.fg("accent", subj ?? `#${args.id}`)}`;
      } else if (args.action === "list" && args.status) {
        text += ` ${theme.fg("muted", args.status === "in_progress" ? "in progress" : args.status)}`;
      }
      return new Text(text, 0, 0);
    },

    renderResult(result, _opts, theme, _context) {
      const details = result.details as TaskDetails | undefined;
      if (details?.error) {
        return new Text(theme.fg("error", "✗"), 0, 0);
      }
      let status: TaskStatus | undefined;
      if (details) {
        const p = details.params as any;
        if (details.action === "create") status = details.tasks[details.tasks.length - 1]?.status;
        else if (details.action === "update") {
          const callId = coerceId(p.id);
          status =
            p.status ??
            (callId !== undefined ? details.tasks.find((t) => t.id === callId)?.status : undefined);
        } else if (details.action === "delete") {
          const callId = coerceId(p.id);
          status =
            callId !== undefined ? details.tasks.find((t) => t.id === callId)?.status : undefined;
        }
      }
      if (status)
        return new Text(
          theme.fg(
            STATUS_COLOR[status],
            `${STATUS_GLYPH[status]} ${status === "in_progress" ? "in progress" : status}`,
          ),
          0,
          0,
        );
      return new Text(theme.fg("success", "✓"), 0, 0);
    },
  });

  pi.registerCommand(COMMAND_NAME, {
    description: "Show all todos grouped by status",
    handler: async (_args, ctx) => {
      if (!ctx.hasUI) {
        ctx.ui.notify("/todos requires interactive mode", "error");
        return;
      }
      const state = getSessionState(sid(ctx));
      const visible = state.tasks.filter((t) => t.status !== "deleted");
      if (visible.length === 0) {
        ctx.ui.notify("No todos yet.", "info");
        return;
      }
      const pending = visible.filter((t) => t.status === "pending");
      const inProgress = visible.filter((t) => t.status === "in_progress");
      const completed = visible.filter((t) => t.status === "completed");

      const header = [];
      if (completed.length > 0) header.push(`${completed.length}/${visible.length} completed`);
      if (inProgress.length > 0) header.push(`${inProgress.length} in progress`);
      if (pending.length > 0) header.push(`${pending.length} pending`);

      const formatLine = (t: Task, glyph: string): string => {
        const form = t.status === "in_progress" && t.activeForm ? ` (${t.activeForm})` : "";
        const block = t.blockedBy?.length
          ? `    ⛓ ${t.blockedBy.map((id) => `#${id}`).join(",")}`
          : "";
        return `  ${glyph} #${t.id} ${t.subject}${form}${block}`;
      };

      const lines = [header.join(" · ")];
      if (pending.length > 0) {
        lines.push("── Pending ──");
        for (const t of pending) lines.push(formatLine(t, "○"));
      }
      if (inProgress.length > 0) {
        lines.push("── In Progress ──");
        for (const t of inProgress) lines.push(formatLine(t, "◐"));
      }
      if (completed.length > 0) {
        lines.push("── Completed ──");
        for (const t of completed) lines.push(formatLine(t, "✓"));
      }

      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  const branchHasTodoHistory = (ctx: any): boolean => {
    const branch = ctx.sessionManager.getBranch() ?? [];
    return branch.some(
      (e: any) => e?.message?.role === "toolResult" && e?.message?.toolName === TOOL_NAME,
    );
  };

  /** Resolve state for compact/tree: branch wins when it has todo results; else keep live/disk. */
  const resolveStateForRefresh = (ctx: any): TaskState => {
    const id = sid(ctx);
    if (branchHasTodoHistory(ctx)) {
      return replayFromBranch(ctx);
    }
    // No todo tool results on the branch yet. Do not clobber in-memory progress
    // with an empty replay (that was wiping tasks on compact).
    if (sessions.has(id)) return sessions.get(id)!;
    return restoreSessionState(id) ?? freshState();
  };

  const replayAndRefresh = (ctx: any): void => {
    let isForeground = false;
    try {
      const id = sid(ctx);
      sessions.set(id, resolveStateForRefresh(ctx));
      isForeground = id === activeRenderSession;
    } catch (e) {
      if (!/stale after session replacement/.test(String(e))) throw e;
    }
    if (isForeground) {
      todoOverlay?.resetCompletedDisplayState();
      todoOverlay?.update();
    }
  };

  pi.on("session_start", async (_event, ctx) => {
    let id: string;
    try {
      id = sid(ctx);
      const branch = ctx.sessionManager.getBranch() ?? [];
      if (branchHasTodoHistory(ctx)) {
        sessions.set(id, replayFromBranch(ctx));
      } else {
        // Restart recovery: disk fallback when message history has no todo results.
        const restored = restoreSessionState(id);
        const state = restored ?? freshState();
        sessions.set(id, state);
        replayCache.set(id, { len: branch.length, state });
      }
    } catch (e) {
      if (!/stale after session replacement/.test(String(e))) throw e;
      return;
    }
    if (!ctx.hasUI) return;
    if (todoOverlay === undefined) {
      todoOverlay = new TodoOverlay();
      activeRenderSession = id;
    }
    if (id !== activeRenderSession) return;
    todoOverlay.setUICtx(ctx.ui);
    todoOverlay.resetCompletedDisplayState();
    todoOverlay.update();
  });

  pi.on("session_compact", async (_event, ctx) => replayAndRefresh(ctx));
  pi.on("session_tree", async (_event, ctx) => replayAndRefresh(ctx));

  pi.on("session_shutdown", async (_event, ctx) => {
    let id = "";
    try {
      id = sid(ctx);
    } catch (e) {
      if (!/stale after session replacement/.test(String(e))) throw e;
    }
    sessions.delete(id);
    replayCache.delete(id);
    if (id === "" || id === activeRenderSession) {
      try {
        todoOverlay?.dispose();
      } finally {
        todoOverlay = undefined;
        activeRenderSession = "";
      }
    }
  });

  pi.on("tool_execution_end", async (event) => {
    if (event.toolName === TOOL_NAME && !event.isError) {
      todoOverlay?.update();
    }
  });

  pi.on("agent_start", async () => {
    todoOverlay?.hideCompletedTasksFromPreviousTurn();
  });
}

// ---------------------------------------------------------------------------
// Testing Hook (Parity with old test-reset exports)
// ---------------------------------------------------------------------------
export function __resetState(): void {
  sessions.clear();
  replayCache.clear();
  replayComputeCount = 0;
  if (activeRenderSession) {
    try {
      unlinkSync(persistPath(activeRenderSession));
    } catch {
      // File may not exist.
    }
  }
  activeRenderSession = "";
}

export function __replayComputeCount(): number {
  return replayComputeCount;
}
