/**
 * pi-xtodo — Simplified single-file todo list extension for Pi.
 * Registers the `todo` tool, `/todos` slash command, and persistent TodoOverlay.
 */

import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionUIContext, Theme } from "@earendil-works/pi-coding-agent";
import { Text, type TUI, truncateToWidth } from "@earendil-works/pi-tui";
import { type Static, Type } from "@sinclair/typebox";

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
export const TodoParamsSchema = Type.Object({
  action: Type.Union([
    Type.Literal("create"),
    Type.Literal("update"),
    Type.Literal("list"),
    Type.Literal("get"),
    Type.Literal("delete"),
    Type.Literal("clear"),
  ]),
  subject: Type.Optional(Type.String({ description: "Task subject line (required for create)" })),
  description: Type.Optional(Type.String({ description: "Long-form task description" })),
  activeForm: Type.Optional(
    Type.String({
      description: "Present-continuous spinner label shown while status is in_progress",
    }),
  ),
  status: Type.Optional(
    Type.Union(
      [
        Type.Literal("pending"),
        Type.Literal("in_progress"),
        Type.Literal("completed"),
        Type.Literal("deleted"),
      ],
      {
        description: "Target status (update) or list filter (list)",
      },
    ),
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
function persistPath(id: string): string {
  return join(XTODO_DIR, `${id}.json`);
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
  const adj = new Map(
    tasks.map((t) => [
      t.id,
      t.id === taskId ? [...(t.blockedBy ?? []), ...newBlockedBy] : [...(t.blockedBy ?? [])],
    ]),
  );
  const dfs = (node: number, depth: number): boolean =>
    depth > 5 || (adj.get(node) ?? []).some((n) => dfs(n, depth + 1));
  return dfs(taskId, 0);
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
      const blocked = params.blockedBy ?? [];
      for (const dep of blocked) {
        const depTask = tasks.find((t) => t.id === dep);
        if (!depTask) return err(`blockedBy: #${dep} not found`);
        if (depTask.status === "deleted") return err(`blockedBy: #${dep} is deleted`);
      }
      const newTask: Task = {
        id: nextId++,
        subject: params.subject,
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
      const idx = tasks.findIndex((t) => t.id === params.id);
      if (idx === -1) return err(`#${params.id} not found`);
      const cur = tasks[idx];

      const hasMutation =
        params.subject !== undefined ||
        params.description !== undefined ||
        params.activeForm !== undefined ||
        params.status !== undefined ||
        params.owner !== undefined ||
        params.metadata !== undefined ||
        params.addBlockedBy?.length ||
        params.removeBlockedBy?.length;
      if (!hasMutation) return err("update requires at least one mutable field");

      let status = cur.status;
      if (params.status !== undefined) {
        if (status !== params.status && !VALID_TRANSITIONS[status].includes(params.status)) {
          return err(`illegal transition ${status} → ${params.status}`);
        }
        status = params.status;
      }

      let blocked = cur.blockedBy ? [...cur.blockedBy] : [];
      if (params.removeBlockedBy?.length) {
        const rm = new Set(params.removeBlockedBy);
        blocked = blocked.filter((d) => !rm.has(d));
      }
      if (params.addBlockedBy?.length) {
        for (const dep of params.addBlockedBy) {
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
        ...(params.subject !== undefined && { subject: params.subject }),
        ...(params.description !== undefined && { description: params.description }),
        ...(params.activeForm !== undefined && { activeForm: params.activeForm }),
        ...(params.owner !== undefined && { owner: params.owner }),
        blockedBy: blocked.length ? blocked : undefined,
        metadata,
      };
      tasks[idx] = updated;
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
      const task = tasks.find((t) => t.id === params.id);
      if (!task) return err(`#${params.id} not found`);

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
      const idx = tasks.findIndex((t) => t.id === params.id);
      if (idx === -1) return err(`#${params.id} not found`);
      const cur = tasks[idx];
      if (cur.status === "deleted") return err(`#${cur.id} is already deleted`);
      tasks[idx] = { ...cur, status: "deleted" };
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

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const action = params.action as TaskAction;
      const id = sid(ctx);
      const state = getSessionState(id);
      const result = applyMutation(state, action, params);
      sessions.set(id, result.state);
      saveSessionState(id, result.state);

      const details: TaskDetails = {
        action,
        params: params as Record<string, unknown>,
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
        const subj = state.tasks.find((t) => t.id === args.id)?.subject;
        text += ` ${theme.fg("accent", subj ?? `#${args.id}`)}`;
      } else if (args.action === "list" && args.status) {
        text += ` ${theme.fg("muted", args.status === "in_progress" ? "in progress" : args.status)}`;
      }
      return new Text(text, 0, 0);
    },

    renderResult(result, _opts, theme, _context) {
      const details = result.details as TaskDetails | undefined;
      let status: TaskStatus | undefined;
      if (details) {
        const p = details.params as any;
        if (details.action === "create") status = details.tasks[details.tasks.length - 1]?.status;
        else if (details.action === "update")
          status = p.status ?? details.tasks.find((t) => t.id === p.id)?.status;
        else if (details.action === "delete")
          status = details.tasks.find((t) => t.id === p.id)?.status;
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

  const replayAndRefresh = (ctx: any): void => {
    let isForeground = false;
    try {
      const id = sid(ctx);
      sessions.set(id, replayFromBranch(ctx));
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
      const branch = ctx.sessionManager.getBranch();
      const replayed = replayFromBranch(ctx);
      const hasTodoHistory = branch.some(
        (e: any) => e?.message?.role === "toolResult" && e?.message?.toolName === TOOL_NAME,
      );
      // Fallback to disk only when the message history hasn't been replayed yet,
      // so a restart can recover in-progress tasks.
      if (!hasTodoHistory) {
        const restored = restoreSessionState(id);
        if (restored) {
          sessions.set(id, restored);
          replayCache.set(id, { len: branch.length, state: restored });
        } else {
          sessions.set(id, replayed);
        }
      } else {
        sessions.set(id, replayed);
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
