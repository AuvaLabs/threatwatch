import type { AnalystWorkspace, FollowedThreat, FollowedThreatKind, Investigation, InvestigationStatus } from "../types";

const STORAGE_KEY = "threatwatch-workspace-v1";
const statuses = new Set<InvestigationStatus>(["open", "monitoring", "closed"]);
const urgencies = new Set(["critical", "high", "medium"]);
const actionTypes = new Set(["patch", "hunt", "investigate", "monitor"]);
const followKinds = new Set<FollowedThreatKind>(["ledger", "incident"]);
const emptyWorkspace = (): AnalystWorkspace => ({ investigations: [], follows: [] });

function validInvestigation(value: unknown): value is Investigation {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<Investigation>;
  return Boolean(
    typeof item.id === "string"
    && typeof item.sourceId === "string"
    && typeof item.title === "string"
    && item.status && statuses.has(item.status)
    && typeof item.urgency === "string" && urgencies.has(item.urgency)
    && typeof item.actionType === "string" && actionTypes.has(item.actionType)
    && typeof item.createdAt === "string"
    && typeof item.updatedAt === "string"
    && typeof item.notes === "string"
    && Array.isArray(item.cves) && item.cves.every((cve) => typeof cve === "string"),
  );
}

export function loadWorkspace(): AnalystWorkspace {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return emptyWorkspace();
    const parsed = JSON.parse(raw) as Partial<AnalystWorkspace>;
    if (!Array.isArray(parsed.investigations)) return emptyWorkspace();
    const follows = Array.isArray(parsed.follows) ? parsed.follows.filter(validFollow) : [];
    return { investigations: parsed.investigations.filter(validInvestigation), follows };
  } catch {
    return emptyWorkspace();
  }
}

function persist(workspace: AnalystWorkspace): AnalystWorkspace {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(workspace));
    return workspace;
  } catch {
    throw new Error("Browser storage is unavailable.");
  }
}

export function saveInvestigation(investigation: Investigation): AnalystWorkspace {
  const workspace = loadWorkspace();
  const exists = workspace.investigations.some(
    (item) => item.id === investigation.id || item.sourceId === investigation.sourceId,
  );
  if (exists) return workspace;
  return persist({ ...workspace, investigations: [investigation, ...workspace.investigations] });
}

function validFollow(value: unknown): value is FollowedThreat {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<FollowedThreat>;
  return Boolean(
    typeof item.id === "string" && item.id.length > 0
    && item.kind && followKinds.has(item.kind)
    && typeof item.title === "string"
    && typeof item.detail === "string"
    && typeof item.href === "string" && item.href.startsWith("/") && !item.href.startsWith("//")
    && typeof item.feedHref === "string" && item.feedHref.startsWith("/api/")
    && typeof item.followedAt === "string"
    && typeof item.lastReviewedAt === "string",
  );
}

export function followThreat(follow: FollowedThreat): AnalystWorkspace {
  if (!validFollow(follow)) throw new Error("The followed threat is invalid.");
  const workspace = loadWorkspace();
  const exists = workspace.follows.some((item) => item.kind === follow.kind && item.id === follow.id);
  if (exists) return workspace;
  return persist({ ...workspace, follows: [follow, ...workspace.follows] });
}

export function unfollowThreat(kind: FollowedThreatKind, id: string): AnalystWorkspace {
  const workspace = loadWorkspace();
  return persist({
    ...workspace,
    follows: workspace.follows.filter((item) => item.kind !== kind || item.id !== id),
  });
}

export function markFollowsReviewed(now = new Date().toISOString()): AnalystWorkspace {
  const workspace = loadWorkspace();
  return persist({
    ...workspace,
    follows: workspace.follows.map((item) => ({ ...item, lastReviewedAt: now })),
  });
}

export function importWorkspace(raw: string): AnalystWorkspace {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("The workspace file is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as Partial<AnalystWorkspace>).investigations)) {
    throw new Error("The workspace file does not contain valid investigations.");
  }
  const workspace = parsed as Partial<AnalystWorkspace>;
  const investigations = workspace.investigations || [];
  if (investigations.some((item) => !validInvestigation(item))) {
    throw new Error("The workspace file does not contain valid investigations.");
  }
  const follows = workspace.follows || [];
  if (!Array.isArray(follows) || follows.some((item) => !validFollow(item))) {
    throw new Error("The workspace file does not contain valid followed threats.");
  }
  return persist({ investigations, follows });
}

export function updateInvestigation(
  id: string,
  changes: Pick<Investigation, "status" | "notes">,
  now = new Date().toISOString(),
): Investigation | null {
  const workspace = loadWorkspace();
  let updated: Investigation | null = null;
  const investigations = workspace.investigations.map((item) => {
    if (item.id !== id) return item;
    updated = { ...item, status: changes.status, notes: changes.notes, updatedAt: now };
    return updated;
  });
  if (updated) persist({ ...workspace, investigations });
  return updated;
}

export function workspaceDownload(workspace: AnalystWorkspace): void {
  const body = JSON.stringify(workspace, null, 2);
  const href = URL.createObjectURL(new Blob([body], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = `threatwatch-workspace-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(href);
}
