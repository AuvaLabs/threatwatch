import type { AnalystWorkspace, Investigation, InvestigationStatus } from "../types";

const STORAGE_KEY = "threatwatch-workspace-v1";
const statuses = new Set<InvestigationStatus>(["open", "monitoring", "closed"]);
const urgencies = new Set(["critical", "high", "medium"]);
const actionTypes = new Set(["patch", "hunt", "investigate", "monitor"]);
const emptyWorkspace = (): AnalystWorkspace => ({ investigations: [] });

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
    return { investigations: parsed.investigations.filter(validInvestigation) };
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
  return persist({ investigations: [investigation, ...workspace.investigations] });
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
  if (updated) persist({ investigations });
  return updated;
}

export function workspaceDownload(workspace: AnalystWorkspace): void {
  const body = JSON.stringify(workspace, null, 2);
  const href = URL.createObjectURL(new Blob([body], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = `threatwatch-investigations-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(href);
}
