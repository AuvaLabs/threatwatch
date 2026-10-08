import type {
  Investigation,
  HuntRecord,
  OperationalActionType,
  OperationalPriority,
  OperationalUrgency,
} from "../types";

const actionLabels: Record<OperationalActionType, string> = {
  patch: "Patch or isolate",
  hunt: "Begin threat hunt",
  investigate: "Validate relevance",
  monitor: "Monitor evidence",
};

const urgencyLabels: Record<OperationalUrgency, string> = {
  critical: "Immediate",
  high: "High priority",
  medium: "Review",
};

export function actionLabel(action: OperationalActionType): string {
  return actionLabels[action];
}

export function urgencyLabel(urgency: OperationalUrgency): string {
  return urgencyLabels[urgency];
}

export function investigationFromPriority(priority: OperationalPriority, now = new Date().toISOString()): Investigation {
  return {
    id: `investigation-${priority.id}`,
    sourceId: priority.id,
    title: priority.title,
    status: "open",
    urgency: priority.urgency,
    actionType: priority.action_type,
    createdAt: now,
    updatedAt: now,
    notes: priority.recommended_action,
    cves: [...priority.evidence.cves],
  };
}

export function huntPack(hunt: HuntRecord): string {
  return hunt.markdown;
}
