import type {
  Investigation,
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

export function huntPack(priority: OperationalPriority): string {
  const sections = [
    `# ThreatWatch Hunt Pack: ${priority.title}`,
    `Urgency: ${urgencyLabel(priority.urgency)}`,
    `Recommended action: ${priority.recommended_action}`,
    "",
    "## Evidence",
    ...priority.reasons.map((reason) => `- ${reason}`),
  ];
  if (priority.evidence.cves.length) sections.push("", "## CVEs", ...priority.evidence.cves.map((value) => `- ${value}`));
  if (priority.evidence.techniques.length) sections.push("", "## ATT&CK techniques", ...priority.evidence.techniques.map((value) => `- ${value}`));
  if (priority.evidence.iocs.length) sections.push("", "## Indicators", ...priority.evidence.iocs.map((value) => `- ${value}`));
  sections.push("", "Validate all indicators and generated hunt logic before production use.");
  return sections.join("\n");
}
