import type { Briefing, OperationalSummary } from "../types";
import { formattedDate } from "../utils/format";

export function operationalReport(summary: OperationalSummary, briefing: Briefing | null): string {
  const lines = [
    "# ThreatWatch Operational Report",
    `Generated: ${formattedDate(summary.generated_at)}`,
    "",
    "## Executive assessment",
    briefing?.headline || "Narrative assessment unavailable",
    briefing?.what_happened || "Use the evidence-backed priorities below while narrative enrichment is unavailable.",
    "",
    "## Operating picture",
    `- ${summary.metrics.critical_priorities} immediate decisions`,
    `- ${summary.metrics.watchlist_matches} watchlist matches requiring validation`,
    `- ${summary.metrics.kev_records} known exploited vulnerability records`,
    `- ${summary.metrics.active_threats} correlated threats`,
    "",
    "## Priority actions",
  ];
  summary.priorities.forEach((priority, index) => {
    lines.push(`${index + 1}. [${priority.urgency.toUpperCase()}] ${priority.title}`);
    lines.push(`   ${priority.recommended_action}`);
    lines.push(`   Basis: ${priority.reasons.join("; ") || "Operational scoring threshold"}`);
  });
  lines.push("", "## Validation note", summary.exposure.disclaimer);
  return lines.join("\n");
}

export function downloadText(filename: string, body: string): void {
  const href = URL.createObjectURL(new Blob([body], { type: "text/markdown;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(href);
}
