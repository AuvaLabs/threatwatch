import type { Briefing, IncidentRecord, OperationalSummary } from "../types";
import { briefingSources, sourceHref, sourcePublisher, sourceTitle } from "./briefing";
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
  if (summary.incidents?.length) {
    lines.push("", "## Major incidents");
    summary.incidents.forEach((incident, index) => {
      lines.push(`${index + 1}. [${incident.title}](/incidents/${incident.id})`);
      lines.push(`   ${incident.summary}`);
      lines.push(`   Action: ${incident.recommended_action}`);
    });
  }
  const sources = briefingSources(briefing);
  if (sources.length) {
    lines.push("", "## Sources");
    sources.forEach((source) => {
      const href = sourceHref(source.link);
      const title = sourceTitle(source);
      lines.push(`[${source.index}] ${href ? `[${title}](${href})` : title} - ${sourcePublisher(source)}`);
    });
  }
  lines.push("", "## Validation note", summary.exposure.disclaimer);
  return lines.join("\n");
}

export function incidentMarkdown(record: IncidentRecord): string {
  const lines = [
    `# ${record.title}`, "", record.summary, "",
    `Status: ${record.state} / ${record.priority} / score ${record.score}`, "",
    "## What we know",
  ];
  record.claims.filter((claim) => ["confirmed", "reported"].includes(claim.state)).forEach((claim) => {
    lines.push(`- [${claim.state}] ${claim.statement} (sources: ${claim.source_ids.join(", ")})`);
  });
  lines.push("", "## How it may have happened");
  record.claims.filter((claim) => ["assessed", "disputed"].includes(claim.state)).forEach((claim) => {
    lines.push(`- [${claim.state}, ${claim.confidence}] ${claim.statement} (sources: ${claim.source_ids.join(", ")})`);
  });
  lines.push("", "## What defenders should inspect", record.recommended_action, "", "## Open questions");
  record.open_questions?.forEach((question) => lines.push(`- ${question}`));
  lines.push("", "## Sources");
  record.sources.forEach((source) => lines.push(`- [${source.title}](${sourceHref(source.url) || "#"}) - ${source.publisher}`));
  return lines.join("\n");
}

export function downloadText(filename: string, body: string, mime = "text/markdown;charset=utf-8"): void {
  const href = URL.createObjectURL(new Blob([body], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(href);
}
