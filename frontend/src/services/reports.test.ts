import { describe, expect, it, vi } from "vitest";
import type { IncidentRecord, OperationalSummary } from "../types";
import { downloadText, incidentMarkdown, operationalReport } from "./reports";

const summary: OperationalSummary = {
  generated_at: "2026-10-08T00:00:00.000Z",
  metrics: { decision_queue: 2, critical_priorities: 1, major_incidents: 1, watchlist_matches: 1, kev_records: 1, active_threats: 2, sources_reviewed: 10 },
  incidents: [{ id: "incident-acme", title: "Acme intrusion", organization: "Acme", event_type: "intrusion", state: "corroborated", priority: "high", score: 72, summary: "Corroborated intrusion reporting.", last_updated: "2026-10-08T00:00:00Z", source_count: 3, independent_source_count: 2, confidence: "medium", recommended_action: "Inspect telemetry." }],
  priorities: [{
    id: "one", title: "Exploited edge device", summary: "Evidence", score: 90, urgency: "critical", action_type: "patch",
    recommended_action: "Patch or isolate.", reasons: ["Known exploitation"], watchlist_matches: ["Device"],
    evidence: { cves: ["CVE-2026-1"], techniques: [], iocs: [], ioc_count: 0 },
  }],
  exposure: { configured: true, brands: [], assets: ["Device"], matches: [], disclaimer: "Validate relevance." },
};

describe("operational reports", () => {
  it("renders metrics, priorities, and briefing evidence", () => {
    const report = operationalReport(summary, {
      headline: "Active exploitation",
      what_happened: "Edge devices are targeted.",
      headline_source: 1,
      source_articles: [{ index: 1, title: "CISA advisory", link: "https://cisa.gov/advisory", source_name: "CISA" }],
    });
    expect(report).toContain("Active exploitation");
    expect(report).toContain("1 immediate decisions");
    expect(report).toContain("Patch or isolate.");
    expect(report).toContain("## Major incidents");
    expect(report).toContain("[Acme intrusion](/incidents/incident-acme)");
    expect(report).toContain("## Sources");
    expect(report).toContain("[1] [CISA advisory](https://cisa.gov/advisory) - CISA");
    expect(report).toContain("Validate relevance.");
  });

  it("uses a truthful fallback when narrative enrichment is absent", () => {
    expect(operationalReport({ ...summary, priorities: [{ ...summary.priorities[0], reasons: [] }] }, null)).toContain("Narrative assessment unavailable");
  });

  it("includes the deterministic evidence assessment in incident exports", () => {
    const incident = {
      ...summary.incidents![0], version: 1, first_seen: "2026-10-07T00:00:00Z",
      last_changed: "2026-10-08T00:00:00Z", open_questions: [], sectors: [],
      claims: [{ subject: "event", statement: "Sources report an intrusion.", state: "reported", confidence: "medium", source_ids: ["one"] }],
      sources: [{ article_id: "one", title: "Incident report", publisher: "CERT", url: "https://cert.example/report", source_family: "publisher:cert" }],
      impact: [], techniques: [], observables: [], affected_assets: [], changes: [],
      evidence_assessment: {
        grade: "corroborated", citation_coverage_pct: 100, claim_count: 1,
        cited_claim_count: 1, independent_source_count: 2, authoritative_source_count: 0,
        confirmed_claim_count: 0, reported_claim_count: 1, assessed_claim_count: 0,
        disputed_claim_count: 0, basis: ["All claims are linked to retained evidence"],
      },
    } as IncidentRecord;

    const report = incidentMarkdown(incident);

    expect(report).toContain("## Evidence assessment");
    expect(report).toContain("Citation coverage: 100%");
    expect(report).toContain("Independent sources: 2");
  });

  it("downloads markdown through a temporary object URL", () => {
    const createObjectURL = vi.fn(() => "blob:report");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    downloadText("report.md", "body");
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:report");
  });
});
