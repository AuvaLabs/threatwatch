import { describe, expect, it, vi } from "vitest";
import type { OperationalSummary } from "../types";
import { downloadText, operationalReport } from "./reports";

const summary: OperationalSummary = {
  generated_at: "2026-10-08T00:00:00.000Z",
  metrics: { decision_queue: 1, critical_priorities: 1, watchlist_matches: 1, kev_records: 1, active_threats: 2, sources_reviewed: 10 },
  priorities: [{
    id: "one", title: "Exploited edge device", summary: "Evidence", score: 90, urgency: "critical", action_type: "patch",
    recommended_action: "Patch or isolate.", reasons: ["Known exploitation"], watchlist_matches: ["Device"],
    evidence: { cves: ["CVE-2026-1"], techniques: [], iocs: [], ioc_count: 0 },
  }],
  exposure: { configured: true, brands: [], assets: ["Device"], matches: [], disclaimer: "Validate relevance." },
};

describe("operational reports", () => {
  it("renders metrics, priorities, and briefing evidence", () => {
    const report = operationalReport(summary, { headline: "Active exploitation", what_happened: "Edge devices are targeted." });
    expect(report).toContain("Active exploitation");
    expect(report).toContain("1 immediate decisions");
    expect(report).toContain("Patch or isolate.");
    expect(report).toContain("Validate relevance.");
  });

  it("uses a truthful fallback when narrative enrichment is absent", () => {
    expect(operationalReport({ ...summary, priorities: [{ ...summary.priorities[0], reasons: [] }] }, null)).toContain("Narrative assessment unavailable");
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
