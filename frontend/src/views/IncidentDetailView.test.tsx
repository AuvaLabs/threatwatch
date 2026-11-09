import { render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { IncidentDetailView } from "./IncidentDetailView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("IncidentDetailView", () => {
  it("separates known, assessed, and unknown evidence with source links", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({
      id: "incident-abc123", organization: "Binance", event_type: "intrusion",
      title: "Binance intrusion", summary: "Unauthorized transfers disrupted operations.",
      state: "corroborated", priority: "high", score: 74, confidence: "medium", version: 2,
      first_seen: "2026-10-29T08:00:00Z", last_updated: "2026-10-30T04:00:00Z",
      last_changed: "2026-10-30T04:00:00Z", source_count: 3, independent_source_count: 2,
      recommended_action: "Inspect relevant telemetry.", sectors: ["Finance"], affected_assets: [],
      impact: ["Withdrawals were temporarily halted"], open_questions: ["The initial access path is not confirmed"],
      techniques: [{ id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }], observables: [],
      claims: [
        { subject: "event", statement: "Multiple sources report an intrusion.", state: "reported", confidence: "high", source_ids: ["article-1", "article-2"], evidence: { source_count: 2, independent_source_count: 2, authoritative_source_count: 0 } },
        { subject: "intrusion_path", statement: "Signing credentials may have been compromised.", state: "assessed", confidence: "medium", source_ids: ["article-1"] },
      ],
      evidence_assessment: {
        grade: "corroborated", citation_coverage_pct: 100, claim_count: 2,
        cited_claim_count: 2, independent_source_count: 2, authoritative_source_count: 0,
        confirmed_claim_count: 0, reported_claim_count: 1, assessed_claim_count: 1,
        disputed_claim_count: 0, basis: ["2 independent source families", "All claims are linked to retained evidence"],
      },
      sources: [
        { article_id: "article-1", title: "Report one", publisher: "Reuters", published: "2026-10-29T08:00:00Z", url: "https://example.test/one", source_family: "publisher:reuters" },
        { article_id: "article-2", title: "Report two", publisher: "BBC", published: "2026-10-29T09:00:00Z", url: "https://example.test/two", source_family: "publisher:bbc" },
      ],
      changes: [],
    })));

    render(<IncidentDetailView id="incident-abc123" />);

    expect(await screen.findByText("What we know")).toBeTruthy();
    expect(screen.getByText("How it may have happened")).toBeTruthy();
    expect(screen.getByText("What remains unknown")).toBeTruthy();
    expect(screen.getByText("Signing credentials may have been compromised.")).toBeTruthy();
    expect(screen.getByText("Evidence assessment")).toBeTruthy();
    expect(screen.getByText("100% citation coverage")).toBeTruthy();
    expect(screen.getByText("2 independent sources", { exact: false })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Report one" }).getAttribute("href")).toBe("https://example.test/one");
    expect(fetch).toHaveBeenCalledWith("/api/v2/incidents/incident-abc123", expect.any(Object));
  });
});
