import { render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { MissionControlView } from "./MissionControlView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("MissionControlView", () => {
  it("leads with public threat changes and preserves the decision queue", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      if (path === "/api/v1/operations/summary") return response({
        generated_at: "2026-10-08T10:00:00Z",
        metrics: { decision_queue: 0, critical_priorities: 0, watchlist_matches: 0, kev_records: 1, active_threats: 1, sources_reviewed: 20 },
        incidents: [{ id: "incident-binance", title: "Binance intrusion", organization: "Binance", event_type: "intrusion", state: "corroborated", priority: "high", score: 72, summary: "Unauthorized transfers disrupted operations.", last_updated: "2026-10-30T04:00:00Z", source_count: 5, independent_source_count: 3, confidence: "medium", recommended_action: "Inspect relevant telemetry." }],
        priorities: [], exposure: { configured: false, brands: [], assets: [], matches: [], disclaimer: "" },
      });
      if (path === "/api/v1/briefings/latest") return response({ headline: "Current assessment", what_happened: "Evidence summary", threat_level: "Elevated", source_articles: [] });
      if (path === "/api/v1/intelligence-delta") return response({
        available: true,
        headline: "New exploitation signal",
        what_happened: "A material change since the command edition.",
        generated_at: "2026-10-08T11:00:00Z",
      });
      if (path === "/api/v1/ledger/changes") return response({
        generated_at: "2026-10-08T10:00:00Z", total: 1,
        changes: [{ id: "global", record_id: "threat-global", entity_name: "CVE-2026-2", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "decision", previous: "monitor", current: "patch", summary: "Newest global ledger change.", source_ids: [] }],
      });
      return response({
        generated_at: "2026-10-08T10:00:00Z", run_change_count: 1,
        summary: { total_records: 1, active_records: 1, patch: 1, hunt: 0, qualified_hunts: 1, investigate: 0, monitor: 0 },
        records: [], changes: [{ id: "one", record_id: "threat-one", entity_name: "CVE-2026-1", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "exploitation", previous: "reported", current: "confirmed", summary: "Exploitation is now confirmed.", source_ids: [] }],
      });
    }));

    render(<MissionControlView />);

    expect(await screen.findByText("Newest global ledger change.")).toBeTruthy();
    expect(screen.getByText("Qualified hunts").previousSibling?.textContent).toBe("1");
    expect(screen.getByText("What changed today")).toBeTruthy();
    expect(screen.getByText("New exploitation signal")).toBeTruthy();
    expect(screen.getByText("A material change since the command edition.")).toBeTruthy();
    expect(screen.getByText("Decision queue")).toBeTruthy();
    expect(screen.getByText("Major incidents")).toBeTruthy();
    expect(screen.getByText("Binance intrusion")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open incident" }).getAttribute("href")).toBe("/incidents/incident-binance");
    expect(screen.getByRole("link", { name: "Open the full ledger" }).getAttribute("href")).toBe("/ledger");
  });
});
