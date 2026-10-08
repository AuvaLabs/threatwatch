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
        priorities: [], exposure: { configured: false, brands: [], assets: [], matches: [], disclaimer: "" },
      });
      if (path === "/api/v1/briefings/latest") return response({ headline: "Current assessment", what_happened: "Evidence summary", threat_level: "Elevated", source_articles: [] });
      if (path === "/api/v1/ledger/changes") return response({
        generated_at: "2026-10-08T10:00:00Z", total: 1,
        changes: [{ id: "global", record_id: "threat-global", entity_name: "CVE-2026-2", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "decision", previous: "monitor", current: "patch", summary: "Newest global ledger change.", source_ids: [] }],
      });
      return response({
        generated_at: "2026-10-08T10:00:00Z", run_change_count: 1,
        summary: { total_records: 1, active_records: 1, patch: 1, hunt: 0, investigate: 0, monitor: 0 },
        records: [], changes: [{ id: "one", record_id: "threat-one", entity_name: "CVE-2026-1", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "exploitation", previous: "reported", current: "confirmed", summary: "Exploitation is now confirmed.", source_ids: [] }],
      });
    }));

    render(<MissionControlView />);

    expect(await screen.findByText("Newest global ledger change.")).toBeTruthy();
    expect(screen.getByText("What changed today")).toBeTruthy();
    expect(screen.getByText("Decision queue")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open the full ledger" }).getAttribute("href")).toBe("/ledger");
  });
});
