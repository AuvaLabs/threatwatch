import { render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { ThreatsView } from "./ThreatsView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("ThreatsView", () => {
  it("uses the standard investigation action for breach records", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      if (path === "/api/v1/incidents/v2") return response({
        schema_version: 1,
        summary: { total_records: 1, high_priority: 1, developing: 0 },
        run_change_count: 0,
        total: 1,
        changes: [],
        records: [{
          id: "incident-binance", title: "Binance intrusion", organization: "Binance",
          event_type: "intrusion", state: "corroborated", priority: "high", score: 79,
          summary: "Unauthorized transfers disrupted operations.", last_updated: "2026-10-30T04:00:00Z",
          source_count: 5, independent_source_count: 3, confidence: "high",
          recommended_action: "Inspect relevant telemetry.",
        }],
      });
      return response({ clusters: [] });
    }));

    render(<ThreatsView />);

    const action = await screen.findByRole("link", { name: "Open investigation" });
    expect(action.getAttribute("href")).toBe("/incidents/incident-binance");
    expect(action.classList.contains("button")).toBe(true);
    expect(action.classList.contains("primary")).toBe(true);
  });
});
