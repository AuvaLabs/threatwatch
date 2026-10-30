import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { ThreatsView } from "./ThreatsView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("ThreatsView", () => {
  it("uses the standard investigation action for breach records", async () => {
    const records = Array.from({ length: 13 }, (_, index) => ({
      id: `incident-${index}`, title: `Incident ${index}`, organization: `Organization ${index}`,
      event_type: index === 12 ? "ransomware" : "intrusion", state: "corroborated", priority: "high", score: 79,
      summary: "Unauthorized transfers disrupted operations.", last_updated: "2026-10-30T04:00:00Z",
      source_count: 5, independent_source_count: 3, confidence: "high",
      recommended_action: "Inspect relevant telemetry.",
    }));
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      if (path === "/api/v1/incidents/v2") return response({
        schema_version: 1,
        summary: { total_records: 13, high_priority: 13, developing: 0 },
        run_change_count: 0,
        total: 13,
        changes: [],
        records,
      });
      return response({ clusters: [] });
    }));

    const { container } = render(<ThreatsView />);

    expect(screen.getByRole("heading", { name: "Incidents", level: 1 })).toBeTruthy();
    expect(await screen.findByText("Incident 0")).toBeTruthy();
    const action = screen.getAllByRole("link", { name: "Open investigation" })[0];
    expect(action.getAttribute("href")).toBe("/incidents/incident-0");
    expect(action.classList.contains("button")).toBe(true);
    expect(action.classList.contains("primary")).toBe(true);
    expect(container.querySelectorAll(".incident-register-row")).toHaveLength(12);
    fireEvent.click(screen.getByRole("button", { name: "Show 1 more incident" }));
    expect(container.querySelectorAll(".incident-register-row")).toHaveLength(13);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
