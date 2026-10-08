import { render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { HuntsView } from "./HuntsView";

function hunt(id: string, status: "qualified" | "lead") {
  return {
    id,
    entity_type: "cve",
    entity_name: "CVE-2026-1000",
    title: status === "qualified" ? "Validated activity" : "Unconfirmed activity",
    status,
    readiness_score: status === "qualified" ? 85 : 45,
    confidence: status === "qualified" ? "high" : "developing",
    summary: "Correlated reporting",
    hypothesis: "Affected systems may show reported behavior.",
    why_qualified: ["Two independent publishers"],
    report_count: 2,
    source_count: 2,
    sources: [], observables: [], techniques: [], telemetry: [], queries: [],
    false_positives: [], triage_steps: [], limitations: [],
    markdown: "# Hunt package",
  };
}

describe("HuntsView", () => {
  it("separates qualified packages from developing leads", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      generated_at: "2026-10-08T00:00:00Z",
      qualified_count: 1,
      lead_count: 1,
      hunts: [hunt("hunt-qualified", "qualified"), hunt("hunt-lead", "lead")],
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    render(<HuntsView />);

    expect(await screen.findByText("Validated activity")).toBeTruthy();
    expect(screen.getByText("Unconfirmed activity")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy hunt package" }).hasAttribute("disabled")).toBe(false);
    expect(screen.getByRole("button", { name: "Awaiting evidence" }).hasAttribute("disabled")).toBe(true);
    expect(fetch).toHaveBeenCalledWith("/api/v1/hunts", expect.any(Object));
  });
});
