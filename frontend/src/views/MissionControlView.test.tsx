import { render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { MissionControlView } from "./MissionControlView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("MissionControlView", () => {
  it("leads with public threat changes and preserves the decision queue", async () => {
    const incidents = Array.from({ length: 4 }, (_, index) => ({ id: `incident-${index}`, title: `Incident ${index}`, organization: `Organization ${index}`, event_type: "intrusion", state: "corroborated", priority: "high", score: 72 - index, summary: "Unauthorized activity disrupted operations.", last_updated: "2026-10-30T04:00:00Z", source_count: 5, independent_source_count: 3, confidence: "medium", recommended_action: "Inspect relevant telemetry." }));
    const priorities = Array.from({ length: 6 }, (_, index) => ({ id: `priority-${index}`, title: `Priority ${index}`, summary: "A concise operational priority.", score: 70 - index, urgency: "high", action_type: "investigate", recommended_action: "Validate the evidence.", reasons: ["Corroborated reporting"], watchlist_matches: [], evidence: { cves: [], techniques: [], iocs: [], ioc_count: 0 } }));
    const changes = Array.from({ length: 4 }, (_, index) => ({ id: `change-${index}`, record_id: `threat-${index}`, entity_name: `CVE-2026-${index}`, changed_at: `2026-10-08T0${index}:00:00Z`, kind: "state_changed", field: "decision", previous: "monitor", current: "investigate", summary: `Ledger change ${index}.`, source_ids: [] }));
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      if (path === "/api/v1/operations/summary") return response({
        generated_at: "2026-10-08T10:00:00Z",
        metrics: { decision_queue: 6, critical_priorities: 0, watchlist_matches: 0, kev_records: 1, active_threats: 1, sources_reviewed: 20 },
        incidents,
        priorities, exposure: { configured: false, brands: [], assets: [], matches: [], disclaimer: "" },
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
        changes,
      });
      return response({
        generated_at: "2026-10-08T10:00:00Z", run_change_count: 1,
        summary: { total_records: 1, active_records: 1, patch: 1, hunt: 0, qualified_hunts: 1, investigate: 0, monitor: 0 },
        records: [], changes: [{ id: "one", record_id: "threat-one", entity_name: "CVE-2026-1", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "exploitation", previous: "reported", current: "confirmed", summary: "Exploitation is now confirmed.", source_ids: [] }],
      });
    }));

    const { container } = render(<MissionControlView />);

    expect(await screen.findByText("Ledger change 0.")).toBeTruthy();
    expect(screen.getByText("Qualified hunts").previousSibling?.textContent).toBe("1");
    expect(screen.getByText("What changed today")).toBeTruthy();
    expect(screen.getByText("New exploitation signal")).toBeTruthy();
    expect(screen.getByText("A material change since the command edition.")).toBeTruthy();
    expect(screen.getByText("Decision queue")).toBeTruthy();
    expect(screen.getByText("Major incidents")).toBeTruthy();
    expect(screen.getByText("Incident 0")).toBeTruthy();
    const [incidentAction] = screen.getAllByRole("link", { name: "Open investigation" });
    expect(incidentAction.getAttribute("href")).toBe("/incidents/incident-0");
    expect(incidentAction.classList.contains("button")).toBe(true);
    expect(incidentAction.classList.contains("primary")).toBe(true);
    expect(screen.getByRole("link", { name: "Open the full ledger" }).getAttribute("href")).toBe("/ledger");
    expect(screen.getByRole("link", { name: "View all incidents" }).getAttribute("href")).toBe("/incidents");
    expect(container.querySelectorAll(".incident-row")).toHaveLength(3);
    expect(container.querySelectorAll(".priority-entry")).toHaveLength(5);
    expect(container.querySelectorAll(".today-changes li")).toHaveLength(3);
    const incidentsSection = container.querySelector(".major-incidents") as HTMLElement;
    const commandBrief = container.querySelector(".command-brief") as HTMLElement;
    expect(incidentsSection.compareDocumentPosition(commandBrief) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});
