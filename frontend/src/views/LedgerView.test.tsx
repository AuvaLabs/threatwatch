import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { LedgerRecordView } from "./LedgerRecordView";
import { LedgerView } from "./LedgerView";

const record = {
  id: "threat-abc123",
  entity_type: "cve",
  entity_name: "CVE-2026-1000",
  title: "CVE-2026-1000",
  summary: "Independent reporting describes active exploitation.",
  decision: { action: "patch", urgency: "critical", rationale: "CISA KEV confirms active exploitation." },
  state: { activity: "active", exploitation: "confirmed", evidence: "corroborated", hunt: "qualified", remediation: "action_available" },
  version: 2,
  first_seen: "2026-10-08T08:00:00Z",
  last_updated: "2026-10-08T10:00:00Z",
  last_changed: "2026-10-08T10:00:00Z",
  report_count: 2,
  source_count: 2,
  sources: [{ article_id: "a", title: "Technical report", publisher: "Research Lab", published: "2026-10-08T08:00:00Z", url: "https://research.example/report", source_type: "reporting" }],
  vulnerability: { cve: "CVE-2026-1000", kev: true, max_cvss: 9.8, max_epss: 0.72 },
  affected_products: ["Acme Gateway"],
  remediation: { required_action: "Apply the vendor update.", due_date: "2026-10-15", affected_versions: [], fixed_versions: [] },
  techniques: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  hunt_id: "hunt-abc123",
  readiness_score: 85,
  observable_count: 1,
  evidence: [{ key: "sources", label: "Independent reporting", status: "corroborated", detail: "2 independent publishers." }],
  open_questions: [],
  changes: [{ id: "change-one", record_id: "threat-abc123", entity_name: "CVE-2026-1000", changed_at: "2026-10-08T10:00:00Z", kind: "state_changed", field: "exploitation", previous: "reported", current: "confirmed", summary: "CVE-2026-1000 gained confirmed exploitation evidence.", source_ids: ["a"] }],
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("LedgerView", () => {
  it("presents state changes and living records with stable links", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      generated_at: "2026-10-08T10:00:00Z",
      run_change_count: 1,
      summary: { total_records: 1, active_records: 1, patch: 1, hunt: 0, qualified_hunts: 1, investigate: 0, monitor: 0 },
      total: 1, offset: 0, limit: 100, has_more: false, filters: {},
      changes: record.changes,
      records: [record],
    })));

    render(<LedgerView />);

    expect(await screen.findByText("CVE-2026-1000 gained confirmed exploitation evidence.")).toBeTruthy();
    expect(screen.getByText("Independent reporting describes active exploitation.")).toBeTruthy();
    expect(screen.getByText("Qualified hunts").previousSibling?.textContent).toBe("1");
    expect(screen.getByRole("link", { name: "Open living record" }).getAttribute("href")).toBe("/ledger/threat-abc123");
    expect(screen.getAllByText("Patch now")).toHaveLength(2);
  });

  it("keeps the default register readable and reveals more on request", async () => {
    const records = Array.from({ length: 21 }, (_, index) => ({
      ...record,
      id: `threat-${index}`,
      entity_name: `CVE-2026-${String(index).padStart(4, "0")}`,
      title: `CVE-2026-${String(index).padStart(4, "0")}`,
    }));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      generated_at: "2026-10-08T10:00:00Z",
      run_change_count: 0,
      summary: { total_records: 21, active_records: 21, patch: 21, hunt: 0, qualified_hunts: 21, investigate: 0, monitor: 0 },
      total: 21, offset: 0, limit: 200, has_more: false, filters: {}, changes: [], records,
    })));

    render(<LedgerView />);

    expect(await screen.findByText("Showing 20 of 21 records")).toBeTruthy();
    expect(screen.queryByText("CVE-2026-0020")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Show 1 more record" }));
    expect(screen.getByText("CVE-2026-0020")).toBeTruthy();
  });

  it("collects every server page before applying local filters", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      const isSecondPage = path.includes("offset=200");
      const records = isSecondPage
        ? [{ ...record, id: "threat-second", title: "Second page record" }]
        : Array.from({ length: 200 }, (_, index) => ({ ...record, id: `threat-${index}`, title: `First page record ${index}` }));
      return jsonResponse({
        generated_at: "2026-10-08T10:00:00Z", run_change_count: 0,
        summary: { total_records: 201, active_records: 201, patch: 201, hunt: 0, qualified_hunts: 201, investigate: 0, monitor: 0 },
        total: 201, offset: isSecondPage ? 200 : 0, limit: 200, has_more: !isSecondPage,
        filters: {}, changes: [], records,
      });
    }));

    render(<LedgerView />);

    expect(await screen.findByText("Showing 20 of 201 records")).toBeTruthy();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("shows evidence, remediation, history, and original reporting on detail", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(record)));

    render(<LedgerRecordView id="threat-abc123" />);

    expect(await screen.findByText("Apply the vendor update.")).toBeTruthy();
    expect(screen.getByText("Independent reporting")).toBeTruthy();
    expect(screen.getByText("CVE-2026-1000 gained confirmed exploitation evidence.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Technical report" }).getAttribute("href")).toBe("https://research.example/report");
    expect(fetch).toHaveBeenCalledWith("/api/v1/ledger/threat-abc123", expect.any(Object));
  });
});
