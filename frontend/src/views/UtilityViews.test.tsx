import { cleanup, render, screen } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AutomationView } from "./AutomationView";
import { SystemView } from "./SystemView";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

afterEach(() => cleanup());

describe("utility views", () => {
  it("groups machine interfaces instead of rendering one unbroken endpoint list", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(async (path: string) => {
      if (path === "/api/v1/openapi.json") return response({ openapi: "3.1.0", info: { title: "ThreatWatch", version: "1" }, paths: {
        "/api/v1/articles": { get: { summary: "List articles" } },
        "/api/v1/incidents/v2": { get: { summary: "List incidents" } },
        "/api/v1/hunts": { get: { summary: "List hunts" } },
        "/api/v1/ledger": { get: { summary: "List records" } },
        "/api/v1/health": { get: { summary: "Get health" } },
      } });
      return response({ status: "ok" });
    }));

    render(<AutomationView />);

    expect(await screen.findByRole("heading", { name: "Endpoint groups" })).toBeTruthy();
    expect(screen.getByText("Incidents")).toBeTruthy();
    expect(screen.getByText("Hunts")).toBeTruthy();
    expect(document.querySelectorAll(".endpoint-group")).toHaveLength(5);
  });

  it("shows public freshness, deployment, and recovery state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({
      status: "ok", articles_total: 2414, feed_health: { ok: 137 }, briefing_stale: false,
      generated_at: "2026-10-30T05:00:00Z", last_run_at: "2026-10-30T04:50:00Z",
      ai_artifacts: { ok: true }, operational_artifacts: { ok: true, capabilities: { incidents: {}, hunts: {}, ledger: {} } },
      deployment: { sha: "1234567890abcdef", api_schema_version: "1.1.0" },
      backup: { configured: true, ok: true, last_restore_verified_at: "2026-10-30T04:00:00Z" },
    })));

    render(<SystemView />);

    expect(screen.getByRole("heading", { name: "Status", level: 1 })).toBeTruthy();
    expect(await screen.findByText("1234567890ab")).toBeTruthy();
    expect(screen.getByText("Verified")).toBeTruthy();
    expect(screen.getByText("incidents, hunts, ledger")).toBeTruthy();
  });
});
