import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { FollowingView } from "./FollowingView";
import { followThreat } from "../services/workspace";

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

describe("FollowingView", () => {
  it("shows only material changes after the local review cursor", async () => {
    followThreat({
      id: "threat-abc123", kind: "ledger", title: "CVE-2026-1000", detail: "Patch now",
      href: "/ledger/threat-abc123", feedHref: "/api/v1/ledger/threat-abc123/feed.xml",
      followedAt: "2026-10-08T00:00:00Z", lastReviewedAt: "2026-10-08T00:00:00Z",
    });
    vi.stubGlobal("fetch", vi.fn().mockImplementation((path: string) => response(path.includes("ledger") ? {
      generated_at: "2026-10-09T00:00:00Z", total: 2, changes: [
        { id: "new", record_id: "threat-abc123", changed_at: "2026-10-08T12:00:00Z", summary: "Exploitation is now confirmed." },
        { id: "old", record_id: "threat-abc123", changed_at: "2026-10-07T12:00:00Z", summary: "Tracking started." },
      ],
    } : { generated_at: "2026-10-09T00:00:00Z", total: 0, changes: [] })));

    render(<FollowingView />);

    expect(await screen.findByText("Exploitation is now confirmed.")).toBeTruthy();
    expect(screen.queryByText("Tracking started.")).toBeNull();
    expect(screen.getByLabelText("1 unread change")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Atom feed" }).getAttribute("href")).toContain("feed.xml");
    fireEvent.click(screen.getByRole("button", { name: "Mark all reviewed" }));
    expect(screen.getByText("No unread material changes.")).toBeTruthy();
  });

  it("passes the automated accessibility gate", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(response({
      generated_at: "2026-10-09T00:00:00Z", total: 0, changes: [],
    }))));
    const { container } = render(<FollowingView />);
    await screen.findByText("No followed threats yet");

    const result = await axe.run(container, { rules: {
      "color-contrast": { enabled: false },
      region: { enabled: false },
    } });

    expect(result.violations.map(({ id }) => id)).toEqual([]);
  });
});
