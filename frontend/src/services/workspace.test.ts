import { beforeEach, describe, expect, it, vi } from "vitest";
import { followThreat, importWorkspace, loadWorkspace, markFollowsReviewed, saveInvestigation, unfollowThreat, updateInvestigation, workspaceDownload } from "./workspace";
import type { FollowedThreat, Investigation } from "../types";

const investigation: Investigation = {
  id: "investigation-1",
  sourceId: "priority-1",
  title: "Review active exploitation",
  status: "open",
  urgency: "high",
  actionType: "hunt",
  createdAt: "2026-10-08T00:00:00.000Z",
  updatedAt: "2026-10-08T00:00:00.000Z",
  notes: "",
  cves: [],
};

const followed: FollowedThreat = {
  id: "threat-abc123",
  kind: "ledger",
  title: "CVE-2026-1000",
  detail: "Patch now",
  href: "/ledger/threat-abc123",
  feedHref: "/api/v1/ledger/threat-abc123/feed.xml",
  followedAt: "2026-10-08T00:00:00.000Z",
  lastReviewedAt: "2026-10-08T00:00:00.000Z",
};

describe("analyst workspace", () => {
  beforeEach(() => localStorage.clear());

  it("persists investigations without duplicating the source priority", () => {
    saveInvestigation(investigation);
    saveInvestigation({ ...investigation, title: "Duplicate" });
    expect(loadWorkspace().investigations).toEqual([investigation]);
  });

  it("validates corrupt storage and updates allowed fields", () => {
    localStorage.setItem("threatwatch-workspace-v1", "not-json");
    expect(loadWorkspace().investigations).toEqual([]);
    saveInvestigation(investigation);
    const updated = updateInvestigation(investigation.id, { status: "monitoring", notes: "Hunt started" }, "2026-10-08T01:00:00.000Z");
    expect(updated?.status).toBe("monitoring");
    expect(updated?.notes).toBe("Hunt started");
    expect(loadWorkspace().investigations[0].updatedAt).toBe("2026-10-08T01:00:00.000Z");
    expect(updateInvestigation("missing", { status: "closed", notes: "none" })).toBeNull();
  });

  it("drops structurally invalid records", () => {
    localStorage.setItem("threatwatch-workspace-v1", JSON.stringify({
      investigations: [{ ...investigation, urgency: "urgent" }, { ...investigation, id: "bad-action", actionType: "email" }],
    }));
    expect(loadWorkspace()).toEqual({ investigations: [], follows: [] });
    localStorage.setItem("threatwatch-workspace-v1", JSON.stringify({ investigations: "invalid" }));
    expect(loadWorkspace()).toEqual({ investigations: [], follows: [] });
  });

  it("downloads a portable JSON workspace", () => {
    const createObjectURL = vi.fn(() => "blob:workspace");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    workspaceDownload({ investigations: [investigation], follows: [] });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:workspace");
  });

  it("imports only structurally valid portable workspaces", () => {
    expect(importWorkspace(JSON.stringify({ investigations: [investigation] }))).toEqual({ investigations: [investigation], follows: [] });
    expect(loadWorkspace()).toEqual({ investigations: [investigation], follows: [] });
    expect(() => importWorkspace(JSON.stringify({ investigations: [{ ...investigation, status: "invalid" }] }))).toThrow("valid investigations");
    expect(() => importWorkspace("not-json")).toThrow("valid JSON");
  });

  it("surfaces unavailable browser storage", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    expect(() => saveInvestigation(investigation)).toThrow("Browser storage is unavailable.");
  });

  it("persists, reviews, and removes browser-local followed threats", () => {
    followThreat(followed);
    followThreat({ ...followed, title: "Duplicate" });
    expect(loadWorkspace().follows).toEqual([followed]);

    markFollowsReviewed("2026-10-09T00:00:00.000Z");
    expect(loadWorkspace().follows[0].lastReviewedAt).toBe("2026-10-09T00:00:00.000Z");

    unfollowThreat(followed.kind, followed.id);
    expect(loadWorkspace().follows).toEqual([]);
  });

  it("imports valid followed records and rejects malformed ones", () => {
    expect(importWorkspace(JSON.stringify({ investigations: [], follows: [followed] }))).toEqual({ investigations: [], follows: [followed] });
    expect(() => importWorkspace(JSON.stringify({ investigations: [], follows: [{ ...followed, href: "https://evil.example" }] }))).toThrow("valid followed threats");
  });
});
