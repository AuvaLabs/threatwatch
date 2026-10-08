import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadWorkspace, saveInvestigation, updateInvestigation, workspaceDownload } from "./workspace";
import type { Investigation } from "../types";

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
    expect(loadWorkspace()).toEqual({ investigations: [] });
    localStorage.setItem("threatwatch-workspace-v1", JSON.stringify({ investigations: "invalid" }));
    expect(loadWorkspace()).toEqual({ investigations: [] });
  });

  it("downloads a portable JSON workspace", () => {
    const createObjectURL = vi.fn(() => "blob:workspace");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    workspaceDownload({ investigations: [investigation] });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:workspace");
  });

  it("surfaces unavailable browser storage", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    expect(() => saveInvestigation(investigation)).toThrow("Browser storage is unavailable.");
  });
});
