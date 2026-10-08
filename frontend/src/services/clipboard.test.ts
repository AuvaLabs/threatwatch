import { describe, expect, it, vi } from "vitest";
import { copyText } from "./clipboard";

describe("copyText", () => {
  it("reports successful clipboard writes", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyText("evidence")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("evidence");
  });

  it("reports unavailable and rejected clipboard access", async () => {
    vi.stubGlobal("navigator", {});
    await expect(copyText("evidence")).resolves.toBe(false);
    vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    await expect(copyText("evidence")).resolves.toBe(false);
  });
});
