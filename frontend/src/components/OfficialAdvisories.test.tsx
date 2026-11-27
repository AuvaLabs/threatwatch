import { cleanup, render, screen } from "@testing-library/preact";
import { afterEach, expect, it, vi } from "vitest";
import { OfficialAdvisories } from "./OfficialAdvisories";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("links to official advisories and labels a publisher revision date", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
    generated_at: "2026-11-27T18:00:00Z",
    advisories: [
      { id: "one", title: "Product update", source: "ProductCERT", url: "https://example.test/advisory", updated_at: "2026-11-27T17:00:00Z" },
      { id: "two", title: "Unsafe link", source: "ProductCERT", url: "javascript:alert(1)", updated_at: "2026-11-27T16:00:00Z" },
    ],
  }))));

  render(<OfficialAdvisories />);
  const link = await screen.findByRole("link", { name: "Product update" });
  expect(link.getAttribute("href")).toBe("https://example.test/advisory");
  expect(screen.queryByRole("link", { name: "Unsafe link" })).toBeNull();
  expect(screen.getAllByText(/Updated/)).toHaveLength(2);
});
