import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import type { Article } from "../types";
import { ArticleList } from "./ArticleList";

const complete: Article = {
  hash: "abc123",
  title: "Original",
  translated_title: "Cloud provider disrupted by ransomware",
  source_name: "Trusted News",
  summary: "Services were interrupted across multiple customers.",
  summary_method: "ai",
  category: "Ransomware",
  region: "APAC",
  language: "ja",
  cve_ids: ["CVE-2026-1"],
  kev_listed: true,
};

describe("ArticleList", () => {
  it("renders analyst metadata and honest pending states", () => {
    render(<ArticleList articles={[complete, { hash: "pending", title: "Pending report", summary_method: "none" }]} />);
    expect(screen.getByText("Cloud provider disrupted by ransomware")).toBeTruthy();
    expect(screen.getByText("Services were interrupted across multiple customers.")).toBeTruthy();
    expect(screen.getByText("Summary pending")).toBeTruthy();
    expect(screen.getByText("CISA KEV")).toBeTruthy();
    expect(screen.getByText("1 CVE")).toBeTruthy();
  });

  it("renders a helpful empty state", () => {
    render(<ArticleList articles={[]} />);
    expect(screen.getByText("No intelligence matched")).toBeTruthy();
  });

  it("opens the dedicated intelligence route", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<ArticleList articles={[complete]} />);
    fireEvent.click(screen.getByRole("link", { name: complete.translated_title }));
    expect(location.pathname).toBe("/sources/abc123");
  });
});
