import { render, screen } from "@testing-library/preact";
import { describe, expect, it } from "vitest";
import { BriefingSources } from "./BriefingSources";

describe("BriefingSources", () => {
  it("renders cited evidence with safe external links and a remaining count", () => {
    render(<BriefingSources briefing={{
      headline_source: 2,
      what_happened_sources: [1, 3],
      source_articles: [
        { index: 1, title: "Advisory", link: "https://cisa.gov/advisory" },
        { index: 2, title: "Headline report", link: "https://news.example/report", source_name: "News Desk" },
        { index: 3, title: "Unsafe record", link: "javascript:alert(1)" },
      ],
    }} compact limit={2} />);
    expect(screen.getByRole("link", { name: "Headline report" }).getAttribute("target")).toBe("_blank");
    expect(screen.getByRole("link", { name: "Advisory" }).getAttribute("href")).toBe("https://cisa.gov/advisory");
    expect(screen.queryByRole("link", { name: "Unsafe record" })).toBeNull();
    expect(screen.getByText("+1 more in the full report")).not.toBeNull();
  });

  it("renders an explicit fallback when citation metadata is unavailable", () => {
    render(<BriefingSources briefing={{ source_articles: [] }} />);
    expect(screen.getByText("Citation details are unavailable for this briefing.")).not.toBeNull();
  });
});
