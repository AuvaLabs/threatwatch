import { describe, expect, it } from "vitest";
import type { Briefing } from "../types";
import { briefingSources, briefingTitle, sourceHref, sourcePublisher } from "./briefing";

const briefing: Briefing = {
  headline_source: 3,
  what_happened_sources: [2, 1, 2, 99],
  what_to_do: [{ action: "Patch now", sources: [1, 4] }],
  source_articles: [
    { index: 1, title: "First source", link: "https://www.cisa.gov/first" },
    { index: 2, title: "Second source", link: "https://example.com/second", source_name: "Example News" },
    { index: 3, title: "Headline source", link: "https://publisher.test/headline" },
    { index: 4, title: "Action source", link: "https://vendor.test/action" },
  ],
};

describe("briefing evidence", () => {
  it("returns cited source articles in narrative order without duplicates", () => {
    expect(briefingSources(briefing).map((source) => source.index)).toEqual([3, 2, 1, 4]);
  });

  it("honors a display limit and ignores missing citation indexes", () => {
    expect(briefingSources(briefing, 2).map((source) => source.index)).toEqual([3, 2]);
  });

  it("allows only web URLs for external evidence links", () => {
    expect(sourceHref("https://example.com/report")).toBe("https://example.com/report");
    expect(sourceHref("javascript:alert(1)")).toBeUndefined();
    expect(sourceHref(undefined)).toBeUndefined();
  });

  it("uses the publisher name, hostname, then a neutral fallback", () => {
    expect(sourcePublisher(briefing.source_articles?.[1])).toBe("Example News");
    expect(sourcePublisher(briefing.source_articles?.[0])).toBe("cisa.gov");
    expect(sourcePublisher(undefined)).toBe("Source");
  });

  it("does not describe a populated briefing as unavailable when its headline is missing", () => {
    expect(briefingTitle({ headline: "Named assessment", what_happened: "Narrative" })).toBe("Named assessment");
    expect(briefingTitle({ what_happened: "Narrative without a headline" })).toBe("Current intelligence assessment");
    expect(briefingTitle(null)).toBe("Narrative assessment unavailable");
  });
});
