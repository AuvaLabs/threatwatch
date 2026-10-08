import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Article } from "../types";
import { actionText, articleDate, articleSummary, displayTitle, excerpt, formattedDate, healthReason, relativeTime, safeExternalUrl, sourceLabel } from "./format";

const article = { hash: "abc", title: "Original title" } as Article;

describe("format utilities", () => {
  beforeEach(() => vi.useFakeTimers().setSystemTime(new Date("2026-10-08T12:00:00Z")));
  afterEach(() => vi.useRealTimers());

  it("selects the canonical article date in priority order", () => {
    expect(articleDate({ ...article, published_at: "2026-10-08T10:00:00Z", published: "older" })).toBe("2026-10-08T10:00:00Z");
    expect(articleDate({ ...article, published: "published" })).toBe("published");
    expect(articleDate(article)).toBeNull();
  });

  it("renders relative times and incomplete dates honestly", () => {
    expect(relativeTime("2026-10-08T11:59:40Z")).toBe("Just now");
    expect(relativeTime("2026-10-08T11:50:00Z")).toBe("10m ago");
    expect(relativeTime("2026-10-08T09:00:00Z")).toBe("3h ago");
    expect(relativeTime("2026-10-06T12:00:00Z")).toBe("2d ago");
    expect(relativeTime("not-a-date")).toBe("Time unavailable");
    expect(formattedDate()).toBe("Time unavailable");
    expect(formattedDate("bad")).toBe("Time unavailable");
  });

  it("uses translated titles and explicit summary fallbacks", () => {
    expect(displayTitle({ ...article, translated_title: "Translated" })).toBe("Translated");
    expect(displayTitle({ ...article, title: "" })).toBe("Untitled intelligence report");
    expect(articleSummary({ ...article, summary: "  Summary  " })).toBe("Summary");
    expect(articleSummary({ ...article, intel_what: "Assessment" })).toBe("Assessment");
    expect(articleSummary(article)).toBeNull();
    expect(sourceLabel({ ...article, source_name: " Trusted Source " })).toBe("Trusted Source");
    expect(sourceLabel({ ...article, source: "darkweb:threatfox" })).toBe("ThreatFox");
    expect(sourceLabel({ ...article, source: "https://feeds.example-security.com/rss" })).toBe("Example Security");
    expect(sourceLabel(article)).toBe("Unknown source");
  });

  it("keeps overview narratives brief without cutting useful sentences", () => {
    expect(excerpt("Short assessment.", 100)).toBe("Short assessment.");
    expect(excerpt("First useful sentence. Second sentence contains more detail than the overview needs.", 30)).toBe("First useful sentence.");
    expect(excerpt("A long statement without sentence punctuation that must stop safely", 20)).toBe("A long statement…");
    expect(excerpt()).toBeNull();
  });

  it("allows only browser-safe source protocols", () => {
    expect(safeExternalUrl("https://example.com/report")).toBe("https://example.com/report");
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeExternalUrl("not a url")).toBeNull();
    expect(safeExternalUrl()).toBeNull();
  });

  it("normalizes briefing actions", () => {
    expect(actionText("Patch now")).toBe("Patch now");
    expect(actionText({ action: "Monitor access" })).toBe("Monitor access");
  });

  it("turns machine health reasons into readable labels", () => {
    expect(healthReason("artifact_stale_regional_emea")).toBe("Artifact stale regional EMEA");
    expect(healthReason("ai_capability_failing_article_summaries")).toBe("AI capability failing article summaries");
  });
});
