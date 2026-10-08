import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import type { OperationalPriority } from "../types";
import { PriorityCard } from "./PriorityCard";

const priority: OperationalPriority = {
  id: "p1", title: "Threat record", summary: "Evidence summary", score: 88, urgency: "high", action_type: "hunt",
  recommended_action: "Hunt affected systems.", reasons: ["Indicator extracted"], watchlist_matches: ["Vendor"],
  evidence: { cves: ["CVE-1"], techniques: ["T1190"], iocs: ["example.test"], ioc_count: 1 },
};

describe("PriorityCard", () => {
  it("presents decision context and starts an investigation", () => {
    const onInvestigate = vi.fn();
    render(<PriorityCard onInvestigate={onInvestigate} priority={priority} />);
    expect(screen.getByText("Threat record")).toBeTruthy();
    expect(screen.getByText("Watchlist match")).toBeTruthy();
    expect(screen.getByText("3 evidence points")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Open investigation" }));
    expect(onInvestigate).toHaveBeenCalledWith(priority);
  });

  it("opens matching source evidence", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<PriorityCard priority={{ ...priority, watchlist_matches: [] }} />);
    fireEvent.click(screen.getByRole("button", { name: "Review sources" }));
    expect(`${location.pathname}${location.search}`).toBe("/sources?q=Threat%20record");
  });
});
