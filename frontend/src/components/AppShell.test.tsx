import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  it("renders the seven analyst jobs and health state", () => {
    render(<AppShell health={{ status: "ok" }} route="overview"><p>Content</p></AppShell>);
    const primary = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(primary.querySelectorAll("a")).toHaveLength(7);
    expect(screen.getByText("Intelligence ok")).toBeTruthy();
    expect(screen.getByText("Content")).toBeTruthy();
  });

  it("moves search queries into the news workspace", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<AppShell health={null} route="overview"><p>Content</p></AppShell>);
    const input = screen.getByRole("searchbox", { name: "Ask ThreatWatch" });
    fireEvent.input(input, { target: { value: "CVE-2026-1" } });
    fireEvent.submit(screen.getByRole("search", { name: "Search ThreatWatch" }));
    expect(`${location.pathname}${location.search}`).toBe("/news?q=CVE-2026-1");
  });

  it("persists an explicit theme choice", () => {
    render(<AppShell health={null} route="news"><p>Content</p></AppShell>);
    fireEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("tw-theme")).toBe("dark");
  });
});
