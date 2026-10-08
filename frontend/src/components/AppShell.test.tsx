import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  it("renders the eight analyst workspaces and health state", () => {
    render(<AppShell health={{ status: "ok" }} route="mission"><p>Content</p></AppShell>);
    const primary = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(primary.querySelectorAll("a")).toHaveLength(8);
    expect(screen.getByText("Platform ok")).toBeTruthy();
    expect(screen.getByText("Content")).toBeTruthy();
  });

  it("moves search queries into the sources workspace", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<AppShell health={null} route="mission"><p>Content</p></AppShell>);
    const input = screen.getByRole("searchbox", { name: "Ask ThreatWatch" });
    fireEvent.input(input, { target: { value: "CVE-2026-1" } });
    fireEvent.submit(screen.getByRole("search", { name: "Search ThreatWatch" }));
    expect(`${location.pathname}${location.search}`).toBe("/sources?q=CVE-2026-1");
  });

  it("persists an explicit theme choice", () => {
    render(<AppShell health={null} route="sources"><p>Content</p></AppShell>);
    fireEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("tw-theme")).toBe("dark");
  });

  it("opens and closes the compact navigation", () => {
    render(<AppShell health={null} route="article"><p>Content</p></AppShell>);
    fireEvent.click(screen.getByRole("button", { name: "Open navigation" }));
    expect(document.querySelector(".sidebar.open")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Close navigation" })[0]);
    expect(document.querySelector(".sidebar.open")).toBeFalsy();
  });

  it("opens the full source library for an empty search", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<AppShell health={null} route="mission"><p>Content</p></AppShell>);
    fireEvent.submit(screen.getByRole("search", { name: "Search ThreatWatch" }));
    expect(location.pathname).toBe("/sources");
  });
});
