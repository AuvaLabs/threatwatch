import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  it("renders the desk index and health state", () => {
    render(<AppShell health={{ status: "ok" }} route="mission"><p>Content</p></AppShell>);
    const primary = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(primary.querySelectorAll("a")).toHaveLength(9);
    expect(screen.getByRole("link", { name: /Incidents/ }).getAttribute("href")).toBe("/incidents");
    expect(screen.getByRole("link", { name: /Investigations/ }).getAttribute("href")).toBe("/investigations");
    expect(screen.getByRole("link", { name: /Ledger/ })).toBeTruthy();
    expect(screen.getByRole("link", { name: /API/ }).getAttribute("href")).toBe("/automation");
    expect(screen.getByRole("link", { name: /Status/ }).getAttribute("href")).toBe("/system");
    expect(screen.getByText("ok")).toBeTruthy();
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
    expect(document.querySelector(".desk-navigation.open")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Close navigation" })[0]);
    expect(document.querySelector(".desk-navigation.open")).toBeFalsy();
  });

  it("opens the full source library for an empty search", () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<AppShell health={null} route="mission"><p>Content</p></AppShell>);
    fireEvent.submit(screen.getByRole("search", { name: "Search ThreatWatch" }));
    expect(location.pathname).toBe("/sources");
  });

  it("passes the automated navigation accessibility gate", async () => {
    const { container } = render(<AppShell health={{ status: "ok" }} route="threats"><h1>Incidents</h1></AppShell>);
    const result = await axe.run(container, { rules: {
      "color-contrast": { enabled: false },
      region: { enabled: false },
    } });
    expect(result.violations.map(({ id }) => id)).toEqual([]);
  });
});
