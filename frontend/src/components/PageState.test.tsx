import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "./PageState";

describe("page states", () => {
  it("announces loading and empty states", () => {
    const { rerender } = render(<LoadingState label="Loading briefing" />);
    expect(screen.getByRole("status").textContent).toContain("Loading briefing");
    rerender(<EmptyState title="No reports">Clear filters.</EmptyState>);
    expect(screen.getByText("Clear filters.")).toBeTruthy();
  });

  it("provides a recovery action for errors", () => {
    const reload = vi.fn();
    Object.defineProperty(window, "location", { configurable: true, value: { ...window.location, reload } });
    render(<ErrorState message="Feed unavailable" />);
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(reload).toHaveBeenCalled();
  });

  it("renders page heading context and actions", () => {
    render(<PageHeader actions={<button>Export</button>} description="Context" eyebrow="Analyst view" title="News" />);
    expect(screen.getByRole("heading", { name: "News" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Export" })).toBeTruthy();
  });
});
