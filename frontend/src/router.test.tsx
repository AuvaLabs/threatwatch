import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { navigate, parseRoute, useRoute } from "./router";

function RouteProbe() {
  const route = useRoute();
  return <span>{route.name}:{route.articleId || "none"}</span>;
}

describe("router", () => {
  it("maps analyst routes and article ids", () => {
    expect(parseRoute("/")).toEqual({ name: "mission" });
    expect(parseRoute("/exposure")).toEqual({ name: "exposure" });
    expect(parseRoute("/sources/abc%20123")).toEqual({ name: "article", articleId: "abc 123" });
    expect(parseRoute("/news/abc%20123")).toEqual({ name: "article", articleId: "abc 123" });
    expect(parseRoute("/unknown")).toEqual({ name: "mission" });
  });

  it("navigates without reloading and notifies listeners", async () => {
    vi.stubGlobal("scrollTo", vi.fn());
    render(<RouteProbe />);
    expect(screen.getByText("mission:none")).toBeTruthy();
    navigate("/threats");
    await waitFor(() => expect(screen.getByText("threats:none")).toBeTruthy());
    expect(scrollTo).toHaveBeenCalled();
    navigate("/threats");
    fireEvent.popState(window);
    expect(screen.getByText("threats:none")).toBeTruthy();
  });
});
