import { cleanup } from "@testing-library/preact";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  localStorage.clear();
  history.replaceState({}, "", "/");
  vi.restoreAllMocks();
});
