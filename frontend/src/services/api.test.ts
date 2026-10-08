import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

function response(body: unknown, status = 200): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("API client", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("encodes bounded article filters", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ articles: [], total: 0, offset: 0, limit: 30, has_more: false }));
    await api.articles({ q: "cloud breach", region: "EMEA", limit: 30 });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/articles?q=cloud+breach&region=EMEA&limit=30",
      expect.objectContaining({ headers: { Accept: "application/json" } }),
    );
  });

  it("calls each stable read contract", async () => {
    vi.mocked(fetch).mockImplementation(async () => response({}));
    await api.article("abc 123");
    await api.briefing("emea");
    await api.health();
    await api.clusters();
    await api.watchlist();
    await api.openApi();
    await api.operations();
    expect(vi.mocked(fetch).mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/articles/abc%20123",
      "/api/v1/briefings/emea",
      "/api/v1/health",
      "/api/v1/incidents",
      "/api/watchlist",
      "/api/v1/openapi.json",
      "/api/v1/operations/summary",
    ]);
  });

  it("exposes safe server errors", async () => {
    vi.mocked(fetch).mockResolvedValue(response({ error: "Article not found" }, 404));
    await expect(api.article("missing")).rejects.toEqual(new ApiError("Article not found", 404));
  });

  it("falls back to the HTTP status for malformed errors", async () => {
    vi.mocked(fetch).mockResolvedValue(response("not-json", 500));
    await expect(api.health()).rejects.toMatchObject({ message: "Request failed with status 500", status: 500 });
  });
});
