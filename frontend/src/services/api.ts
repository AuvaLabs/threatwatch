import type {
  Article,
  ArticlesResponse,
  Briefing,
  ClustersResponse,
  Health,
  OperationalSummary,
  OpenApiDocument,
  Watchlist,
} from "../types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const error = (await response.json()) as { error?: string };
      message = error.error || message;
    } catch {
      // The status remains actionable even if the error body is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export interface ArticleQuery {
  q?: string;
  category?: string;
  region?: string;
  source?: string;
  view?: "news" | "vulnerabilities";
  offset?: number;
  limit?: number;
}

function queryString(query: ArticleQuery): string {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== "") params.set(key, String(value));
  });
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export const api = {
  articles: (query: ArticleQuery = {}, signal?: AbortSignal) =>
    request<ArticlesResponse>(`/api/v1/articles${queryString(query)}`, signal),
  article: (id: string, signal?: AbortSignal) =>
    request<Article>(`/api/v1/articles/${encodeURIComponent(id)}`, signal),
  briefing: (region = "latest", signal?: AbortSignal) =>
    request<Briefing>(`/api/v1/briefings/${region}`, signal),
  health: (signal?: AbortSignal) => request<Health>("/api/v1/health", signal),
  clusters: (signal?: AbortSignal) => request<ClustersResponse>("/api/v1/incidents", signal),
  watchlist: (signal?: AbortSignal) => request<Watchlist>("/api/watchlist", signal),
  openApi: (signal?: AbortSignal) => request<OpenApiDocument>("/api/v1/openapi.json", signal),
  operations: (signal?: AbortSignal) => request<OperationalSummary>("/api/v1/operations/summary", signal),
};
