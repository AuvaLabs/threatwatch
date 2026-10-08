import type {
  Article,
  ArticlesResponse,
  Briefing,
  ClustersResponse,
  Health,
  HuntsResponse,
  LedgerResponse,
  OperationalSummary,
  OpenApiDocument,
  Watchlist,
  ThreatRecord,
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

export interface LedgerQuery {
  q?: string;
  type?: "cve" | "actor";
  action?: "patch" | "hunt" | "investigate" | "monitor";
  activity?: "active" | "not_recent";
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

function ledgerQueryString(query: LedgerQuery): string {
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
  hunts: (signal?: AbortSignal) => request<HuntsResponse>("/api/v1/hunts", signal),
  ledger: (query: LedgerQuery = {}, signal?: AbortSignal) =>
    request<LedgerResponse>(`/api/v1/ledger${ledgerQueryString(query)}`, signal),
  ledgerRecord: (id: string, signal?: AbortSignal) =>
    request<ThreatRecord>(`/api/v1/ledger/${encodeURIComponent(id)}`, signal),
  ledgerChanges: (signal?: AbortSignal) =>
    request<Pick<LedgerResponse, "generated_at" | "changes"> & { total: number }>("/api/v1/ledger/changes", signal),
};
