export interface Article {
  hash: string;
  title: string;
  translated_title?: string;
  link?: string;
  canonical_url?: string;
  published?: string;
  published_at?: string | null;
  timestamp?: string;
  summary?: string;
  summary_method?: "none" | "source" | "ai" | string;
  source_name?: string;
  source?: string;
  category?: string;
  confidence?: number;
  region?: string;
  feed_region?: string;
  language?: string;
  cve_ids?: string[];
  iocs?: Record<string, unknown[]>;
  asset_tags?: string[];
  brand_tags?: string[];
  victim_sectors?: string[];
  attack_techniques?: Array<string | { id?: string; name?: string }>;
  kev_listed?: boolean;
  kevListed?: boolean;
  cvss_score?: number;
  cvss_severity?: string;
  epss_score?: number;
  intel_what?: string;
}

export interface ArticlesResponse {
  articles: Article[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  filters?: Record<string, string>;
}

export interface BriefingAction {
  action: string;
  threat?: string;
  sources?: number[];
}

export interface SourceArticle {
  index: number;
  title?: string;
  link?: string;
  source_name?: string;
}

export interface Briefing {
  threat_level?: string;
  headline?: string;
  assessment_basis?: string;
  what_happened?: string;
  what_to_do?: Array<BriefingAction | string>;
  outlook?: string;
  generated_at?: string;
  reporting_window?: string;
  provider?: string;
  headline_source?: number;
  threat_level_source?: number | string;
  what_happened_sources?: number[];
  week_in_review_sources?: number[];
  source_articles?: SourceArticle[];
  served_stale?: boolean;
}

export interface Health {
  status: "ok" | "degraded" | "stale" | string;
  reasons?: string[];
  generated_at?: string;
  articles_total?: number;
  briefing_stale?: boolean;
  feed_health?: Record<string, number>;
}

export interface Cluster {
  campaign_id?: string;
  entity_type?: string;
  entity_name?: string;
  synthesis?: string;
  confidence?: number;
  article_count?: number;
  first_seen?: string;
  first_observed?: string;
  campaign_status?: string;
  articles?: Article[];
}

export interface ClustersResponse {
  clusters: Cluster[];
  total_clusters?: number;
  generated_at?: string;
}

export interface Watchlist {
  brands: string[];
  assets: string[];
  updated_at?: string | null;
  write_enabled: boolean;
  suggest_list?: string[];
}

export interface OpenApiDocument {
  openapi: string;
  info: { title: string; version: string };
  paths: Record<string, Record<string, { summary?: string }>>;
}

export type OperationalUrgency = "critical" | "high" | "medium";
export type OperationalActionType = "patch" | "hunt" | "investigate" | "monitor";

export interface OperationalEvidence {
  cves: string[];
  techniques: string[];
  iocs: string[];
  ioc_count: number;
  kev?: boolean;
  cvss?: number | null;
  epss?: number | null;
  confidence?: number | null;
}

export interface OperationalPriority {
  id: string;
  title: string;
  summary: string;
  source_name?: string;
  published?: string;
  region?: string;
  score: number;
  urgency: OperationalUrgency;
  action_type: OperationalActionType;
  recommended_action: string;
  reasons: string[];
  watchlist_matches: string[];
  evidence: OperationalEvidence;
}

export interface OperationalSummary {
  generated_at: string;
  metrics: {
    decision_queue: number;
    critical_priorities: number;
    watchlist_matches: number;
    kev_records: number;
    active_threats: number;
    sources_reviewed: number;
  };
  priorities: OperationalPriority[];
  exposure: {
    configured: boolean;
    brands: string[];
    assets: string[];
    matches: OperationalPriority[];
    disclaimer: string;
  };
}

export type InvestigationStatus = "open" | "monitoring" | "closed";

export interface Investigation {
  id: string;
  sourceId: string;
  title: string;
  status: InvestigationStatus;
  urgency: OperationalUrgency;
  actionType: OperationalActionType;
  createdAt: string;
  updatedAt: string;
  notes: string;
  cves: string[];
}

export interface AnalystWorkspace {
  investigations: Investigation[];
}
