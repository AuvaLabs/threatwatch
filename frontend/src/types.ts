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
  title: string;
  link: string;
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
