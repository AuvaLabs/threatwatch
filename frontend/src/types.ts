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

export type HuntStatus = "qualified" | "lead";

export interface HuntSource {
  article_id: string;
  title: string;
  publisher: string;
  published?: string | null;
  url?: string;
}

export interface HuntObservable {
  type: string;
  value: string;
  disposition: "confirmed" | "reported" | "lead" | "suppressed";
  confidence: number;
  contexts: string[];
  sources: HuntSource[];
}

export interface HuntTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface HuntQuery {
  name: string;
  language: string;
  telemetry: string;
  query: string;
}

export interface HuntRecord {
  id: string;
  entity_type: string;
  entity_name: string;
  title: string;
  status: HuntStatus;
  readiness_score: number;
  confidence: string;
  summary: string;
  hypothesis: string;
  why_qualified: string[];
  report_count: number;
  source_count: number;
  first_seen?: string | null;
  sources: HuntSource[];
  observables: HuntObservable[];
  techniques: HuntTechnique[];
  vulnerability?: {
    cves: string[];
    kev: boolean;
    max_cvss?: number | null;
    max_epss?: number | null;
  };
  telemetry: string[];
  queries: HuntQuery[];
  false_positives: string[];
  triage_steps: string[];
  limitations: string[];
  markdown: string;
}

export interface HuntsResponse {
  generated_at: string;
  qualified_count: number;
  lead_count: number;
  hunts: HuntRecord[];
}

export type LedgerAction = "patch" | "hunt" | "investigate" | "monitor";

export interface LedgerSource {
  article_id: string;
  title: string;
  publisher: string;
  published?: string | null;
  url?: string;
  source_type: "structured" | "reporting" | string;
}

export interface LedgerChange {
  id: string;
  record_id: string;
  entity_name: string;
  changed_at: string;
  kind: "tracking_started" | "state_changed" | string;
  field: string;
  previous: unknown;
  current: unknown;
  summary: string;
  source_ids: string[];
}

export interface ThreatRecord {
  id: string;
  entity_type: "cve" | "actor";
  entity_name: string;
  title: string;
  summary: string;
  decision: { action: LedgerAction; urgency: string; rationale: string };
  state: { activity: string; exploitation: string; evidence: string; hunt: string; remediation: string };
  version: number;
  first_seen?: string | null;
  last_updated: string;
  last_changed: string;
  report_count: number;
  source_count: number;
  sources: LedgerSource[];
  vulnerability?: { cve: string; kev: boolean; max_cvss?: number | null; max_epss?: number | null } | null;
  affected_products: string[];
  remediation: { required_action?: string | null; due_date?: string | null; affected_versions: string[]; fixed_versions: string[] };
  techniques: HuntTechnique[];
  hunt_id?: string | null;
  readiness_score: number;
  observable_count: number;
  evidence: Array<{ key: string; label: string; status: string; detail: string }>;
  open_questions: string[];
  changes: LedgerChange[];
}

export type ThreatRecordSummary = Pick<ThreatRecord,
  | "id" | "entity_type" | "entity_name" | "title" | "summary" | "decision"
  | "state" | "version" | "first_seen" | "last_updated" | "last_changed"
  | "report_count" | "source_count" | "vulnerability" | "affected_products"
  | "hunt_id" | "readiness_score" | "observable_count" | "open_questions"
>;

export interface LedgerResponse {
  schema_version: number;
  generated_at: string;
  run_change_count: number;
  summary: { total_records: number; active_records: number; patch: number; hunt: number; qualified_hunts: number; investigate: number; monitor: number };
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  filters: Record<string, string>;
  changes: LedgerChange[];
  records: ThreatRecordSummary[];
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
