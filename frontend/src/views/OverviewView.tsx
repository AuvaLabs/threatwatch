import { useMemo } from "preact/hooks";
import { api } from "../services/api";
import type { Article, Briefing } from "../types";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { actionText, articleSummary, displayTitle, excerpt, formattedDate, safeExternalUrl, sourceLabel } from "../utils/format";
import { ArticleList } from "../components/ArticleList";
import { ErrorState, LoadingState } from "../components/PageState";

interface OverviewData {
  briefing: Briefing | null;
  articles: Article[];
  total: number;
}

async function loadOverview(signal: AbortSignal): Promise<OverviewData> {
  const [briefing, articles] = await Promise.allSettled([
    api.briefing("latest", signal),
    api.articles({ view: "news", limit: 8 }, signal),
  ]);
  if (articles.status === "rejected") throw articles.reason;
  return {
    briefing: briefing.status === "fulfilled" ? briefing.value : null,
    articles: articles.value.articles,
    total: articles.value.total,
  };
}

export function OverviewView() {
  const resource = useResource(loadOverview, []);
  const lead = resource.data?.articles[0];
  const briefing = resource.data?.briefing;
  const actions = useMemo(() => (briefing?.what_to_do || []).slice(0, 3), [briefing]);

  if (resource.loading) return <LoadingState label="Preparing today’s intelligence brief" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "The briefing could not be loaded."} />;

  const briefingSource = briefing?.source_articles?.find((source) => source.index === briefing.headline_source)
    || briefing?.source_articles?.[0];
  const sourceUrl = safeExternalUrl(briefingSource?.link || lead?.canonical_url || lead?.link);
  return (
    <div class="view overview-view">
      <header class="briefing-heading">
        <div>
          <p class="eyebrow">Daily analyst overview</p>
          <h1>Today’s Intelligence Brief</h1>
          <p>Key developments, emerging risks, and what to do next.</p>
        </div>
        <div class="briefing-time">
          <span>{briefing?.reporting_window || "Current reporting window"}</span>
          <time>{formattedDate(briefing?.generated_at)}</time>
        </div>
      </header>

      {(briefing?.served_stale || !briefing) && (
        <div class="notice warning" role="status">
          {briefing?.served_stale ? "The latest validated briefing is being served while enrichment recovers." : "The narrative briefing is unavailable. Current source reporting remains accessible below."}
        </div>
      )}

      <section aria-labelledby="lead-story" class="lead-story surface">
        <div class="lead-copy">
          <div class="lead-labels">
            <span class="eyebrow">Top development</span>
            {briefing?.threat_level && <span class={`risk-label ${briefing.threat_level.toLowerCase()}`}>{briefing.threat_level}</span>}
          </div>
          <h2 id="lead-story">{briefing?.headline || (lead ? displayTitle(lead) : "No lead development identified")}</h2>
          <p>{excerpt(briefing?.what_happened) || (lead && articleSummary(lead)) || "A validated analyst summary is not yet available."}</p>
          <div class="source-line">
            {(briefingSource?.source_name || lead) && <span>{briefingSource?.source_name || (lead && sourceLabel(lead))}</span>}
            {sourceUrl && <a href={sourceUrl} rel="noopener noreferrer" target="_blank">Open original source</a>}
          </div>
        </div>
        <aside class="why-panel">
          <h3>Why it matters</h3>
          <p>{briefing?.assessment_basis || briefing?.outlook || "This story leads the current reporting window based on source recency and analyst relevance."}</p>
          <button class="button primary" onClick={() => navigate("/briefings")} type="button">Read full briefing</button>
        </aside>
      </section>

      <section aria-labelledby="attention-title" class="attention surface">
        <div class="section-heading inline">
          <div><p class="eyebrow">Analyst actions</p><h2 id="attention-title">What needs attention</h2></div>
          <span>{actions.length ? `${actions.length} priorities` : "No validated actions"}</span>
        </div>
        {actions.length ? (
          <ol class="action-list">
            {actions.map((action, index) => <li key={`${index}-${actionText(action)}`}><span>{index + 1}</span><p>{actionText(action)}</p></li>)}
          </ol>
        ) : <p class="muted-copy">Recommended actions are pending. Review the latest source reporting before changing controls.</p>}
      </section>

      <section aria-labelledby="latest-title" class="latest-section">
        <div class="section-heading">
          <div><p class="eyebrow">Source-linked reporting</p><h2 id="latest-title">Latest intelligence</h2></div>
          <button class="text-button" onClick={() => navigate("/news")} type="button">View all {resource.data.total} reports</button>
        </div>
        <ArticleList articles={resource.data.articles} compact />
      </section>
    </div>
  );
}
