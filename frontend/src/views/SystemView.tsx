import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { formattedDate, healthReason } from "../utils/format";

export function SystemView() {
  const resource = useResource(api.health, []);
  return (
    <div class="view system-view">
      <PageHeader eyebrow="Platform ledger" title="System status" description="Pipeline, corpus, briefing, and dependency freshness." />
      {resource.loading && <LoadingState label="Checking intelligence services" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && <div class="status-grid">
        <section class="surface status-hero"><span class={`health-indicator ${resource.data.status}`} /><div><p class="eyebrow">Platform</p><h2>{resource.data.status}</h2>{resource.data.reasons?.length ? <ul class="status-reasons">{resource.data.reasons.map((reason) => <li key={reason}>{healthReason(reason)}</li>)}</ul> : <p>No active degradation reasons reported.</p>}</div></section>
        <section class="surface"><p class="eyebrow">Corpus</p><strong class="large-stat">{resource.data.articles_total?.toLocaleString() || "Unavailable"}</strong><span>served intelligence records</span></section>
        <section class="surface"><p class="eyebrow">Briefing</p><strong class="large-stat">{resource.data.briefing_stale ? "Stale" : "Current"}</strong><span>latest narrative state</span></section>
        <section class="surface"><p class="eyebrow">Last checked</p><strong>{formattedDate(resource.data.generated_at)}</strong></section>
      </div>}
    </div>
  );
}
