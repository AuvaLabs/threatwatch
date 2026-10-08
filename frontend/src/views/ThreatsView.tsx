import { useState } from "preact/hooks";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { formattedDate } from "../utils/format";

export function ThreatsView() {
  const [query, setQuery] = useState("");
  const resource = useResource(api.clusters, []);
  const clusters = (resource.data?.clusters || []).filter((cluster) => {
    const searchable = `${cluster.entity_name || ""} ${cluster.entity_type || ""} ${cluster.synthesis || ""}`.toLowerCase();
    return searchable.includes(query.toLowerCase());
  });
  return (
    <div class="view threats-view">
      <PageHeader eyebrow="Threat register" title="Threats" description="Correlated activity built from shared actors, vulnerabilities, and affected organizations." />
      <label class="standalone-search"><span>Filter threats</span><input onInput={(event) => setQuery(event.currentTarget.value)} placeholder="Actor, campaign, malware, or vulnerability" type="search" value={query} /></label>
      {resource.loading && <LoadingState label="Correlating threat evidence" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && !clusters.length && <EmptyState title="No threats matched">Clear the filter or wait for additional correlated evidence.</EmptyState>}
      <div class="threat-grid">
        {clusters.slice(0, 60).map((cluster) => (
          <article class="threat-card surface" key={cluster.campaign_id || `${cluster.entity_type}-${cluster.entity_name}`}>
            <div class="threat-card-head"><span class={`status-pill ${cluster.campaign_status || "observed"}`}>{cluster.campaign_status || "Observed"}</span><span>{cluster.entity_type || "Threat"}</span></div>
            <h2>{cluster.entity_name || "Unattributed activity"}</h2>
            <p>{cluster.synthesis || "Shared entities connect this reporting. Analyst synthesis is pending."}</p>
            <dl><div><dt>Evidence</dt><dd>{cluster.article_count || cluster.articles?.length || 0} reports</dd></div><div><dt>Confidence</dt><dd>{cluster.confidence !== undefined ? `${cluster.confidence}%` : "Unscored"}</dd></div><div><dt>First seen</dt><dd>{formattedDate(cluster.first_observed || cluster.first_seen)}</dd></div></dl>
          </article>
        ))}
      </div>
    </div>
  );
}
