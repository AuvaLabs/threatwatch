import { useState } from "preact/hooks";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import type { ClustersResponse, IncidentsResponse } from "../types";
import { formattedDate } from "../utils/format";

export function ThreatsView() {
  const [query, setQuery] = useState("");
  const resource = useResource(async (signal): Promise<{ clusters: ClustersResponse; incidents: IncidentsResponse }> => {
    const [clusters, incidents] = await Promise.allSettled([api.clusters(signal), api.incidents(signal)]);
    if (clusters.status === "rejected" && incidents.status === "rejected") throw clusters.reason;
    return {
      clusters: clusters.status === "fulfilled" ? clusters.value : { clusters: [] },
      incidents: incidents.status === "fulfilled" ? incidents.value : {
        schema_version: 1, summary: { total_records: 0, high_priority: 0, developing: 0 },
        run_change_count: 0, total: 0, changes: [], records: [],
      },
    };
  }, []);
  const clusters = (resource.data?.clusters.clusters || []).filter((cluster) => {
    const searchable = `${cluster.entity_name || ""} ${cluster.entity_type || ""} ${cluster.synthesis || ""}`.toLowerCase();
    return searchable.includes(query.toLowerCase());
  });
  const incidents = (resource.data?.incidents.records || []).filter((incident) => (
    incident.state === "corroborated"
    && `${incident.organization} ${incident.title} ${incident.summary}`.toLowerCase().includes(query.toLowerCase())
  ));
  return (
    <div class="view threats-view">
      <PageHeader eyebrow="Threat register" title="Threats" description="Evidence-linked incidents alongside correlated actors and vulnerabilities." />
      <label class="standalone-search"><span>Filter threats</span><input onInput={(event) => setQuery(event.currentTarget.value)} placeholder="Actor, campaign, malware, or vulnerability" type="search" value={query} /></label>
      {resource.loading && <LoadingState label="Correlating threat evidence" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && <section class="incident-register" aria-labelledby="incident-register-title">
        <div class="section-heading"><div><p class="eyebrow">Living incident records</p><h2 id="incident-register-title">Breach anatomy</h2></div><span>{incidents.length} evidence-linked</span></div>
        <div class="incident-register-list">{incidents.slice(0, 30).map((incident) => <article class="incident-register-row" key={incident.id}>
          <div><span class={`status-pill ${incident.priority}`}>{incident.priority}</span><strong>{incident.score}</strong></div>
          <div><p class="eyebrow">{incident.organization} / {incident.state}</p><h3>{incident.title}</h3><p>{incident.summary}</p><small>{incident.independent_source_count} independent sources / updated {formattedDate(incident.last_updated)}</small></div>
          <a href={`/incidents/${incident.id}`} onClick={(event) => { event.preventDefault(); navigate(`/incidents/${incident.id}`); }}>Review evidence</a>
        </article>)}</div>
      </section>}
      {resource.data && !clusters.length && !incidents.length && <EmptyState title="No threats matched">Clear the filter or wait for additional correlated evidence.</EmptyState>}
      <div class="threat-grid">
        {clusters.slice(0, 60).map((cluster) => (
          <article class="threat-card surface" key={cluster.campaign_id || `${cluster.entity_type}-${cluster.entity_name}`}>
            <div class="threat-card-head"><span class={`status-pill ${cluster.campaign_status || "observed"}`}>{cluster.campaign_status || "Observed"}</span><span>{cluster.entity_type || "Threat"}</span></div>
            <h2>{cluster.entity_name || "Unattributed activity"}</h2>
            <p>{cluster.synthesis || "Shared entities connect this reporting. Analyst synthesis is pending."}</p>
            <dl><div><dt>Evidence</dt><dd>{cluster.article_count || cluster.articles?.length || 0} reports</dd></div><div><dt>Confidence</dt><dd>{typeof cluster.confidence === "number" ? `${cluster.confidence}%` : cluster.confidence || "Unscored"}</dd></div><div><dt>First seen</dt><dd>{formattedDate(cluster.first_observed || cluster.first_seen)}</dd></div></dl>
          </article>
        ))}
      </div>
    </div>
  );
}
