import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { formattedDate } from "../utils/format";

export function CampaignsView() {
  const resource = useResource(api.clusters, []);
  return (
    <div class="view campaigns-view">
      <PageHeader eyebrow="Correlated reporting" title="Campaigns" description="Persistent activity grouped by actors, vulnerabilities, and affected organizations." />
      {resource.loading && <LoadingState label="Correlating campaign intelligence" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && (
        <div class="campaign-list">
          {resource.data.clusters.slice(0, 40).map((cluster) => (
            <article class="campaign-row surface" key={cluster.campaign_id || `${cluster.entity_type}-${cluster.entity_name}`}>
              <div class="campaign-status"><span class={`status-pill ${cluster.campaign_status || "observed"}`}>{cluster.campaign_status || "Observed"}</span><span>{cluster.entity_type || "Campaign"}</span></div>
              <div class="campaign-copy"><h2>{cluster.entity_name || "Unattributed activity"}</h2><p>{cluster.synthesis || "Related reporting has been grouped through shared entities. Analyst synthesis is pending."}</p></div>
              <dl><div><dt>Reports</dt><dd>{cluster.article_count || cluster.articles?.length || 0}</dd></div><div><dt>Confidence</dt><dd>{cluster.confidence !== undefined ? `${cluster.confidence}%` : "Unscored"}</dd></div><div><dt>First seen</dt><dd>{formattedDate(cluster.first_observed || cluster.first_seen)}</dd></div></dl>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
