import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { formattedDate, healthReason } from "../utils/format";

export function SystemView() {
  const resource = useResource(api.health, []);
  const backup = resource.data?.backup;
  const telegram = resource.data?.notifications?.telegram_daily;
  const commandBrief = resource.data?.ai_artifacts?.capabilities?.command_brief;
  const offsiteVerified = backup?.offsite?.ok === true && backup.offsite.restore_verified === true;
  return (
    <div class="view system-view">
      <PageHeader eyebrow="Trust and freshness" title="Status" description="Pipeline, evidence corpus, analytical artifacts, delivery, deployment, and recovery state." />
      {resource.loading && <LoadingState label="Checking intelligence services" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && <div class="status-grid status-dashboard">
        <section class="surface status-hero"><span class={`health-indicator ${resource.data.status}`} /><div><p class="eyebrow">Platform</p><h2>{resource.data.status}</h2>{resource.data.reasons?.length ? <ul class="status-reasons">{resource.data.reasons.map((reason) => <li key={reason}>{healthReason(reason)}</li>)}</ul> : <p>No active degradation reasons reported.</p>}</div></section>
        <section class="surface"><p class="eyebrow">Evidence corpus</p><strong class="large-stat">{resource.data.articles_total?.toLocaleString() || "Unavailable"}</strong><span>{Object.values(resource.data.feed_health || {}).reduce((total, value) => total + value, 0)} feeds reporting state</span></section>
        <section class="surface"><p class="eyebrow">Pipeline</p><strong>{formattedDate(resource.data.last_run_at)}</strong><span>last successful intelligence run</span></section>
        <section class="surface"><p class="eyebrow">Command brief</p><strong class="large-stat">{commandBrief?.ok === false ? "Degraded" : resource.data.briefing_stale ? "Stale" : "Current"}</strong><span>{resource.data.ai_artifacts?.ok === false ? "analytical artifact degradation reported" : "analytical artifacts current"}</span></section>
        <section class="surface"><p class="eyebrow">Operational artifacts</p><strong class="large-stat">{resource.data.operational_artifacts?.ok === false ? "Degraded" : "Current"}</strong><span>{Object.keys(resource.data.operational_artifacts?.capabilities || {}).join(", ") || "incident, hunt, and ledger state"}</span></section>
        <section class="surface"><p class="eyebrow">Deployment</p><strong><code>{resource.data.deployment?.sha?.slice(0, 12) || "Unavailable"}</code></strong><span>API schema {resource.data.deployment?.api_schema_version || "unknown"}</span></section>
        <section class="surface"><p class="eyebrow">Recovery</p><strong class="large-stat">{offsiteVerified ? "Verified offsite" : backup?.ok === true ? "Verified local" : backup?.configured ? "Check" : "Unavailable"}</strong><span>{offsiteVerified ? `${backup?.offsite?.location || "offsite"} copy restore verified ${formattedDate(backup?.offsite?.verified_at)}` : backup?.last_restore_verified_at ? `local restore checked ${formattedDate(backup.last_restore_verified_at)}` : "restore verification unavailable"}</span></section>
        <section class="surface"><p class="eyebrow">Telegram daily</p><strong class="large-stat">{!telegram?.configured ? "Not configured" : telegram.ok === true ? "Delivered" : telegram.ok === false ? "Delivery failed" : "Pending"}</strong><span>{telegram?.attempted_at ? `last attempt ${formattedDate(telegram.attempted_at)}` : "delivery status unavailable"}</span></section>
        <section class="surface"><p class="eyebrow">Last checked</p><strong>{formattedDate(resource.data.generated_at)}</strong><span>public health snapshot</span></section>
      </div>}
    </div>
  );
}
