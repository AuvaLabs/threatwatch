import { ErrorState, LoadingState } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { downloadText, incidentMarkdown } from "../services/reports";
import type { IncidentClaim, IncidentRecord, IncidentSource } from "../types";
import { formattedDate, safeExternalUrl } from "../utils/format";

function ClaimSources({ claim, sources }: { claim: IncidentClaim; sources: IncidentSource[] }) {
  const linked = sources.filter((source) => claim.source_ids.includes(source.article_id));
  return <span class="claim-sources">{linked.map((source) => {
    const href = safeExternalUrl(source.url);
    return href ? <a href={href} key={source.article_id} rel="noreferrer" target="_blank">{source.publisher}</a>
      : <span key={source.article_id}>{source.publisher}</span>;
  })}</span>;
}

function ClaimList({ claims, record }: { claims: IncidentClaim[]; record: IncidentRecord }) {
  return claims.length ? <ol class="incident-claims">{claims.map((claim, index) => (
    <li key={`${claim.subject}-${index}`}>
      <div><span class={`evidence-state state-${claim.state}`}>{claim.state}</span><span>{claim.confidence} confidence</span></div>
      <p>{claim.statement}</p>
      <ClaimSources claim={claim} sources={record.sources} />
    </li>
  ))}</ol> : <p class="muted-copy">No source-bound finding is available for this section.</p>;
}

export function IncidentDetailView({ id }: { id: string }) {
  const resource = useResource((signal) => api.incident(id, signal), [id]);
  if (resource.loading) return <LoadingState label="Opening the incident record" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "Incident record unavailable."} />;
  const record = resource.data;
  const known = record.claims.filter((claim) => ["confirmed", "reported"].includes(claim.state));
  const assessed = record.claims.filter((claim) => ["assessed", "disputed"].includes(claim.state));
  return <div class="view incident-detail-view">
    <button class="text-button back-link" onClick={() => navigate("/threats")} type="button">Back to threats</button>
    <header class="incident-record-header">
      <div><p class="eyebrow">Breach anatomy / v{record.version || 1}</p><h1>{record.title}</h1><p>{record.summary}</p></div>
      <div class={`incident-score incident-${record.priority}`}><span>{record.state}</span><strong>{record.score}</strong><small>{record.priority} priority</small></div>
    </header>
    <dl class="incident-facts">
      <div><dt>Organization</dt><dd>{record.organization}</dd></div>
      <div><dt>First reported</dt><dd>{formattedDate(record.first_seen)}</dd></div>
      <div><dt>Independent sources</dt><dd>{record.independent_source_count}</dd></div>
      <div><dt>Last material change</dt><dd>{formattedDate(record.last_changed)}</dd></div>
    </dl>
    <div class="incident-actions button-row">
      <button class="button secondary" onClick={() => downloadText(`${record.id}.md`, incidentMarkdown(record))} type="button">Download Markdown</button>
      <button class="button secondary" onClick={() => downloadText(`${record.id}.json`, JSON.stringify(record, null, 2), "application/json")} type="button">Download JSON</button>
    </div>
    <div class="incident-detail-grid">
      <main>
        <section class="record-section"><p class="eyebrow">Established reporting</p><h2>What we know</h2><ClaimList claims={known} record={record} /></section>
        <section class="record-section"><p class="eyebrow">Analyst assessment</p><h2>How it may have happened</h2><ClaimList claims={assessed} record={record} /></section>
        <section class="record-section"><p class="eyebrow">Observed consequence</p><h2>Impact</h2>{record.impact.length ? <ul>{record.impact.map((impact) => <li key={impact}>{impact}</li>)}</ul> : <p class="muted-copy">Impact details have not been independently established.</p>}</section>
        <section class="record-section"><p class="eyebrow">Defensive use</p><h2>What to inspect</h2><p>{record.recommended_action}</p>{record.techniques.length > 0 && <ul class="technique-list">{record.techniques.map((technique) => <li key={technique.id}><code>{technique.id}</code> {technique.name}</li>)}</ul>}</section>
        <section class="record-section"><p class="eyebrow">Evidence gaps</p><h2>What remains unknown</h2>{record.open_questions?.length ? <ul>{record.open_questions.map((question) => <li key={question}>{question}</li>)}</ul> : <p>No material evidence gaps are recorded.</p>}</section>
      </main>
      <aside>
        <section class="record-side-section"><h2>Evidence sources</h2><p>{record.source_count} reports across {record.independent_source_count} independent source families.</p><ol class="record-sources">{record.sources.map((source) => {
          const href = safeExternalUrl(source.url);
          return <li key={source.article_id}>{href ? <a href={href} rel="noreferrer" target="_blank">{source.title}</a> : <strong>{source.title}</strong>}<small>{source.publisher} / {formattedDate(source.published)}</small></li>;
        })}</ol></section>
        <section class="record-side-section"><h2>Revision history</h2>{record.changes.length ? <ol class="record-timeline">{record.changes.map((change) => <li key={change.id}><time>{formattedDate(change.changed_at)}</time><div><strong>{change.summary}</strong><span>{change.field.replaceAll("_", " ")}</span></div></li>)}</ol> : <p>No material revisions recorded.</p>}</section>
      </aside>
    </div>
  </div>;
}
