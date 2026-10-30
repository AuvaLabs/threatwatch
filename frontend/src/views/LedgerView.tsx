import { useEffect, useState } from "preact/hooks";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import type { LedgerAction, ThreatRecordSummary } from "../types";
import { formattedDate } from "../utils/format";

const actionLabels: Record<LedgerAction, string> = {
  patch: "Patch now",
  hunt: "Begin hunt",
  investigate: "Investigate",
  monitor: "Monitor",
};
const LEDGER_PAGE_SIZE = 12;

function follow(event: Event, path: string): void {
  event.preventDefault();
  navigate(path);
}

function RecordRow({ record }: { record: ThreatRecordSummary }) {
  const path = `/ledger/${record.id}`;
  return <article class={`ledger-row ledger-${record.decision.urgency}`}>
    <div class="ledger-decision"><strong>{actionLabels[record.decision.action]}</strong><span>{record.decision.urgency}</span></div>
    <div class="ledger-copy">
      <p class="eyebrow">{record.entity_type} · record v{record.version} · changed {formattedDate(record.last_changed)}</p>
      <h2><a href={path} onClick={(event) => follow(event, path)}>{record.title}</a></h2>
      <p>{record.summary}</p>
      <div class="ledger-signals">
        <span>{record.source_count} independent source{record.source_count === 1 ? "" : "s"}</span>
        <span>Exploitation: {record.state.exploitation}</span>
        <span>Hunt: {record.state.hunt}</span>
        {record.vulnerability?.kev && <span class="critical-signal">KEV listed</span>}
      </div>
    </div>
    <div class="ledger-open"><span>{record.decision.rationale}</span><a href={path} onClick={(event) => follow(event, path)}>Open living record</a></div>
  </article>;
}

export function LedgerView() {
  const [query, setQuery] = useState("");
  const [action, setAction] = useState<LedgerAction | "">("");
  const [entityType, setEntityType] = useState<"cve" | "actor" | "">("");
  const [offset, setOffset] = useState(0);
  const resource = useResource(
    (signal) => api.ledger({ activity: "active", q: query, action: action || undefined, type: entityType || undefined, offset, limit: LEDGER_PAGE_SIZE }, signal),
    [query, action, entityType, offset],
  );
  const records = resource.data?.records || [];

  useEffect(() => setOffset(0), [query, action, entityType]);

  return <div class="view ledger-view">
    <PageHeader eyebrow="Decision history" title="Threat ledger" description="Living CVE and actor records that preserve evidence, uncertainty, decisions, and revision history as public reporting evolves." />
    {resource.loading && <LoadingState label="Reconstructing current threat state" />}
    {resource.error && <ErrorState message={resource.error} />}
    {resource.data && <>
      <section aria-label="Ledger metrics" class="metric-grid ledger-metrics">
        <article><strong>{resource.data.run_change_count}</strong><span>Changes this run</span></article>
        <article><strong>{resource.data.summary.patch}</strong><span>Patch decisions</span></article>
        <article><strong>{resource.data.summary.qualified_hunts ?? resource.data.summary.hunt}</strong><span>Qualified hunts</span></article>
        <article><strong>{resource.data.summary.active_records}</strong><span>Active records</span></article>
      </section>
      <section class="change-register" aria-labelledby="changes-title">
        <header class="section-heading"><div><p class="eyebrow">Revision desk</p><h2 id="changes-title">Latest recorded changes</h2></div><span>{resource.data.changes.length} retained events</span></header>
        {resource.data.changes.length ? <ol>{resource.data.changes.slice(0, 5).map((change) => <li key={change.id}>
          <time>{formattedDate(change.changed_at)}</time><div><strong>{change.summary}</strong><span>{change.kind.replaceAll("_", " ")} · {change.field.replaceAll("_", " ")}</span></div>
        </li>)}</ol> : <p class="quiet-empty">No assessment state changed in the current ledger run.</p>}
      </section>
      <section class="ledger-register" aria-labelledby="records-title">
        <header class="section-heading"><div><p class="eyebrow">Current assessment</p><h2 id="records-title">Living threat records</h2></div><span>{resource.data.total ? `${offset + 1}–${Math.min(offset + records.length, resource.data.total)} of ${resource.data.total} records` : "No matching records"}</span></header>
        <div class="ledger-filter">
          <label><span>Find a record</span><input onInput={(event) => setQuery(event.currentTarget.value)} placeholder="CVE, actor, product, or report text" type="search" value={query} /></label>
          <label><span>Decision</span><select onChange={(event) => setAction(event.currentTarget.value as LedgerAction | "")} value={action}><option value="">All decisions</option><option value="patch">Patch now</option><option value="hunt">Begin hunt</option><option value="investigate">Investigate</option><option value="monitor">Monitor</option></select></label>
          <label><span>Entity</span><select onChange={(event) => setEntityType(event.currentTarget.value as "cve" | "actor" | "")} value={entityType}><option value="">All entities</option><option value="cve">Vulnerabilities</option><option value="actor">Actors</option></select></label>
        </div>
        {records.length ? records.map((record) => <RecordRow key={record.id} record={record} />) : <p class="quiet-empty">No living record matches the current filter.</p>}
        <nav aria-label="Ledger pagination" class="pagination"><button class="button secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LEDGER_PAGE_SIZE))} type="button">Previous</button><span>{resource.data.total ? `Page ${Math.floor(offset / LEDGER_PAGE_SIZE) + 1}` : "No pages"}</span><button class="button secondary" disabled={!resource.data.has_more} onClick={() => setOffset(offset + LEDGER_PAGE_SIZE)} type="button">Next</button></nav>
      </section>
    </>}
  </div>;
}
