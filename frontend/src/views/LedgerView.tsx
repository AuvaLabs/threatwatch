import { useEffect, useMemo, useState } from "preact/hooks";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import type { LedgerAction, LedgerChange, LedgerResponse, ThreatRecordSummary } from "../types";
import { formattedDate } from "../utils/format";

const actionLabels: Record<LedgerAction, string> = {
  patch: "Patch now",
  hunt: "Begin hunt",
  investigate: "Investigate",
  monitor: "Monitor",
};
const REGISTER_BATCH_SIZE = 20;
const API_PAGE_SIZE = 200;
const MAX_LEDGER_RECORDS = 5_000;

async function loadActiveLedger(signal: AbortSignal): Promise<LedgerResponse> {
  const records: ThreatRecordSummary[] = [];
  const changes = new Map<string, LedgerChange>();
  let first: LedgerResponse | null = null;
  let hasMore = true;
  while (hasMore && records.length < MAX_LEDGER_RECORDS) {
    const page = await api.ledger({ activity: "active", offset: records.length, limit: API_PAGE_SIZE }, signal);
    first ||= page;
    records.push(...page.records);
    page.changes.forEach((change) => changes.set(change.id, change));
    hasMore = page.has_more && page.records.length > 0;
  }
  if (!first) throw new Error("Threat ledger returned no response");
  const mergedChanges = [...changes.values()].sort((left, right) => right.changed_at.localeCompare(left.changed_at));
  return { ...first, offset: 0, limit: records.length, has_more: hasMore, records, changes: mergedChanges };
}

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
  const resource = useResource(loadActiveLedger, []);
  const [query, setQuery] = useState("");
  const [action, setAction] = useState<LedgerAction | "">("");
  const [visibleCount, setVisibleCount] = useState(REGISTER_BATCH_SIZE);
  const records = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return (resource.data?.records || []).filter((record) => {
      if (action && record.decision.action !== action) return false;
      if (!needle) return true;
      return `${record.entity_name} ${record.title} ${record.summary} ${(record.affected_products || []).join(" ")}`.toLocaleLowerCase().includes(needle);
    });
  }, [resource.data, query, action]);
  const visibleRecords = records.slice(0, visibleCount);
  const remaining = records.length - visibleRecords.length;

  useEffect(() => setVisibleCount(REGISTER_BATCH_SIZE), [query, action]);

  return <div class="view ledger-view">
    <PageHeader eyebrow="Public threat-state ledger" title="What changed" description="Living CVE and actor records that preserve evidence, uncertainty, decisions, and revision history as public reporting evolves." />
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
        {resource.data.changes.length ? <ol>{resource.data.changes.slice(0, 8).map((change) => <li key={change.id}>
          <time>{formattedDate(change.changed_at)}</time><div><strong>{change.summary}</strong><span>{change.kind.replaceAll("_", " ")} · {change.field.replaceAll("_", " ")}</span></div>
        </li>)}</ol> : <p class="quiet-empty">No assessment state changed in the current ledger run.</p>}
      </section>
      <section class="ledger-register" aria-labelledby="records-title">
        <header class="section-heading"><div><p class="eyebrow">Current assessment</p><h2 id="records-title">Living threat records</h2></div><span>Showing {visibleRecords.length} of {records.length} records</span></header>
        <div class="ledger-filter">
          <label><span>Find a record</span><input onInput={(event) => setQuery(event.currentTarget.value)} placeholder="CVE, actor, product, or report text" type="search" value={query} /></label>
          <label><span>Decision</span><select onChange={(event) => setAction(event.currentTarget.value as LedgerAction | "")} value={action}><option value="">All decisions</option><option value="patch">Patch now</option><option value="hunt">Begin hunt</option><option value="investigate">Investigate</option><option value="monitor">Monitor</option></select></label>
        </div>
        {records.length ? visibleRecords.map((record) => <RecordRow key={record.id} record={record} />) : <p class="quiet-empty">No living record matches the current filter.</p>}
        {remaining > 0 && <div class="ledger-more"><button class="text-button" onClick={() => setVisibleCount((count) => count + REGISTER_BATCH_SIZE)} type="button">Show {Math.min(remaining, REGISTER_BATCH_SIZE)} more record{Math.min(remaining, REGISTER_BATCH_SIZE) === 1 ? "" : "s"}</button></div>}
      </section>
    </>}
  </div>;
}
