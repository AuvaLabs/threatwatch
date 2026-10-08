import { useState } from "preact/hooks";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { copyText } from "../services/clipboard";
import { huntPack } from "../services/operations";
import type { HuntRecord } from "../types";
import { formattedDate, safeExternalUrl } from "../utils/format";

function EvidenceList({ hunt }: { hunt: HuntRecord }) {
  return <div class="hunt-evidence">
    <section>
      <h3>Observables</h3>
      {hunt.observables.length ? <div class="observable-table" role="table" aria-label="Hunt observables">
        {hunt.observables.map((observable) => <div class="observable-row" role="row" key={`${observable.type}:${observable.value}`}>
          <code>{observable.value}</code><span>{observable.type}</span><span>{observable.disposition}</span><span>{observable.sources.length} source{observable.sources.length === 1 ? "" : "s"}</span>
        </div>)}
      </div> : <p class="muted-copy">No observable has passed validation yet.</p>}
    </section>
    <section>
      <h3>ATT&amp;CK behavior</h3>
      {hunt.techniques.length ? <ul class="compact-list">{hunt.techniques.map((technique) => <li key={technique.id}><strong>{technique.id}</strong> {technique.name}{technique.tactic && <small>{technique.tactic}</small>}</li>)}</ul> : <p class="muted-copy">No behavior mapping is supported by the current reports.</p>}
    </section>
  </div>;
}

function HuntDetails({ hunt }: { hunt: HuntRecord }) {
  return <details class="hunt-package">
    <summary>Open analyst package</summary>
    <div class="hunt-package-body">
      <section><h3>Hunt hypothesis</h3><p>{hunt.hypothesis}</p></section>
      <EvidenceList hunt={hunt} />
      <section><h3>Telemetry to collect</h3>{hunt.telemetry.length ? <ul>{hunt.telemetry.map((value) => <li key={value}>{value}</li>)}</ul> : <p class="muted-copy">Telemetry requirements will appear after actionable evidence is validated.</p>}</section>
      {hunt.queries.length > 0 && <section><h3>Starter queries</h3>{hunt.queries.map((query) => <details class="query-block" key={query.name}><summary>{query.name} <span>{query.language}</span></summary><p>{query.telemetry}</p><pre>{query.query}</pre></details>)}</section>}
      <section><h3>Analyst sequence</h3><ol>{hunt.triage_steps.map((value) => <li key={value}>{value}</li>)}</ol></section>
      <section><h3>Source reporting</h3><ol class="hunt-sources">{hunt.sources.map((source) => {
        const href = safeExternalUrl(source.url);
        return <li key={source.article_id}>{href ? <a href={href} rel="noreferrer" target="_blank">{source.title}</a> : <span>{source.title}</span>}<small>{source.publisher} · {formattedDate(source.published)}</small></li>;
      })}</ol></section>
      {hunt.false_positives.length > 0 && <section><h3>False-positive checks</h3><ul>{hunt.false_positives.map((value) => <li key={value}>{value}</li>)}</ul></section>}
      {hunt.limitations.length > 0 && <section class="hunt-limitations"><h3>What is still missing</h3><ul>{hunt.limitations.map((value) => <li key={value}>{value}</li>)}</ul></section>}
    </div>
  </details>;
}

function HuntCard({ hunt, copied, onCopy }: { hunt: HuntRecord; copied: string; onCopy: (hunt: HuntRecord) => void }) {
  const confirmed = hunt.observables.filter((item) => item.disposition === "confirmed").length;
  return <article class={`hunt-card surface hunt-${hunt.status}`}>
    <div class="hunt-card-head"><span class={`hunt-status ${hunt.status}`}>{hunt.status === "qualified" ? "Ready for validation" : "Developing lead"}</span><span>{hunt.readiness_score}/100 readiness</span></div>
    <p class="eyebrow">{hunt.entity_type} · first seen {formattedDate(hunt.first_seen)}</p>
    <h2>{hunt.title}</h2><p>{hunt.summary}</p>
    {hunt.vulnerability && (hunt.vulnerability.kev || hunt.vulnerability.max_cvss != null || hunt.vulnerability.max_epss != null) && <div class="hunt-risk-context">
      {hunt.vulnerability.kev && <span>KEV listed</span>}
      {hunt.vulnerability.max_cvss != null && <span>CVSS {hunt.vulnerability.max_cvss}</span>}
      {hunt.vulnerability.max_epss != null && <span>EPSS {(hunt.vulnerability.max_epss * 100).toFixed(1)}%</span>}
    </div>}
    <dl class="hunt-metrics"><div><dt>Reports</dt><dd>{hunt.report_count}</dd></div><div><dt>Publishers</dt><dd>{hunt.source_count}</dd></div><div><dt>Observables</dt><dd>{hunt.observables.length}</dd></div><div><dt>Confirmed</dt><dd>{confirmed}</dd></div></dl>
    <div class="hunt-basis"><strong>Evidence basis</strong><ul>{hunt.why_qualified.map((reason) => <li key={reason}>{reason}</li>)}</ul></div>
    <HuntDetails hunt={hunt} />
    <button class="button primary" disabled={hunt.status !== "qualified"} onClick={() => onCopy(hunt)} type="button">{copied === hunt.id ? "Copied" : hunt.status === "qualified" ? "Copy hunt package" : "Awaiting evidence"}</button>
  </article>;
}

export function HuntsView() {
  const resource = useResource(api.hunts, []);
  const [copied, setCopied] = useState("");
  const copy = async (hunt: HuntRecord) => setCopied(await copyText(huntPack(hunt)) ? hunt.id : "error");
  const qualified = resource.data?.hunts.filter((hunt) => hunt.status === "qualified") || [];
  const leads = resource.data?.hunts.filter((hunt) => hunt.status === "lead") || [];
  return <div class="view hunts-view">
    <PageHeader eyebrow="Evidence-gated hunt desk" title="Hunts" description="Correlated reporting becomes a hunt only after its observables, behavior, provenance, and source independence pass a readiness gate." />
    <div class="notice warning" role="note"><strong>Analyst validation required.</strong> Queries are starting points. Check scope, syntax, timestamps, and local context before production use.</div>
    {copied === "error" && <div class="notice" role="status">Clipboard access is unavailable. Open the analyst package and copy the text manually.</div>}
    {resource.loading && <LoadingState label="Correlating hunt evidence" />}{resource.error && <ErrorState message={resource.error} />}
    {!resource.loading && !resource.error && <>
      <section class="hunt-section"><header class="section-heading"><div><p class="eyebrow">Qualified packages</p><h2>Ready for analyst validation</h2></div><strong>{qualified.length}</strong></header>
        {qualified.length ? <div class="hunt-grid">{qualified.map((hunt) => <HuntCard hunt={hunt} copied={copied} onCopy={copy} key={hunt.id} />)}</div> : <EmptyState title="No hunt has passed the evidence gate">Developing leads remain visible below, but ThreatWatch will not label them as hunt packages until they have independent reporting, actionable observables, and mapped behavior.</EmptyState>}
      </section>
      <section class="hunt-section hunt-leads"><header class="section-heading"><div><p class="eyebrow">Evidence queue</p><h2>Developing leads</h2></div><strong>{leads.length}</strong></header>
        {leads.length ? <div class="hunt-grid">{leads.map((hunt) => <HuntCard hunt={hunt} copied={copied} onCopy={copy} key={hunt.id} />)}</div> : <p class="quiet-empty">No developing leads in the current reporting window.</p>}
      </section>
    </>}
  </div>;
}
