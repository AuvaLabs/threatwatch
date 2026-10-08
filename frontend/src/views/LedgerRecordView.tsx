import { ErrorState, LoadingState } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { formattedDate, safeExternalUrl } from "../utils/format";

function back(event: Event): void {
  event.preventDefault();
  navigate("/ledger");
}

export function LedgerRecordView({ id }: { id: string }) {
  const resource = useResource((signal) => api.ledgerRecord(id, signal), [id]);
  if (resource.loading) return <LoadingState label="Opening living threat record" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "Threat record unavailable"} />;
  const record = resource.data;
  return <div class="view ledger-record-view">
    <a class="back-link" href="/ledger" onClick={back}>← Return to threat ledger</a>
    <header class="record-header ledger-record-header">
      <div><p class="eyebrow">{record.entity_type} · living record v{record.version}</p><h1>{record.title}</h1><p>{record.summary}</p></div>
      <div class={`record-decision decision-${record.decision.urgency}`}><span>Current decision</span><strong>{record.decision.action}</strong><p>{record.decision.rationale}</p></div>
    </header>
    <dl class="ledger-facts">
      <div><dt>First seen</dt><dd>{formattedDate(record.first_seen)}</dd></div>
      <div><dt>Last changed</dt><dd>{formattedDate(record.last_changed)}</dd></div>
      <div><dt>Independent sources</dt><dd>{record.source_count}</dd></div>
      <div><dt>Exploitation</dt><dd>{record.state.exploitation}</dd></div>
    </dl>
    <div class="ledger-detail-grid">
      <div>
        <section class="record-section"><p class="eyebrow">Evidence matrix</p><h2>What supports the assessment</h2><div class="evidence-matrix">{record.evidence.map((item) => <article key={item.key}><div><strong>{item.label}</strong><span class={`evidence-state state-${item.status}`}>{item.status.replaceAll("_", " ")}</span></div><p>{item.detail}</p></article>)}</div></section>
        <section class="record-section"><p class="eyebrow">Revision history</p><h2>How the assessment changed</h2>{record.changes.length ? <ol class="record-timeline">{record.changes.map((change) => <li key={change.id}><time>{formattedDate(change.changed_at)}</time><div><strong>{change.summary}</strong><span>{change.previous == null ? "Tracking started" : `${String(change.previous)} → ${String(change.current)}`}</span></div></li>)}</ol> : <p>No changes have been recorded.</p>}</section>
        <section class="record-section"><p class="eyebrow">Original reporting</p><h2>Sources</h2><ol class="record-sources">{record.sources.map((source) => {
          const href = safeExternalUrl(source.url);
          return <li key={source.article_id}>{href ? <a href={href} rel="noreferrer" target="_blank">{source.title}</a> : <span>{source.title}</span>}<small>{source.publisher} · {formattedDate(source.published)} · {source.source_type}</small></li>;
        })}</ol></section>
      </div>
      <aside>
        <section class="record-side-section"><p class="eyebrow">Remediation</p><h2>Defender action</h2><p>{record.remediation.required_action || "No authoritative remediation action is attached. Review the vendor advisory before acting."}</p>{record.remediation.due_date && <span class="due-date">Due date {record.remediation.due_date}</span>}</section>
        <section class="record-side-section"><p class="eyebrow">Affected technology</p><h2>Reported products</h2>{record.affected_products.length ? <ul>{record.affected_products.map((product) => <li key={product}>{product}</li>)}</ul> : <p>No structured product mapping is available.</p>}<small>ThreatWatch does not claim organizational exposure.</small></section>
        {record.vulnerability && <section class="record-side-section"><p class="eyebrow">Vulnerability context</p><h2>{record.vulnerability.cve}</h2><dl><div><dt>KEV</dt><dd>{record.vulnerability.kev ? "Listed" : "Not listed"}</dd></div><div><dt>CVSS</dt><dd>{record.vulnerability.max_cvss ?? "Unknown"}</dd></div><div><dt>EPSS</dt><dd>{record.vulnerability.max_epss == null ? "Unknown" : `${(record.vulnerability.max_epss * 100).toFixed(1)}%`}</dd></div></dl></section>}
        <section class="record-side-section"><p class="eyebrow">Open questions</p><h2>What remains unknown</h2>{record.open_questions.length ? <ul>{record.open_questions.map((question) => <li key={question}>{question}</li>)}</ul> : <p>No qualification gap is currently recorded.</p>}</section>
      </aside>
    </div>
  </div>;
}
