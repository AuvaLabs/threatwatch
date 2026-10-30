import { useMemo, useState } from "preact/hooks";
import { BriefingSources } from "../components/BriefingSources";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { briefingTitle } from "../services/briefing";
import { copyText } from "../services/clipboard";
import { downloadText, operationalReport } from "../services/reports";
import type { Briefing, OperationalSummary } from "../types";
import { actionText, formattedDate } from "../utils/format";

interface ReportData { summary: OperationalSummary; briefing: Briefing | null }

async function loadReport(signal: AbortSignal): Promise<ReportData> {
  const [summary, briefing] = await Promise.allSettled([api.operations(signal), api.briefing("latest", signal)]);
  if (summary.status === "rejected") throw summary.reason;
  return { summary: summary.value, briefing: briefing.status === "fulfilled" ? briefing.value : null };
}

export function ReportsView() {
  const resource = useResource(loadReport, []);
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");
  const body = useMemo(() => resource.data ? operationalReport(resource.data.summary, resource.data.briefing) : "", [resource.data]);
  const data = resource.data;
  return <div class="view reports-view">
    <PageHeader eyebrow="Current issue" title="Reports" description="The complete operating picture for handoff, briefing, or archive." actions={data && <div class="button-row"><button class="button secondary" onClick={async () => setCopyStatus(await copyText(body) ? "copied" : "error")} type="button">{copyStatus === "copied" ? "Copied" : "Copy report"}</button><button class="button primary" onClick={() => downloadText(`threatwatch-report-${new Date().toISOString().slice(0, 10)}.md`, body)} type="button">Download Markdown</button></div>} />
    {copyStatus === "error" && <div class="notice" role="status">Clipboard access is unavailable. Download the Markdown report instead.</div>}
    {resource.loading && <LoadingState label="Preparing operational report" />}{resource.error && <ErrorState message={resource.error} />}
    {data && <>
      <nav aria-label="Report sections" class="report-index"><a href="#assessment">Assessment</a>{data.summary.incidents?.length ? <a href="#incidents">Incidents</a> : null}<a href="#actions">Actions</a><a href="#sources">Sources</a></nav>
      <article class="operational-report surface">
        <header id="assessment"><div><p class="eyebrow">Executive assessment</p><span class={`risk-label ${(data.briefing?.threat_level || "unknown").toLowerCase()}`}>{data.briefing?.threat_level || "Unclassified"}</span></div><h2>{briefingTitle(data.briefing)}</h2><p>{data.briefing?.what_happened || "Operational priorities remain available below."}</p><div class="report-edition"><time>{formattedDate(data.summary.generated_at)}</time><span>{data.briefing?.provider || "Deterministic fallback"}</span><span>{data.briefing?.reporting_window || "Current reporting window"}</span></div></header>
        <section><h3>Operating picture</h3><div class="report-metrics"><span><strong>{data.summary.metrics.critical_priorities}</strong> immediate</span><span><strong>{data.summary.metrics.major_incidents || 0}</strong> major incidents</span><span><strong>{data.summary.metrics.active_threats}</strong> threats</span></div></section>
        {!!data.summary.incidents?.length && <section id="incidents"><h3>Major incidents</h3><ol>{data.summary.incidents.map((incident) => <li key={incident.id}><a href={`/incidents/${incident.id}`} onClick={(event) => { event.preventDefault(); navigate(`/incidents/${incident.id}`); }}><strong>{incident.title}</strong></a><p>{incident.summary}</p><small>{incident.independent_source_count} independent sources / {incident.confidence} confidence</small></li>)}</ol></section>}
        <section id="actions"><h3>Priority actions</h3><ol>{data.summary.priorities.slice(0, 8).map((priority) => <li key={priority.id}><strong>{priority.title}</strong><p>{priority.recommended_action}</p></li>)}</ol></section>
        {!!data.briefing?.what_to_do?.length && <section><h3>Briefing actions</h3><ul>{data.briefing.what_to_do.map((action, index) => <li key={`${index}-${actionText(action)}`}>{actionText(action)}</li>)}</ul></section>}
        <details class="report-sources" id="sources" open={typeof matchMedia === "undefined" || !matchMedia("(max-width: 760px)").matches}><summary>Sources and citations</summary><BriefingSources briefing={data.briefing} label={false} /></details>
        <footer>{data.summary.exposure.disclaimer}</footer>
      </article>
    </>}
  </div>;
}
