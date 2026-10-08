import { useMemo, useState } from "preact/hooks";
import { BriefingSources } from "../components/BriefingSources";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
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
  return <div class="view reports-view">
    <PageHeader eyebrow="Current issue" title="Reports" description="The current operating picture, formatted for handoff, briefing, or archive." actions={resource.data && <div class="button-row"><button class="button secondary" onClick={async () => setCopyStatus(await copyText(body) ? "copied" : "error")} type="button">{copyStatus === "copied" ? "Copied" : "Copy report"}</button><button class="button primary" onClick={() => downloadText(`threatwatch-report-${new Date().toISOString().slice(0, 10)}.md`, body)} type="button">Download Markdown</button></div>} />
    {copyStatus === "error" && <div class="notice" role="status">Clipboard access is unavailable. Download the Markdown report instead.</div>}
    {resource.loading && <LoadingState label="Preparing operational report" />}{resource.error && <ErrorState message={resource.error} />}
    {resource.data && <article class="operational-report surface"><header><div><p class="eyebrow">Executive assessment</p><span class={`risk-label ${(resource.data.briefing?.threat_level || "unknown").toLowerCase()}`}>{resource.data.briefing?.threat_level || "Unclassified"}</span></div><h2>{briefingTitle(resource.data.briefing)}</h2><p>{resource.data.briefing?.what_happened || "Operational priorities remain available below."}</p><time>{formattedDate(resource.data.summary.generated_at)}</time></header><section><h3>Operating picture</h3><div class="report-metrics"><span><strong>{resource.data.summary.metrics.critical_priorities}</strong> immediate</span><span><strong>{resource.data.summary.metrics.watchlist_matches}</strong> watchlist matches</span><span><strong>{resource.data.summary.metrics.active_threats}</strong> threats</span></div></section><section><h3>Priority actions</h3><ol>{resource.data.summary.priorities.slice(0, 8).map((priority) => <li key={priority.id}><strong>{priority.title}</strong><p>{priority.recommended_action}</p></li>)}</ol></section>{resource.data.briefing?.what_to_do?.length && <section><h3>Briefing actions</h3><ul>{resource.data.briefing.what_to_do.map((action, index) => <li key={`${index}-${actionText(action)}`}>{actionText(action)}</li>)}</ul></section>}<section><h3>Sources</h3><BriefingSources briefing={resource.data.briefing} label={false} /></section><footer>{resource.data.summary.exposure.disclaimer}</footer></article>}
  </div>;
}
