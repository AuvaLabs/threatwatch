import { useState } from "preact/hooks";
import { BriefingSources } from "../components/BriefingSources";
import { ErrorState, LoadingState } from "../components/PageState";
import { PriorityCard } from "../components/PriorityCard";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { briefingTitle } from "../services/briefing";
import { investigationFromPriority } from "../services/operations";
import { saveInvestigation } from "../services/workspace";
import type { Briefing, LedgerResponse, OperationalSummary } from "../types";
import { excerpt, formattedDate } from "../utils/format";

interface MissionData { operations: OperationalSummary; briefing: Briefing | null; ledger: LedgerResponse | null }

async function loadMission(signal: AbortSignal): Promise<MissionData> {
  const [operations, briefing, ledger, ledgerChanges] = await Promise.allSettled([
    api.operations(signal), api.briefing("latest", signal),
    api.ledger({ activity: "active", limit: 1 }, signal), api.ledgerChanges(signal),
  ]);
  if (operations.status === "rejected") throw operations.reason;
  const ledgerValue = ledger.status === "fulfilled" ? ledger.value : null;
  return {
    operations: operations.value,
    briefing: briefing.status === "fulfilled" ? briefing.value : null,
    ledger: ledgerValue && ledgerChanges.status === "fulfilled"
      ? { ...ledgerValue, changes: ledgerChanges.value.changes }
      : ledgerValue,
  };
}

export function MissionControlView() {
  const resource = useResource(loadMission, []);
  const [notice, setNotice] = useState("");
  if (resource.loading) return <LoadingState label="Building the operational picture" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "Operational priorities are unavailable."} />;
  const { operations, briefing, ledger } = resource.data;
  const track = (priority: OperationalSummary["priorities"][number]) => {
    try {
      const workspace = saveInvestigation(investigationFromPriority(priority));
      setNotice(`${priority.title} is tracked in your local workspace (${workspace.investigations.length} total).`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The investigation could not be saved.");
    }
  };
  return (
    <div class="view mission-view">
      <header class="mission-header">
        <div><p class="eyebrow">Public intelligence desk</p><h1>Today</h1><p>Material changes in threat state, followed by the decisions they support.</p></div>
        <div class="mission-time"><span>Picture generated</span><time>{formattedDate(operations.generated_at)}</time></div>
      </header>
      {notice && <div class="notice" role="status">{notice} <button class="text-button" onClick={() => navigate("/investigations")} type="button">Open workspace</button></div>}
      <section aria-label="Operational metrics" class="metric-grid">
        <article><strong>{ledger?.run_change_count ?? 0}</strong><span>Assessment changes</span></article>
        <article><strong>{ledger?.summary.patch ?? operations.metrics.critical_priorities}</strong><span>Patch decisions</span></article>
        <article><strong>{ledger?.summary.qualified_hunts ?? ledger?.summary.hunt ?? 0}</strong><span>Qualified hunts</span></article>
        <article><strong>{ledger?.summary.active_records ?? operations.metrics.active_threats}</strong><span>Living records</span></article>
      </section>
      <section class="command-brief surface">
        <div><p class="eyebrow">Command brief</p><h2>{briefingTitle(briefing)}</h2><p>{excerpt(briefing?.what_happened, 340) || "Use the decision queue below while narrative enrichment recovers."}</p><BriefingSources briefing={briefing} compact limit={3} /></div>
        <div class="command-brief-action"><span>{briefing?.threat_level || "Unclassified"}</span><button class="button secondary" onClick={() => navigate("/reports")} type="button">Open report</button></div>
      </section>
      <section class="today-changes" aria-labelledby="today-changes-title">
        <div class="section-heading"><div><p class="eyebrow">Revision register</p><h2 id="today-changes-title">What changed today</h2></div><a href="/ledger" onClick={(event) => { event.preventDefault(); navigate("/ledger"); }}>Open the full ledger</a></div>
        {ledger?.changes.length ? <ol>{ledger.changes.slice(0, 5).map((change) => <li key={change.id}><time>{formattedDate(change.changed_at)}</time><strong>{change.summary}</strong></li>)}</ol> : <div class="quiet-empty surface"><strong>No assessment changes in the latest run</strong><p>Living records remain available in the public threat ledger.</p></div>}
      </section>
      <section aria-labelledby="queue-title" class="decision-queue">
        <div class="section-heading"><div><p class="eyebrow">Working register</p><h2 id="queue-title">Decision queue</h2></div><span>{operations.metrics.decision_queue} actionable items</span></div>
        {operations.priorities.length ? operations.priorities.map((priority) => <PriorityCard key={priority.id} onInvestigate={track} priority={priority} />) : <div class="quiet-empty surface"><strong>No elevated priorities</strong><p>Signals are being monitored. No item currently passes the operational threshold.</p></div>}
      </section>
    </div>
  );
}
