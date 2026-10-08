import { useState } from "preact/hooks";
import { ErrorState, LoadingState } from "../components/PageState";
import { PriorityCard } from "../components/PriorityCard";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { investigationFromPriority } from "../services/operations";
import { saveInvestigation } from "../services/workspace";
import type { Briefing, OperationalSummary } from "../types";
import { excerpt, formattedDate } from "../utils/format";

interface MissionData { operations: OperationalSummary; briefing: Briefing | null }

async function loadMission(signal: AbortSignal): Promise<MissionData> {
  const [operations, briefing] = await Promise.allSettled([api.operations(signal), api.briefing("latest", signal)]);
  if (operations.status === "rejected") throw operations.reason;
  return { operations: operations.value, briefing: briefing.status === "fulfilled" ? briefing.value : null };
}

export function MissionControlView() {
  const resource = useResource(loadMission, []);
  const [notice, setNotice] = useState("");
  if (resource.loading) return <LoadingState label="Building the operational picture" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "Operational priorities are unavailable."} />;
  const { operations, briefing } = resource.data;
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
        <div><p class="eyebrow">Desk / current</p><h1>Mission Control</h1><p>One working queue for patching, hunting, investigation, and watch.</p></div>
        <div class="mission-time"><span>Picture generated</span><time>{formattedDate(operations.generated_at)}</time></div>
      </header>
      {notice && <div class="notice" role="status">{notice} <button class="text-button" onClick={() => navigate("/investigations")} type="button">Open workspace</button></div>}
      <section aria-label="Operational metrics" class="metric-grid">
        <article><strong>{operations.metrics.critical_priorities}</strong><span>Immediate decisions</span></article>
        <article><strong>{operations.metrics.watchlist_matches}</strong><span>Watchlist matches</span></article>
        <article><strong>{operations.metrics.kev_records}</strong><span>Known exploited records</span></article>
        <article><strong>{operations.metrics.active_threats}</strong><span>Correlated threats</span></article>
      </section>
      <section class="command-brief surface">
        <div><p class="eyebrow">Command brief</p><h2>{briefing?.headline || "Narrative briefing unavailable"}</h2><p>{excerpt(briefing?.what_happened, 340) || "Use the decision queue below while narrative enrichment recovers."}</p></div>
        <div class="command-brief-action"><span>{briefing?.threat_level || "Unclassified"}</span><button class="button secondary" onClick={() => navigate("/reports")} type="button">Open report</button></div>
      </section>
      <section aria-labelledby="queue-title" class="decision-queue">
        <div class="section-heading"><div><p class="eyebrow">Working register</p><h2 id="queue-title">Decision queue</h2></div><span>{operations.metrics.decision_queue} actionable items</span></div>
        {operations.priorities.length ? operations.priorities.map((priority) => <PriorityCard key={priority.id} onInvestigate={track} priority={priority} />) : <div class="quiet-empty surface"><strong>No elevated priorities</strong><p>Signals are being monitored. No item currently passes the operational threshold.</p></div>}
      </section>
    </div>
  );
}
