import type { OperationalPriority } from "../types";
import { navigate } from "../router";
import { actionLabel, urgencyLabel } from "../services/operations";

export function PriorityCard({ priority, onInvestigate }: {
  priority: OperationalPriority;
  onInvestigate?: (priority: OperationalPriority) => void;
}) {
  const evidenceCount = priority.evidence.cves.length + priority.evidence.techniques.length + priority.evidence.ioc_count;
  return (
    <article class={`priority-card surface urgency-${priority.urgency}`}>
      <div class="priority-score"><strong>{priority.score}</strong><span>priority</span></div>
      <div class="priority-copy">
        <div class="priority-labels">
          <span class={`urgency-pill ${priority.urgency}`}>{urgencyLabel(priority.urgency)}</span>
          <span>{actionLabel(priority.action_type)}</span>
          {priority.watchlist_matches.length > 0 && <span class="watch-match">Watchlist match</span>}
        </div>
        <h2>{priority.title}</h2>
        <p>{priority.summary}</p>
        <div class="reason-list">{priority.reasons.slice(0, 3).map((reason) => <span key={reason}>{reason}</span>)}</div>
        <p class="recommended-action"><strong>Next action:</strong> {priority.recommended_action}</p>
      </div>
      <div class="priority-actions">
        <span>{evidenceCount} evidence points</span>
        {onInvestigate && <button class="button primary" onClick={() => onInvestigate(priority)} type="button">Open investigation</button>}
        <button class="button secondary" onClick={() => navigate(`/sources?q=${encodeURIComponent(priority.title)}`)} type="button">Review sources</button>
      </div>
    </article>
  );
}
