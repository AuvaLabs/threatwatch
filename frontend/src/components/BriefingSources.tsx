import { briefingSources, sourceHref, sourcePublisher, sourceTitle } from "../services/briefing";
import type { Briefing } from "../types";

export function BriefingSources({ briefing, compact = false, label = "Evidence sources", limit }: {
  briefing: Briefing | null | undefined;
  compact?: boolean;
  label?: string | false;
  limit?: number;
}) {
  const allSources = briefingSources(briefing);
  const visibleSources = limit === undefined ? allSources : allSources.slice(0, limit);
  const remaining = allSources.length - visibleSources.length;
  return <div class={`briefing-sources${compact ? " compact" : ""}`}>
    {label !== false && <p class="eyebrow">{label}</p>}
    {visibleSources.length ? <ol>
      {visibleSources.map((source) => {
        const href = sourceHref(source.link);
        return <li key={source.index}>
          <span class="source-index">[{source.index}]</span>
          <div>{href
            ? <a href={href} rel="noopener noreferrer" target="_blank">{sourceTitle(source)}</a>
            : <span>{sourceTitle(source)}</span>}
            <small>{sourcePublisher(source)}</small>
          </div>
        </li>;
      })}
    </ol> : <p class="source-unavailable">Citation details are unavailable for this briefing.</p>}
    {remaining > 0 && <span class="source-more">+{remaining} more in the full report</span>}
  </div>;
}
