import { useState } from "preact/hooks";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { sourceHref } from "../services/briefing";
import { formattedDate } from "../utils/format";
import { ErrorState, LoadingState } from "./PageState";

const PAGE_SIZE = 8;

export function OfficialAdvisories() {
  const resource = useResource(api.advisories, []);
  const [visible, setVisible] = useState(PAGE_SIZE);
  const advisories = resource.data?.advisories ?? [];
  return (
    <section class="official-advisories" aria-labelledby="official-advisories-heading">
      <div class="section-heading"><div><h2 id="official-advisories-heading">Official advisories</h2></div></div>
      {resource.loading && <LoadingState label="Loading official advisories" />}
      {resource.error && <ErrorState message="Official advisories are temporarily unavailable." />}
      {resource.data && (advisories.length ? <>
        <ul class="official-advisory-list">
          {advisories.slice(0, visible).map((item) => {
            const date = item.updated_at || item.published_at;
            const href = sourceHref(item.url);
            return (
              <li key={item.id}>
                <span>{item.source}{date && <> · {item.updated_at ? "Updated" : "Published"} <time dateTime={date}>{formattedDate(date)}</time></>}</span>
                {href ? <a href={href} target="_blank" rel="noopener noreferrer">{item.title}</a> : <strong>{item.title}</strong>}
              </li>
            );
          })}
        </ul>
        {visible < advisories.length && <button class="button secondary" type="button" onClick={() => setVisible(visible + PAGE_SIZE)}>Show more advisories</button>}
      </> : <div class="quiet-empty surface"><strong>No recent official advisories</strong></div>)}
    </section>
  );
}
