import { useEffect, useMemo, useState } from "preact/hooks";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { formattedDate } from "../utils/format";

const INCIDENT_BATCH_SIZE = 12;

export function ThreatsView() {
  const resource = useResource(api.incidents, []);
  const [query, setQuery] = useState("");
  const [eventType, setEventType] = useState("");
  const [priority, setPriority] = useState("");
  const [state, setState] = useState("corroborated");
  const [visibleCount, setVisibleCount] = useState(INCIDENT_BATCH_SIZE);
  const records = resource.data?.records || [];
  const eventTypes = useMemo(() => [...new Set(records.map((record) => record.event_type))].sort(), [records]);
  const incidents = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return records.filter((incident) => {
      if (state && incident.state !== state) return false;
      if (eventType && incident.event_type !== eventType) return false;
      if (priority && incident.priority !== priority) return false;
      return !needle || `${incident.organization} ${incident.title} ${incident.summary}`.toLocaleLowerCase().includes(needle);
    });
  }, [records, query, eventType, priority, state]);
  const visible = incidents.slice(0, visibleCount);
  const remaining = incidents.length - visible.length;

  useEffect(() => setVisibleCount(INCIDENT_BATCH_SIZE), [query, eventType, priority, state]);

  return <div class="view threats-view">
    <PageHeader eyebrow="Breach anatomy" title="Incidents" description="Evidence-linked incident records that separate established reporting, assessment, impact, and remaining uncertainty." />
    <form class="filter-bar incident-filter" onSubmit={(event) => event.preventDefault()}>
      <label class="search-field"><span>Find an incident</span><input onInput={(event) => setQuery(event.currentTarget.value)} placeholder="Organization, breach, ransomware, or impact" type="search" value={query} /></label>
      <label><span>Event</span><select onChange={(event) => setEventType(event.currentTarget.value)} value={eventType}><option value="">All events</option>{eventTypes.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
      <label><span>Priority</span><select onChange={(event) => setPriority(event.currentTarget.value)} value={priority}><option value="">All priorities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label><span>State</span><select onChange={(event) => setState(event.currentTarget.value)} value={state}><option value="corroborated">Corroborated</option><option value="developing">Developing</option><option value="">All states</option></select></label>
    </form>
    {resource.loading && <LoadingState label="Correlating incident evidence" />}
    {resource.error && <ErrorState message={resource.error} />}
    {resource.data && <section class="incident-register" aria-labelledby="incident-register-title">
      <div class="section-heading"><div><p class="eyebrow">Living incident records</p><h2 id="incident-register-title">Current investigations</h2></div><span>Showing {visible.length} of {incidents.length}</span></div>
      {visible.length ? <div class="incident-register-list">{visible.map((incident) => <article class="incident-register-row" key={incident.id}>
        <div><span class={`status-pill ${incident.priority}`}>{incident.priority}</span><strong>{incident.score}</strong></div>
        <div><p class="eyebrow">{incident.organization} / {incident.state}</p><h3>{incident.title}</h3><p>{incident.summary}</p><small>{incident.independent_source_count} independent sources / updated {formattedDate(incident.last_updated)}</small></div>
        <a class="button primary" href={`/incidents/${incident.id}`} onClick={(event) => { event.preventDefault(); navigate(`/incidents/${incident.id}`); }}>Open investigation</a>
      </article>)}</div> : <EmptyState title="No incidents matched">Clear one or more filters or review developing records.</EmptyState>}
      {remaining > 0 && <div class="ledger-more"><button class="text-button" onClick={() => setVisibleCount((count) => count + INCIDENT_BATCH_SIZE)} type="button">Show {Math.min(remaining, INCIDENT_BATCH_SIZE)} more incident{Math.min(remaining, INCIDENT_BATCH_SIZE) === 1 ? "" : "s"}</button></div>}
    </section>}
  </div>;
}
