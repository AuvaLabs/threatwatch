import { useEffect, useState } from "preact/hooks";
import { ArticleList } from "../components/ArticleList";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";

const categories = ["", "Data Breach", "Ransomware", "Malware", "Phishing", "Threat Intelligence Report", "Cloud Security Incident"];
const regions = ["", "Global", "NA", "EMEA", "MENA", "APAC", "LATAM"];
const initialParam = (name: string) => new URLSearchParams(location.search).get(name) || "";

export function SourcesView() {
  const [q, setQ] = useState(() => initialParam("q"));
  const [category, setCategory] = useState(() => initialParam("category"));
  const [region, setRegion] = useState(() => initialParam("region"));
  const [offset, setOffset] = useState(0);
  const limit = 30;
  const resource = useResource((signal) => api.articles({ view: "news", q, category, region, offset, limit }, signal), [q, category, region, offset]);
  useEffect(() => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (category) params.set("category", category);
    if (region) params.set("region", region);
    history.replaceState({}, "", `/sources${params.size ? `?${params}` : ""}`);
  }, [q, category, region]);
  const reset = () => { setQ(""); setCategory(""); setRegion(""); setOffset(0); };
  return <div class="view sources-view">
    <PageHeader eyebrow="Evidence library" title="Sources" description="The underlying public reporting used to build threats, priorities, hunts, and reports." />
    <div class="notice" role="note">Source reporting is evidence, not a final assessment. Validate consequential claims against the original publisher.</div>
    <form class="filter-bar" onSubmit={(event) => event.preventDefault()}>
      <label class="search-field"><span>Search evidence</span><input onInput={(event) => { setQ(event.currentTarget.value); setOffset(0); }} placeholder="Actor, organization, CVE, or topic" type="search" value={q} /></label>
      <label><span>Topic</span><select onChange={(event) => { setCategory(event.currentTarget.value); setOffset(0); }} value={category}>{categories.map((item) => <option key={item || "all"} value={item}>{item || "All topics"}</option>)}</select></label>
      <label><span>Region</span><select onChange={(event) => { setRegion(event.currentTarget.value); setOffset(0); }} value={region}>{regions.map((item) => <option key={item || "all"} value={item}>{item || "All regions"}</option>)}</select></label>
      {(q || category || region) && <button class="button secondary" onClick={reset} type="button">Reset</button>}
    </form>
    {resource.loading && <LoadingState />}{resource.error && <ErrorState message={resource.error} />}
    {resource.data && <section aria-label="Source reports"><div class="results-summary"><strong>{resource.data.total.toLocaleString()}</strong> source records <span>Continuously collected and deduplicated</span></div><ArticleList articles={resource.data.articles} /><nav aria-label="Sources pagination" class="pagination"><button class="button secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} type="button">Previous</button><span>{offset + 1}–{Math.min(offset + limit, resource.data.total)} of {resource.data.total}</span><button class="button secondary" disabled={!resource.data.has_more} onClick={() => setOffset(offset + limit)} type="button">Next</button></nav></section>}
  </div>;
}
