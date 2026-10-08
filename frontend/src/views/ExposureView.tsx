import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { PriorityCard } from "../components/PriorityCard";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";

export function ExposureView() {
  const resource = useResource(api.operations, []);
  return (
    <div class="view exposure-view">
      <PageHeader eyebrow="Organization context" title="Exposure" description="Connect external threat evidence to the brands and technologies you monitor." />
      {resource.loading && <LoadingState label="Evaluating watchlist relevance" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && <>
        <div class="notice warning" role="note"><strong>Relevance is not exposure.</strong> {resource.data.exposure.disclaimer}</div>
        <section class="exposure-layout">
          <article class="surface exposure-inventory"><p class="eyebrow">Monitoring scope</p><h2>Organization watchlist</h2><div><h3>Brands</h3>{resource.data.exposure.brands.length ? <div class="chip-list">{resource.data.exposure.brands.map((item) => <span class="tag" key={item}>{item}</span>)}</div> : <p>No brands configured.</p>}</div><div><h3>Technologies and assets</h3>{resource.data.exposure.assets.length ? <div class="chip-list">{resource.data.exposure.assets.map((item) => <span class="tag" key={item}>{item}</span>)}</div> : <p>No technologies configured.</p>}</div></article>
          <article class="surface exposure-summary"><p class="eyebrow">Potential relevance</p><strong>{resource.data.exposure.matches.length}</strong><h2>priorities match monitored terms</h2><p>Validate asset ownership, version, reachability, and controls before treating a match as confirmed exposure.</p></article>
        </section>
        <section><div class="section-heading"><div><p class="eyebrow">Evidence requiring validation</p><h2>Relevant priorities</h2></div></div>{resource.data.exposure.matches.length ? resource.data.exposure.matches.map((priority) => <PriorityCard key={priority.id} priority={priority} />) : <div class="quiet-empty surface"><strong>No watchlist matches</strong><p>Configure monitored brands and technologies through the protected watchlist API.</p></div>}</section>
      </>}
    </div>
  );
}
