import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { formattedDate } from "../utils/format";

export function WatchlistsView() {
  const resource = useResource(api.watchlist, []);
  return (
    <div class="view watchlists-view">
      <PageHeader eyebrow="Organization context" title="Watchlists" description="Keep critical brands, vendors, and technologies visible across the intelligence stream." />
      {resource.loading && <LoadingState label="Loading monitored entities" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && (
        <div class="watch-grid">
          <section class="surface watch-panel">
            <div class="section-heading"><div><p class="eyebrow">Organizations</p><h2>Watched brands</h2></div><span>{resource.data.brands.length}</span></div>
            {resource.data.brands.length ? <ul class="watch-items">{resource.data.brands.map((brand) => <li key={brand}><span class="signal-dot" />{brand}</li>)}</ul> : <div class="quiet-empty"><strong>No brand watchlist configured</strong><p>Add organization names through the authenticated watchlist API to surface matching reports.</p></div>}
          </section>
          <section class="surface watch-panel">
            <div class="section-heading"><div><p class="eyebrow">Technology</p><h2>Watched assets</h2></div><span>{resource.data.assets.length}</span></div>
            {resource.data.assets.length ? <ul class="watch-items">{resource.data.assets.map((asset) => <li key={asset}><span class="signal-dot" />{asset}</li>)}</ul> : <div class="quiet-empty"><strong>No technology watchlist configured</strong><p>Add products, platforms, and infrastructure through the authenticated watchlist API.</p></div>}
          </section>
          <section class="surface watch-guidance">
            <p class="eyebrow">Configuration</p><h2>Controlled write access</h2>
            <p>{resource.data.write_enabled ? "This deployment accepts authenticated watchlist updates." : "Watchlist writes are disabled on this deployment. Read access remains available."}</p>
            <dl class="fact-list"><div><dt>Last updated</dt><dd>{formattedDate(resource.data.updated_at)}</dd></div><div><dt>Suggested vendors</dt><dd>{resource.data.suggest_list?.length || 0}</dd></div></dl>
          </section>
        </div>
      )}
    </div>
  );
}
