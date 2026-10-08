import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";

export function ApiView() {
  const resource = useResource(api.openApi, []);
  return (
    <div class="view api-view">
      <PageHeader eyebrow="Automation" title="ThreatWatch API" description="Stable, source-linked intelligence for internal tools, feeds, and analyst workflows." actions={<a class="button primary" href="/api/stix">Download STIX</a>} />
      <section class="api-intro surface"><div><p class="eyebrow">Base path</p><code>{location.origin}/api/v1</code></div><p>Public read endpoints support conditional requests and compressed responses. Operational health and watchlist routes use restricted cross-origin access.</p></section>
      {resource.loading && <LoadingState label="Loading API contract" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && <div class="endpoint-list">{Object.entries(resource.data.paths).map(([path, methods]) => Object.entries(methods).map(([method, operation]) => <article class="endpoint-row" key={`${method}-${path}`}><span class="method">{method.toUpperCase()}</span><code>{path}</code><p>{operation.summary || "ThreatWatch API operation"}</p><button class="text-button" onClick={() => navigator.clipboard.writeText(`${location.origin}${path.replace("{id}", "ARTICLE_ID").replace("{region}", "latest")}`)} type="button">Copy URL</button></article>))}</div>}
      <section class="ai-ready surface"><p class="eyebrow">AI integration contract</p><h2>Grounded intelligence by design</h2><p>Future assistant responses will carry citations, generation time, provider status, confidence, and stale-result metadata. Live synthesis will remain feature-gated and rate-limited so the core intelligence feed never depends on an AI provider.</p></section>
    </div>
  );
}
