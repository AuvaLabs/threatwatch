import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { copyText } from "../services/clipboard";

async function loadAutomation(signal: AbortSignal) {
  const [contract, health] = await Promise.all([api.openApi(signal), api.health(signal)]);
  return { contract, health };
}

export function AutomationView() {
  const resource = useResource(loadAutomation, []);
  return <div class="view automation-view">
    <PageHeader eyebrow="Machine-readable intelligence" title="Automation" description="Connect ThreatWatch evidence and priorities to internal workflows through stable interfaces." actions={<a class="button primary" href="/api/stix">Download STIX</a>} />
    {resource.loading && <LoadingState label="Loading automation contract" />}{resource.error && <ErrorState message={resource.error} />}
    {resource.data && <>
      <section class="automation-status"><article class="surface"><span class={`health-indicator ${resource.data.health.status}`} /><div><strong>REST API</strong><p>{resource.data.health.status === "ok" ? "Operational" : `Available with ${resource.data.health.status} dependencies`}</p></div></article><article class="surface"><strong>STIX 2.1</strong><p>Download current machine-readable indicators and objects.</p></article><article class="surface"><strong>RSS feed</strong><p><a href="/feed.xml">Subscribe to source reporting</a></p></article></section>
      <section><div class="section-heading"><div><p class="eyebrow">OpenAPI contract</p><h2>Available endpoints</h2></div><code>{location.origin}/api/v1</code></div><div class="endpoint-list">{Object.entries(resource.data.contract.paths).map(([path, methods]) => Object.entries(methods).map(([method, operation]) => <article class="endpoint-row" key={`${method}-${path}`}><span class="method">{method.toUpperCase()}</span><code>{path}</code><p>{operation.summary || "ThreatWatch API operation"}</p><button class="text-button" onClick={() => copyText(`${location.origin}${path.replace("{id}", "ARTICLE_ID").replace("{region}", "latest")}`)} type="button">Copy URL</button></article>))}</div></section>
      <section class="surface integration-note"><p class="eyebrow">Integration boundary</p><h2>Grounded by default</h2><p>The API exposes evidence, citations, generation time, and health state. Consumers should preserve these fields and must not silently treat stale or degraded enrichment as current analysis.</p></section>
    </>}
  </div>;
}
