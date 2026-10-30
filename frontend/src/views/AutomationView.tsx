import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { copyText } from "../services/clipboard";

async function loadAutomation(signal: AbortSignal) {
  const [contract, health] = await Promise.all([api.openApi(signal), api.health(signal)]);
  return { contract, health };
}

function endpointGroup(path: string): string {
  if (path.includes("briefing") || path.includes("intelligence") || path.includes("top-stories")) return "Intelligence";
  if (path.includes("incidents")) return "Incidents";
  if (path.includes("hunts")) return "Hunts";
  if (path.includes("ledger")) return "Ledger";
  if (path.includes("articles") || path.includes("feed")) return "Sources";
  if (path.includes("health") || path.includes("openapi")) return "Health";
  return "Other";
}

export function AutomationView() {
  const resource = useResource(loadAutomation, []);
  const groups = new Map<string, Array<[string, string, { summary?: string }]>>();
  if (resource.data) Object.entries(resource.data.contract.paths).forEach(([path, methods]) => Object.entries(methods).forEach(([method, operation]) => {
    const name = endpointGroup(path);
    groups.set(name, [...(groups.get(name) || []), [method, path, operation]]);
  }));
  return <div class="view automation-view">
    <PageHeader eyebrow="Machine access" title="API" description="REST, STIX, and RSS access to ThreatWatch evidence and decisions." actions={<div class="button-row"><a class="button secondary" href="/api/v1/openapi.json">OpenAPI JSON</a><a class="button primary" href="/api/stix">Download STIX</a></div>} />
    {resource.loading && <LoadingState label="Loading automation contract" />}{resource.error && <ErrorState message={resource.error} />}
    {resource.data && <>
      <section class="automation-status"><article class="surface"><span class={`health-indicator ${resource.data.health.status}`} /><div><strong>REST API</strong><p>{resource.data.health.status === "ok" ? "Operational" : `Available with ${resource.data.health.status} dependencies`}</p></div></article><article class="surface"><strong>STIX 2.1</strong><p>Download current machine-readable indicators and objects.</p></article><article class="surface"><strong>RSS feed</strong><p><a href="/feed.xml">Subscribe to source reporting</a></p></article></section>
      <section><div class="section-heading"><div><p class="eyebrow">OpenAPI contract</p><h2>Endpoint groups</h2></div><code>{location.origin}/api/v1</code></div><div class="endpoint-groups">{[...groups.entries()].map(([name, endpoints]) => <details class="endpoint-group" key={name}><summary><strong>{name}</strong><span>{endpoints.length} endpoint{endpoints.length === 1 ? "" : "s"}</span></summary><div class="endpoint-list">{endpoints.map(([method, path, operation]) => <article class="endpoint-row" key={`${method}-${path}`}><span class="method">{method.toUpperCase()}</span><code>{path}</code><p>{operation.summary || "ThreatWatch API operation"}</p><button class="text-button" onClick={() => copyText(`${location.origin}${path.replace("{id}", "RECORD_ID").replace("{region}", "latest")}`)} type="button">Copy URL</button></article>)}</div></details>)}</div></section>
      <section class="surface integration-note"><p class="eyebrow">Integration boundary</p><h2>Grounded by default</h2><p>The API exposes evidence, citations, generation time, and health state. Consumers should preserve these fields and must not silently treat stale or degraded enrichment as current analysis.</p></section>
    </>}
  </div>;
}
