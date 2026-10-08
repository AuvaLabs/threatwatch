import { useState } from "preact/hooks";
import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { api } from "../services/api";
import { copyText } from "../services/clipboard";
import { huntPack, urgencyLabel } from "../services/operations";

export function HuntsView() {
  const resource = useResource(api.operations, []);
  const [copied, setCopied] = useState("");
  const copy = async (id: string, pack: string) => {
    setCopied(await copyText(pack) ? id : "error");
  };
  return <div class="view hunts-view">
    <PageHeader eyebrow="Hunt desk" title="Hunts" description="Observed CVEs, ATT&CK techniques, and indicators assembled for analyst validation." />
    <div class="notice warning" role="note"><strong>Analyst validation required.</strong> Hunt packs contain leads, not detection rules. Validate scope, syntax, and indicators before production use.</div>
    {copied === "error" && <div class="notice" role="status">Clipboard access is unavailable. Expand the preview and copy the text manually.</div>}
    {resource.loading && <LoadingState label="Assembling evidence packs" />}{resource.error && <ErrorState message={resource.error} />}
    <div class="hunt-grid">{resource.data?.priorities.filter((item) => item.action_type === "hunt" || item.evidence.ioc_count > 0 || item.evidence.techniques.length > 0).map((priority) => <article class="hunt-card surface" key={priority.id}><div class="hunt-card-head"><span class={`urgency-pill ${priority.urgency}`}>{urgencyLabel(priority.urgency)}</span><span>{priority.evidence.ioc_count} indicators</span></div><h2>{priority.title}</h2><p>{priority.recommended_action}</p><dl><div><dt>CVEs</dt><dd>{priority.evidence.cves.join(", ") || "None extracted"}</dd></div><div><dt>ATT&amp;CK</dt><dd>{priority.evidence.techniques.join(", ") || "None extracted"}</dd></div></dl><details><summary>Preview hunt pack</summary><pre>{huntPack(priority)}</pre></details><button class="button primary" onClick={() => copy(priority.id, huntPack(priority))} type="button">{copied === priority.id ? "Copied" : "Copy hunt pack"}</button></article>)}</div>
  </div>;
}
