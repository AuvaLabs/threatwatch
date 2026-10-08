import { useMemo, useState } from "preact/hooks";
import { ErrorState, LoadingState } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { copyText } from "../services/clipboard";
import { articleDate, articleSummary, displayTitle, formattedDate, safeExternalUrl } from "../utils/format";

function flattenIndicators(iocs?: Record<string, unknown[]>): Array<[string, string[]]> {
  if (!iocs) return [];
  return Object.entries(iocs).reduce<Array<[string, string[]]>>((groups, [name, values]) => {
    const rendered = values.map((value) => typeof value === "string" ? value : JSON.stringify(value));
    return rendered.length ? [...groups, [name, rendered]] : groups;
  }, []);
}

export function ArticleView({ id }: { id: string }) {
  const resource = useResource((signal) => api.article(id, signal), [id]);
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");
  const indicators = useMemo(() => flattenIndicators(resource.data?.iocs), [resource.data]);
  if (resource.loading) return <LoadingState label="Loading intelligence record" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error || "The report was not found."} />;

  const article = resource.data;
  const summary = articleSummary(article);
  const external = safeExternalUrl(article.canonical_url || article.link);
  return (
    <div class="view article-view">
      <button class="back-link" onClick={() => navigate("/sources")} type="button">← Back to sources</button>
      <article class="article-record">
        <header class="record-header">
          <div class="record-meta">
            <span>{article.source_name || "Unknown source"}</span>
            <time dateTime={articleDate(article) || undefined}>{formattedDate(articleDate(article))}</time>
            {article.language && <span>{article.language.toUpperCase()}</span>}
          </div>
          <h1>{displayTitle(article)}</h1>
          {article.translated_title && article.translated_title !== article.title && <details class="original-title"><summary>Original title</summary><p>{article.title}</p></details>}
          <div class="record-tags">
            {article.category && <span class="tag">{article.category}</span>}
            {article.region && <span class="tag muted">{article.region}</span>}
            {article.summary_method === "ai" && <span class="tag ai">AI summarized</span>}
          </div>
        </header>

        <section class="record-summary">
          <p class="eyebrow">Intelligence summary</p>
          <h2>What happened</h2>
          <p>{summary || "Summary pending. Review the original reporting before drawing conclusions."}</p>
          {article.confidence !== undefined && <p class="confidence-note">Classification confidence: {article.confidence}%</p>}
        </section>

        <div class="record-grid">
          <section><p class="eyebrow">Assessment</p><h2>Why it matters</h2><p>{article.intel_what || "ThreatWatch has not produced a separate assessment for this report. The source facts remain available for analyst review."}</p></section>
          <section><p class="eyebrow">Coverage</p><h2>Context</h2><dl class="fact-list"><div><dt>Region</dt><dd>{article.region || "Unclassified"}</dd></div><div><dt>Sector</dt><dd>{article.victim_sectors?.join(", ") || "Unclassified"}</dd></div><div><dt>Source confidence</dt><dd>{article.confidence !== undefined ? `${article.confidence}%` : "Not scored"}</dd></div></dl></section>
        </div>

        {!!article.cve_ids?.length && <section class="technical-section"><p class="eyebrow">Vulnerabilities</p><h2>Referenced CVEs</h2><div class="chip-list">{article.cve_ids.map((cve) => <code key={cve}>{cve}</code>)}</div></section>}
        {!!article.attack_techniques?.length && <section class="technical-section"><p class="eyebrow">Techniques</p><h2>Observed behavior</h2><ul>{article.attack_techniques.map((technique) => <li key={typeof technique === "string" ? technique : technique.id || technique.name}>{typeof technique === "string" ? technique : `${technique.id || ""} ${technique.name || ""}`.trim()}</li>)}</ul></section>}
        {!!indicators.length && <section class="technical-section"><p class="eyebrow">Indicators</p><h2>Extracted observables</h2>{indicators.map(([name, values]) => <div class="indicator-group" key={name}><h3>{name.replaceAll("_", " ")}</h3><div class="chip-list">{values.slice(0, 20).map((value) => <code key={value}>{value}</code>)}</div></div>)}</section>}

        <footer class="record-actions">
          {external ? <a class="button primary" href={external} rel="noopener noreferrer" target="_blank">Open original source</a> : <span class="notice">Original source unavailable</span>}
          <button class="button secondary" onClick={async () => setCopyStatus(await copyText(location.href) ? "copied" : "error")} type="button">{copyStatus === "copied" ? "Link copied" : "Copy intelligence link"}</button>
        </footer>
        {copyStatus === "error" && <div class="notice" role="status">Clipboard access is unavailable. Copy the address from your browser.</div>}
      </article>
    </div>
  );
}
