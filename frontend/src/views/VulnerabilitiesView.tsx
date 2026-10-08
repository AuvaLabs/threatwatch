import { ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { articleDate, displayTitle, relativeTime } from "../utils/format";

export function VulnerabilitiesView() {
  const resource = useResource((signal) => api.articles({ view: "vulnerabilities", limit: 50 }, signal), []);
  return (
    <div class="view vulnerabilities-view">
      <PageHeader eyebrow="Exposure intelligence" title="Vulnerabilities" description="KEV, exploit, CVSS, and source reporting organized for remediation decisions." />
      {resource.loading && <LoadingState label="Loading vulnerability intelligence" />}
      {resource.error && <ErrorState message={resource.error} />}
      {resource.data && (
        <div class="table-wrap">
          <table>
            <thead><tr><th>Vulnerability</th><th>Risk</th><th>Evidence</th><th>Published</th></tr></thead>
            <tbody>{resource.data.articles.map((article) => {
              const cve = article.cve_ids?.[0] || displayTitle(article).match(/CVE-\d{4}-\d+/i)?.[0];
              const kev = article.kev_listed || article.kevListed;
              return <tr key={article.hash}>
                <td><button class="table-title" onClick={() => navigate(`/news/${encodeURIComponent(article.hash)}`)} type="button">{cve || displayTitle(article)}</button><span>{cve ? displayTitle(article).replace(cve, "").replace(/^[:\s-]+/, "") : article.source_name}</span></td>
                <td><div class="stacked-tags">{kev && <span class="tag tag-critical">CISA KEV</span>}{article.cvss_score !== undefined && <span class="tag">CVSS {article.cvss_score}</span>}{article.epss_score !== undefined && <span class="tag muted">EPSS {(article.epss_score * 100).toFixed(1)}%</span>}{!kev && article.cvss_score === undefined && article.epss_score === undefined && <span class="subtle-label">Unscored</span>}</div></td>
                <td>{article.summary?.trim() || "Assessment pending"}</td>
                <td>{relativeTime(articleDate(article))}</td>
              </tr>;
            })}</tbody>
          </table>
          <p class="table-note">Showing {resource.data.articles.length} of {resource.data.total} vulnerability records.</p>
        </div>
      )}
    </div>
  );
}
