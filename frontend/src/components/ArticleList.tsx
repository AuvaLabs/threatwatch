import type { Article } from "../types";
import { navigate } from "../router";
import { articleDate, articleSummary, displayTitle, relativeTime, sourceLabel } from "../utils/format";
import { EmptyState } from "./PageState";

function metadata(article: Article): string[] {
  return [article.region || article.feed_region, ...(article.victim_sectors || []).slice(0, 1)].filter(Boolean) as string[];
}

function openArticle(event: Event, id: string): void {
  event.preventDefault();
  navigate(`/sources/${encodeURIComponent(id)}`);
}

export function ArticleList({ articles, compact = false }: { articles: Article[]; compact?: boolean }) {
  if (!articles.length) {
    return <EmptyState title="No intelligence matched">Adjust the current filters or return to the complete news stream.</EmptyState>;
  }

  return (
    <div class={`article-list${compact ? " compact" : ""}`}>
      {articles.map((article) => {
        const summary = articleSummary(article);
        const pending = !summary || article.summary_method === "none";
        const kev = article.kev_listed || article.kevListed;
        return (
          <article class="article-row" key={article.hash}>
            <div class="article-time">
              <span class={`signal-dot${kev ? " critical" : ""}`} />
              <time dateTime={articleDate(article) || undefined}>{relativeTime(articleDate(article))}</time>
            </div>
            <div class="article-source">
              <span>{sourceLabel(article)}</span>
              {article.language && article.language !== "en" && <span class="subtle-label">{article.language.toUpperCase()}</span>}
            </div>
            <div class="article-copy">
              <a href={`/sources/${encodeURIComponent(article.hash)}`} onClick={(event) => openArticle(event, article.hash)}>
                {displayTitle(article)}
              </a>
              <p class={pending ? "summary-pending" : ""}>{pending ? "Summary pending" : summary}</p>
            </div>
            <div class="article-tags" aria-label="Article classifications">
              {kev && <span class="tag tag-critical">CISA KEV</span>}
              {article.category && <span class="tag">{article.category}</span>}
              {metadata(article).map((item) => <span class="tag muted" key={item}>{item}</span>)}
              {!!article.cve_ids?.length && <span class="tag technical">{article.cve_ids.length} CVE{article.cve_ids.length === 1 ? "" : "s"}</span>}
            </div>
          </article>
        );
      })}
    </div>
  );
}
