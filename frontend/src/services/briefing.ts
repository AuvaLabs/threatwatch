import type { Briefing, BriefingAction, SourceArticle } from "../types";

function actionSources(action: BriefingAction | string): number[] {
  return typeof action === "string" || !Array.isArray(action.sources) ? [] : action.sources;
}

function citationIndexes(briefing: Briefing): number[] {
  const candidates: unknown[] = [
    briefing.headline_source,
    ...(briefing.what_happened_sources || []),
    ...(briefing.what_to_do || []).flatMap(actionSources),
    typeof briefing.threat_level_source === "number" ? briefing.threat_level_source : undefined,
  ];
  return candidates.filter((value, index): value is number => (
    Number.isInteger(value)
    && (value as number) > 0
    && candidates.indexOf(value) === index
  ));
}

export function briefingSources(briefing: Briefing | null | undefined, limit?: number): SourceArticle[] {
  if (!briefing?.source_articles?.length) return [];
  const sources = new Map(briefing.source_articles.map((source) => [source.index, source]));
  const cited = citationIndexes(briefing).flatMap((index) => {
    const source = sources.get(index);
    return source ? [source] : [];
  });
  return limit === undefined ? cited : cited.slice(0, Math.max(0, limit));
}

export function sourceHref(link: string | undefined): string | undefined {
  if (!link) return undefined;
  try {
    const parsed = new URL(link);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

export function sourcePublisher(source: SourceArticle | undefined): string {
  const publisher = source?.source_name?.trim();
  if (publisher) return publisher;
  const href = sourceHref(source?.link);
  if (!href) return "Source";
  return new URL(href).hostname.replace(/^www\./, "") || "Source";
}

export function sourceTitle(source: SourceArticle): string {
  return source.title?.trim() || `Source ${source.index}`;
}
