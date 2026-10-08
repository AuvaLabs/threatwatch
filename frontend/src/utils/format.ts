import type { Article } from "../types";

export function articleDate(article: Article): string | null {
  return article.published_at || article.published || article.timestamp || null;
}

export function relativeTime(value?: string | null): string {
  if (!value) return "Time unavailable";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "Time unavailable";
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formattedDate(value?: string | null): string {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Time unavailable";
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date) + " UTC";
}

export function displayTitle(article: Article): string {
  return article.translated_title?.trim() || article.title?.trim() || "Untitled intelligence report";
}

export function articleSummary(article: Article): string | null {
  const summary = article.summary?.trim() || article.intel_what?.trim();
  return summary || null;
}

export function sourceLabel(article: Article): string {
  if (article.source_name?.trim()) return article.source_name.trim();
  const aliases: Record<string, string> = {
    "nvd:cve": "NVD",
    "darkweb:threatfox": "ThreatFox",
    "darkweb:ransomware.live": "Ransomware.live",
  };
  if (article.source && aliases[article.source]) return aliases[article.source];
  try {
    const hostname = new URL(article.source || "").hostname.replace(/^www\./, "");
    const name = hostname.split(".").slice(-2, -1)[0] || hostname;
    return name ? name.replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Unknown source";
  } catch {
    return "Unknown source";
  }
}

export function excerpt(value?: string, maxLength = 520): string | null {
  const text = value?.trim();
  if (!text) return null;
  if (text.length <= maxLength) return text;
  const candidate = text.slice(0, maxLength + 1);
  const sentenceEnd = Math.max(candidate.lastIndexOf(". "), candidate.lastIndexOf("! "), candidate.lastIndexOf("? "));
  if (sentenceEnd >= Math.floor(maxLength * 0.55)) return candidate.slice(0, sentenceEnd + 1);
  const wordEnd = candidate.lastIndexOf(" ");
  return `${candidate.slice(0, wordEnd > 0 ? wordEnd : maxLength).trim()}…`;
}

export function safeExternalUrl(value?: string): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

export function actionText(value: string | { action: string }): string {
  return typeof value === "string" ? value : value.action;
}

export function healthReason(value: string): string {
  const normalized = value
    .replaceAll("_", " ")
    .replace(/\bai\b/gi, "AI")
    .replace(/\bemea\b/gi, "EMEA")
    .replace(/\bapac\b/gi, "APAC")
    .replace(/\bna\b/gi, "North America");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}
