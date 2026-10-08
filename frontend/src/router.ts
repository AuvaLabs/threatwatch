import { useEffect, useState } from "preact/hooks";

export type RouteName =
  | "overview"
  | "news"
  | "article"
  | "vulnerabilities"
  | "campaigns"
  | "watchlists"
  | "briefings"
  | "api"
  | "system";

export interface Route {
  name: RouteName;
  articleId?: string;
}

export function parseRoute(pathname: string): Route {
  if (pathname.startsWith("/news/")) {
    return { name: "article", articleId: decodeURIComponent(pathname.slice(6)) };
  }
  const routes: Record<string, RouteName> = {
    "/": "overview",
    "/news": "news",
    "/vulnerabilities": "vulnerabilities",
    "/campaigns": "campaigns",
    "/watchlists": "watchlists",
    "/briefings": "briefings",
    "/api-docs": "api",
    "/system": "system",
  };
  return { name: routes[pathname] || "overview" };
}

export function navigate(path: string): void {
  if (`${location.pathname}${location.search}` === path) return;
  history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(location.pathname));
  useEffect(() => {
    const update = () => setRoute(parseRoute(location.pathname));
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  return route;
}
