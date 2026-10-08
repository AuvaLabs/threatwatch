import { useEffect, useState } from "preact/hooks";

export type RouteName =
  | "mission"
  | "ledger"
  | "ledgerRecord"
  | "threats"
  | "exposure"
  | "investigations"
  | "hunts"
  | "reports"
  | "automation"
  | "sources"
  | "article"
  | "system";

export interface Route {
  name: RouteName;
  articleId?: string;
  recordId?: string;
}

export function parseRoute(pathname: string): Route {
  if (pathname.startsWith("/ledger/")) {
    return { name: "ledgerRecord", recordId: decodeURIComponent(pathname.slice(8)) };
  }
  if (pathname.startsWith("/sources/")) {
    return { name: "article", articleId: decodeURIComponent(pathname.slice(9)) };
  }
  if (pathname.startsWith("/news/")) {
    return { name: "article", articleId: decodeURIComponent(pathname.slice(6)) };
  }
  const routes: Record<string, RouteName> = {
    "/": "mission",
    "/ledger": "ledger",
    "/threats": "threats",
    "/exposure": "exposure",
    "/investigations": "investigations",
    "/hunts": "hunts",
    "/reports": "reports",
    "/automation": "automation",
    "/sources": "sources",
    "/news": "sources",
    "/vulnerabilities": "exposure",
    "/campaigns": "threats",
    "/watchlists": "exposure",
    "/briefings": "reports",
    "/api-docs": "automation",
    "/system": "system",
  };
  return { name: routes[pathname] || "mission" };
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
