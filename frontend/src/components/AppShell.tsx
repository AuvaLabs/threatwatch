import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Health } from "../types";
import type { RouteName } from "../router";
import { navigate } from "../router";
import { Icon } from "./Icon";

const navigation = [
  { label: "Overview", href: "/", route: "overview", icon: "overview" },
  { label: "News", href: "/news", route: "news", icon: "news" },
  { label: "Vulnerabilities", href: "/vulnerabilities", route: "vulnerabilities", icon: "shield" },
  { label: "Campaigns", href: "/campaigns", route: "campaigns", icon: "campaigns" },
  { label: "Watchlists", href: "/watchlists", route: "watchlists", icon: "watch" },
  { label: "Briefings", href: "/briefings", route: "briefings", icon: "briefings" },
  { label: "API", href: "/api-docs", route: "api", icon: "api" },
] as const;

function follow(event: Event, href: string): void {
  event.preventDefault();
  navigate(href);
}

export function AppShell({ route, health, children }: { route: RouteName; health: Health | null; children: ComponentChildren }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [dark, setDark] = useState(() => localStorage.getItem("tw-theme") === "dark");

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("tw-theme", dark ? "dark" : "light");
  }, [dark]);

  const submitSearch = (event: Event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const value = new FormData(form).get("q")?.toString().trim();
    navigate(value ? `/news?q=${encodeURIComponent(value)}` : "/news");
  };

  return (
    <div class="app-shell">
      <aside class={`sidebar${menuOpen ? " open" : ""}`}>
        <div class="brand-row">
          <a class="brand" href="/" onClick={(event) => follow(event, "/")}>THREATWATCH</a>
          <button aria-label="Close navigation" class="icon-button sidebar-close" onClick={() => setMenuOpen(false)} type="button"><Icon name="close" /></button>
        </div>
        <nav aria-label="Primary navigation" class="primary-nav">
          {navigation.map((item) => (
            <a class={route === item.route || (route === "article" && item.route === "news") ? "active" : ""} href={item.href} key={item.route} onClick={(event) => { follow(event, item.href); setMenuOpen(false); }}>
              <Icon name={item.icon} /><span>{item.label}</span>
            </a>
          ))}
        </nav>
        <div class="sidebar-footer">
          <a class={route === "system" ? "active" : ""} href="/system" onClick={(event) => follow(event, "/system")}><Icon name="system" /><span>System status</span></a>
          <p>Open-source intelligence<br />Version 2.0</p>
        </div>
      </aside>

      {menuOpen && <button aria-label="Close navigation" class="nav-scrim" onClick={() => setMenuOpen(false)} type="button" />}

      <div class="workspace">
        <header class="topbar">
          <button aria-label="Open navigation" class="icon-button menu-button" onClick={() => setMenuOpen(true)} type="button"><Icon name="menu" /></button>
          <form aria-label="Search ThreatWatch" class="command-search" onSubmit={submitSearch} role="search">
            <Icon name="search" size={19} />
            <input aria-label="Ask ThreatWatch" name="q" placeholder="Ask ThreatWatch" type="search" />
            <span>Search intelligence</span>
          </form>
          <div class="topbar-status">
            <span class={`health-indicator ${health?.status || "unknown"}`} />
            <span>{health ? `Intelligence ${health.status}` : "Checking intelligence"}</span>
          </div>
          <button aria-label={`Switch to ${dark ? "light" : "dark"} theme`} class="icon-button" onClick={() => setDark((value) => !value)} type="button">
            <Icon name={dark ? "sun" : "moon"} />
          </button>
        </header>
        <main id="main-content">{children}</main>
      </div>

      <nav aria-label="Mobile navigation" class="mobile-nav">
        {navigation.slice(0, 5).map((item) => (
          <a class={route === item.route || (route === "article" && item.route === "news") ? "active" : ""} href={item.href} key={item.route} onClick={(event) => follow(event, item.href)}>
            <Icon name={item.icon} size={19} /><span>{item.label}</span>
          </a>
        ))}
      </nav>
    </div>
  );
}
