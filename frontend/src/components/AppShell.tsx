import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Health } from "../types";
import type { RouteName } from "../router";
import { navigate } from "../router";
import { Icon } from "./Icon";

const navigation = [
  { label: "Mission Control", shortLabel: "Mission", href: "/", route: "mission", icon: "overview" },
  { label: "Threats", shortLabel: "Threats", href: "/threats", route: "threats", icon: "campaigns" },
  { label: "Exposure", shortLabel: "Exposure", href: "/exposure", route: "exposure", icon: "shield" },
  { label: "Investigations", shortLabel: "Cases", href: "/investigations", route: "investigations", icon: "watch" },
  { label: "Hunts", shortLabel: "Hunts", href: "/hunts", route: "hunts", icon: "search" },
  { label: "Reports", shortLabel: "Reports", href: "/reports", route: "reports", icon: "briefings" },
  { label: "Automation", shortLabel: "Automate", href: "/automation", route: "automation", icon: "api" },
  { label: "Sources", shortLabel: "Sources", href: "/sources", route: "sources", icon: "news" },
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
    navigate(value ? `/sources?q=${encodeURIComponent(value)}` : "/sources");
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
            <a class={route === item.route || (route === "article" && item.route === "sources") ? "active" : ""} href={item.href} key={item.route} onClick={(event) => { follow(event, item.href); setMenuOpen(false); }}>
              <Icon name={item.icon} /><span>{item.label}</span>
            </a>
          ))}
        </nav>
        <div class="sidebar-footer">
          <a class={route === "system" ? "active" : ""} href="/system" onClick={(event) => follow(event, "/system")}><Icon name="system" /><span>System status</span></a>
          <p>Intelligence operations<br />Version 3.0</p>
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
            <span>{health ? `Platform ${health.status}` : "Checking platform"}</span>
          </div>
          <button aria-label={`Switch to ${dark ? "light" : "dark"} theme`} class="icon-button" onClick={() => setDark((value) => !value)} type="button">
            <Icon name={dark ? "sun" : "moon"} />
          </button>
        </header>
        <main id="main-content">{children}</main>
      </div>

      <nav aria-label="Mobile navigation" class="mobile-nav">
        {navigation.slice(0, 5).map((item) => (
          <a class={route === item.route || (route === "article" && item.route === "sources") ? "active" : ""} href={item.href} key={item.route} onClick={(event) => follow(event, item.href)}>
            <Icon name={item.icon} size={19} /><span>{item.shortLabel}</span>
          </a>
        ))}
      </nav>
    </div>
  );
}
