import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Health } from "../types";
import type { RouteName } from "../router";
import { navigate } from "../router";
import { Icon } from "./Icon";

const navigation = [
  { label: "Today", href: "/", route: "mission" },
  { label: "Ledger", href: "/ledger", route: "ledger" },
  { label: "Threats", href: "/threats", route: "threats" },
  { label: "Hunts", href: "/hunts", route: "hunts" },
  { label: "Reports", href: "/reports", route: "reports" },
  { label: "Automation", href: "/automation", route: "automation" },
  { label: "Sources", href: "/sources", route: "sources" },
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
      <header class="site-masthead">
        <div class="masthead-row">
          <a class="brand" href="/" onClick={(event) => follow(event, "/")}><span>THREAT</span><b>/</b><span>WATCH</span></a>
          <span class="desk-edition">INTELLIGENCE DESK&nbsp;&nbsp;•&nbsp;&nbsp;UTC</span>
          <form aria-label="Search ThreatWatch" class="command-search" onSubmit={submitSearch} role="search">
            <Icon name="search" size={18} />
            <input aria-label="Ask ThreatWatch" name="q" placeholder="Search actors, CVEs, organizations" type="search" />
          </form>
          <div class="topbar-status"><span class={`health-indicator ${health?.status || "unknown"}`} /><span>{health ? health.status : "checking"}</span></div>
          <button aria-label={`Switch to ${dark ? "light" : "dark"} theme`} class="icon-button" onClick={() => setDark((value) => !value)} type="button"><Icon name={dark ? "sun" : "moon"} /></button>
          <button aria-label="Open navigation" class="icon-button menu-button" onClick={() => setMenuOpen(true)} type="button"><Icon name="menu" /></button>
        </div>
        <nav aria-label="Primary navigation" class={`desk-navigation${menuOpen ? " open" : ""}`}>
          <div class="navigation-heading"><span>Desk index</span><button aria-label="Close navigation" class="icon-button" onClick={() => setMenuOpen(false)} type="button"><Icon name="close" /></button></div>
          {navigation.map((item, index) => (
            <a class={route === item.route || (route === "article" && item.route === "sources") || (route === "ledgerRecord" && item.route === "ledger") ? "active" : ""} href={item.href} key={item.route} onClick={(event) => { follow(event, item.href); setMenuOpen(false); }}><span>{String(index + 1).padStart(2, "0")}</span>{item.label}</a>
          ))}
          <a class={`system-link${route === "system" ? " active" : ""}`} href="/system" onClick={(event) => { follow(event, "/system"); setMenuOpen(false); }}><span>08</span>System</a>
        </nav>
      </header>
      {menuOpen && <button aria-label="Close navigation" class="nav-scrim" onClick={() => setMenuOpen(false)} type="button" />}
      <div class="workspace route-workspace">
        <main id="main-content">{children}</main>
        <footer class="site-footer"><span>THREATWATCH / 3.1</span><span>Public evidence for operational decisions</span></footer>
      </div>
    </div>
  );
}
