import { useResource } from "./hooks/useResource";
import { api } from "./services/api";
import { useRoute } from "./router";
import { AppShell } from "./components/AppShell";
import { ApiView } from "./views/ApiView";
import { ArticleView } from "./views/ArticleView";
import { BriefingsView } from "./views/BriefingsView";
import { CampaignsView } from "./views/CampaignsView";
import { NewsView } from "./views/NewsView";
import { OverviewView } from "./views/OverviewView";
import { SystemView } from "./views/SystemView";
import { VulnerabilitiesView } from "./views/VulnerabilitiesView";
import { WatchlistsView } from "./views/WatchlistsView";

export function App() {
  const route = useRoute();
  const health = useResource(api.health, []);
  const view = (() => {
    switch (route.name) {
      case "news": return <NewsView />;
      case "article": return <ArticleView id={route.articleId || ""} />;
      case "vulnerabilities": return <VulnerabilitiesView />;
      case "campaigns": return <CampaignsView />;
      case "watchlists": return <WatchlistsView />;
      case "briefings": return <BriefingsView />;
      case "api": return <ApiView />;
      case "system": return <SystemView />;
      default: return <OverviewView />;
    }
  })();
  return <AppShell health={health.data} route={route.name}>{view}</AppShell>;
}
