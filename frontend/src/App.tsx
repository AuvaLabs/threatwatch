import { useResource } from "./hooks/useResource";
import { api } from "./services/api";
import { useRoute } from "./router";
import { AppShell } from "./components/AppShell";
import { ArticleView } from "./views/ArticleView";
import { AutomationView } from "./views/AutomationView";
import { ExposureView } from "./views/ExposureView";
import { HuntsView } from "./views/HuntsView";
import { InvestigationsView } from "./views/InvestigationsView";
import { LedgerRecordView } from "./views/LedgerRecordView";
import { LedgerView } from "./views/LedgerView";
import { MissionControlView } from "./views/MissionControlView";
import { ReportsView } from "./views/ReportsView";
import { SourcesView } from "./views/SourcesView";
import { SystemView } from "./views/SystemView";
import { ThreatsView } from "./views/ThreatsView";

export function App() {
  const route = useRoute();
  const health = useResource(api.health, []);
  const view = (() => {
    switch (route.name) {
      case "ledger": return <LedgerView />;
      case "ledgerRecord": return <LedgerRecordView id={route.recordId || ""} />;
      case "threats": return <ThreatsView />;
      case "exposure": return <ExposureView />;
      case "investigations": return <InvestigationsView />;
      case "hunts": return <HuntsView />;
      case "reports": return <ReportsView />;
      case "automation": return <AutomationView />;
      case "sources": return <SourcesView />;
      case "article": return <ArticleView id={route.articleId || ""} />;
      case "system": return <SystemView />;
      default: return <MissionControlView />;
    }
  })();
  return <AppShell health={health.data} route={route.name}>{view}</AppShell>;
}
