import { useState } from "preact/hooks";
import { EmptyState, PageHeader } from "../components/PageState";
import { actionLabel, urgencyLabel } from "../services/operations";
import { loadWorkspace, updateInvestigation, workspaceDownload } from "../services/workspace";
import type { AnalystWorkspace, InvestigationStatus } from "../types";
import { formattedDate } from "../utils/format";

export function InvestigationsView() {
  const [workspace, setWorkspace] = useState<AnalystWorkspace>(() => loadWorkspace());
  const [notice, setNotice] = useState("");
  const update = (id: string, status: InvestigationStatus, notes: string) => {
    try {
      const saved = updateInvestigation(id, { status, notes });
      if (!saved) return;
      setWorkspace(loadWorkspace());
      setNotice(`Saved ${saved.title}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The investigation could not be saved.");
    }
  };
  return (
    <div class="view investigations-view">
      <PageHeader eyebrow="Casebook" title="Investigations" description="Status, decisions, and working notes for priorities under review." actions={workspace.investigations.length ? <button class="button secondary" onClick={() => workspaceDownload(workspace)} type="button">Export workspace</button> : undefined} />
      <div class="notice" role="note"><strong>Private to this browser.</strong> Investigations are stored locally on this device. Export regularly if the record must be retained or shared.</div>
      {notice && <div class="notice" role="status">{notice}</div>}
      {!workspace.investigations.length && <EmptyState title="No investigations yet">Open a priority from Mission Control to begin a local investigation.</EmptyState>}
      <div class="investigation-list">
        {workspace.investigations.map((item) => <InvestigationRecord item={item} key={item.id} onSave={update} />)}
      </div>
    </div>
  );
}

function InvestigationRecord({ item, onSave }: {
  item: AnalystWorkspace["investigations"][number];
  onSave: (id: string, status: InvestigationStatus, notes: string) => void;
}) {
  const [status, setStatus] = useState<InvestigationStatus>(item.status);
  const [notes, setNotes] = useState(item.notes);
  return <article class="investigation-record surface">
    <div class="investigation-head"><div><span class={`urgency-pill ${item.urgency}`}>{urgencyLabel(item.urgency)}</span><span>{actionLabel(item.actionType)}</span></div><span>Updated {formattedDate(item.updatedAt)}</span></div>
    <h2>{item.title}</h2>
    {!!item.cves.length && <div class="chip-list">{item.cves.map((cve) => <code key={cve}>{cve}</code>)}</div>}
    <div class="investigation-controls"><label><span>Status</span><select onChange={(event) => setStatus(event.currentTarget.value as InvestigationStatus)} value={status}><option value="open">Open</option><option value="monitoring">Monitoring</option><option value="closed">Closed</option></select></label><label><span>Analyst notes and decision record</span><textarea onInput={(event) => setNotes(event.currentTarget.value)} rows={5} value={notes} /></label></div>
    <button class="button primary" onClick={() => onSave(item.id, status, notes)} type="button">Save investigation</button>
  </article>;
}
