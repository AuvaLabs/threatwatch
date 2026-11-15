import { useState } from "preact/hooks";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "../components/PageState";
import { useResource } from "../hooks/useResource";
import { navigate } from "../router";
import { api } from "../services/api";
import { importWorkspace, loadWorkspace, markFollowsReviewed, unfollowThreat, workspaceDownload } from "../services/workspace";
import type { AnalystWorkspace, FollowedThreat, IncidentChange, LedgerChange } from "../types";
import { formattedDate } from "../utils/format";


type PublicChange = IncidentChange | LedgerChange;


async function loadChanges(signal: AbortSignal): Promise<PublicChange[]> {
  const [ledger, incidents] = await Promise.all([api.ledgerChanges(signal), api.incidentChanges(signal)]);
  return [...ledger.changes, ...incidents.changes];
}


function unreadChanges(follow: FollowedThreat, changes: PublicChange[]): PublicChange[] {
  const cursor = Date.parse(follow.lastReviewedAt);
  return changes
    .filter((change) => change.record_id === follow.id && Date.parse(change.changed_at) > cursor)
    .sort((left, right) => Date.parse(right.changed_at) - Date.parse(left.changed_at));
}


export function FollowingView() {
  const resource = useResource(loadChanges, []);
  const [workspace, setWorkspace] = useState<AnalystWorkspace>(() => loadWorkspace());
  const [notice, setNotice] = useState("");
  const review = () => {
    setWorkspace(markFollowsReviewed());
    setNotice("All current changes marked reviewed.");
  };
  const remove = (follow: FollowedThreat) => setWorkspace(unfollowThreat(follow.kind, follow.id));
  const importFile = async (event: Event) => {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const imported = importWorkspace(await file.text());
      setWorkspace(imported);
      setNotice(`Imported ${imported.follows.length} followed threat${imported.follows.length === 1 ? "" : "s"}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The workspace could not be imported.");
    } finally {
      input.value = "";
    }
  };
  const unreadTotal = resource.data
    ? workspace.follows.reduce((total, follow) => total + unreadChanges(follow, resource.data || []).length, 0)
    : 0;
  return <div class="view following-view">
    <PageHeader eyebrow="Private watch desk" title="Following" description="Material changes to the public threats you choose, stored only in this browser." actions={<div class="button-row"><label class="button secondary file-button">Import workspace<input accept="application/json" onChange={importFile} type="file" /></label>{workspace.follows.length ? <button class="button secondary" onClick={() => workspaceDownload(workspace)} type="button">Export workspace</button> : null}</div>} />
    <div class="notice" role="note"><strong>No account and no inventory upload.</strong> Your followed records stay in browser storage. Each public record also has a portable Atom feed.</div>
    {notice && <div class="notice" role="status">{notice}</div>}
    {resource.loading && <LoadingState label="Checking followed threat changes" />}
    {resource.error && <ErrorState message={resource.error} />}
    {!resource.loading && !resource.error && !workspace.follows.length && <EmptyState title="No followed threats yet"><span>Open an incident or living threat record and select Follow threat.</span><button class="button primary" onClick={() => navigate("/ledger")} type="button">Browse the ledger</button></EmptyState>}
    {!resource.loading && !resource.error && workspace.follows.length > 0 && <>
      <section aria-label={`${unreadTotal} ${unreadTotal === 1 ? "unread change" : "unread changes"}`} class="following-summary surface"><div><p class="eyebrow">Change inbox</p><strong>{unreadTotal}</strong><span>{unreadTotal === 1 ? "unread change" : "unread changes"}</span></div><button class="button secondary" disabled={unreadTotal === 0} onClick={review} type="button">Mark all reviewed</button></section>
      {unreadTotal === 0 && <p class="quiet-empty surface">No unread material changes.</p>}
      <section class="following-list">{workspace.follows.map((follow) => {
        const changes = unreadChanges(follow, resource.data || []);
        return <article class="followed-record surface" key={`${follow.kind}:${follow.id}`}>
          <div><p class="eyebrow">{follow.kind} / followed {formattedDate(follow.followedAt)}</p><h2>{follow.title}</h2><p>{follow.detail}</p></div>
          <div class="followed-actions"><a class="button primary" href={follow.href}>Open record</a><a class="button secondary" href={follow.feedHref}>Atom feed</a><button class="text-button" onClick={() => remove(follow)} type="button">Unfollow</button></div>
          {changes.length > 0 && <ol class="followed-changes">{changes.map((change) => <li key={change.id}><time>{formattedDate(change.changed_at)}</time><strong>{change.summary}</strong></li>)}</ol>}
        </article>;
      })}</section>
    </>}
  </div>;
}
