import { useState } from "preact/hooks";
import { followThreat, loadWorkspace, unfollowThreat } from "../services/workspace";
import type { FollowedThreat } from "../types";


type FollowTarget = Omit<FollowedThreat, "followedAt" | "lastReviewedAt">;


export function FollowThreatButton({ target }: { target: FollowTarget }) {
  const [following, setFollowing] = useState(() => loadWorkspace().follows.some(
    (item) => item.kind === target.kind && item.id === target.id,
  ));
  const [error, setError] = useState("");
  const toggle = () => {
    try {
      if (following) {
        unfollowThreat(target.kind, target.id);
      } else {
        const now = new Date().toISOString();
        followThreat({ ...target, followedAt: now, lastReviewedAt: now });
      }
      setFollowing(!following);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Browser storage is unavailable.");
    }
  };
  return <>
    <button class={`button ${following ? "secondary" : "primary"}`} onClick={toggle} type="button">
      {following ? "Unfollow threat" : "Follow threat"}
    </button>
    {error && <span class="follow-error" role="status">{error}</span>}
  </>;
}
