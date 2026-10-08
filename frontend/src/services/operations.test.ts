import { describe, expect, it } from "vitest";
import { actionLabel, huntPack, investigationFromPriority, urgencyLabel } from "./operations";
import type { OperationalPriority } from "../types";

const priority: OperationalPriority = {
  id: "threat-1",
  title: "Exploited gateway vulnerability",
  summary: "Active exploitation is confirmed.",
  score: 91,
  urgency: "critical",
  action_type: "patch",
  recommended_action: "Patch or isolate affected technology.",
  reasons: ["CISA KEV confirms active exploitation"],
  watchlist_matches: ["Ivanti"],
  evidence: { cves: ["CVE-2026-1000"], techniques: [], iocs: ["192.0.2.10"], ioc_count: 1 },
};

describe("operational presentation", () => {
  it("uses clear action and urgency labels", () => {
    expect(actionLabel("patch")).toBe("Patch or isolate");
    expect(actionLabel("hunt")).toBe("Begin threat hunt");
    expect(actionLabel("investigate")).toBe("Validate relevance");
    expect(actionLabel("monitor")).toBe("Monitor evidence");
    expect(urgencyLabel("critical")).toBe("Immediate");
    expect(urgencyLabel("high")).toBe("High priority");
    expect(urgencyLabel("medium")).toBe("Review");
  });

  it("creates an investigation from traceable priority evidence", () => {
    const investigation = investigationFromPriority(priority, "2026-10-08T00:00:00.000Z");
    expect(investigation).toMatchObject({
      id: "investigation-threat-1",
      sourceId: "threat-1",
      title: priority.title,
      status: "open",
      cves: ["CVE-2026-1000"],
    });
  });

  it("builds a portable evidence pack with optional evidence sections", () => {
    const pack = huntPack({
      ...priority,
      evidence: { cves: ["CVE-2026-1000"], techniques: ["T1190"], iocs: ["192.0.2.10"], ioc_count: 1 },
    });
    expect(pack).toContain("## CVEs");
    expect(pack).toContain("## ATT&CK techniques");
    expect(pack).toContain("## Indicators");
    expect(pack).toContain("Validate all indicators");
    expect(huntPack({ ...priority, evidence: { cves: [], techniques: [], iocs: [], ioc_count: 0 } })).not.toContain("## CVEs");
  });
});
