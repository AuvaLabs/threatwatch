import { describe, expect, it } from "vitest";

import {
  collectRootAdvisories,
  findUnapprovedVulnerabilities,
  isReviewExpired,
} from "./audit-security.mjs";

const allowed = new Map([
  ["GHSA-fc5q-39xc-vjpf", { reviewBy: "2026-12-18" }],
]);

const audit = {
  vulnerabilities: {
    picomatch: {
      via: [{ url: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf" }],
    },
    vite: { via: ["picomatch"] },
  },
};

describe("frontend audit policy", () => {
  it("resolves transitive findings to the root advisory", () => {
    expect(collectRootAdvisories("vite", audit.vulnerabilities)).toEqual(
      new Set(["GHSA-fc5q-39xc-vjpf"]),
    );
    expect(findUnapprovedVulnerabilities(audit, allowed)).toEqual([]);
  });

  it("rejects an advisory that is not explicitly approved", () => {
    const unsafeAudit = {
      vulnerabilities: {
        package: {
          via: [{ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" }],
        },
      },
    };

    expect(findUnapprovedVulnerabilities(unsafeAudit, allowed)).toEqual([
      "package",
    ]);
  });

  it("expires an exception on its review date", () => {
    expect(
      isReviewExpired("2026-12-18", new Date("2026-12-17T23:59:59Z")),
    ).toBe(false);
    expect(
      isReviewExpired("2026-12-18", new Date("2026-12-18T00:00:00Z")),
    ).toBe(true);
  });
});
