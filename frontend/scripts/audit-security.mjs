import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const ALLOWED_DEV_ADVISORIES = new Map([
  [
    "GHSA-fc5q-39xc-vjpf",
    {
      package: "picomatch",
      reviewBy: "2026-12-18",
      reason: "Unpatched build-only dependency; no runtime package exposure",
    },
  ],
]);

function advisoryId(via) {
  if (!via || typeof via !== "object" || typeof via.url !== "string") {
    return null;
  }
  const id = via.url.split("/").filter(Boolean).at(-1) || "";
  return id.startsWith("GHSA-") ? id : null;
}

export function collectRootAdvisories(
  packageName,
  vulnerabilities,
  visited = new Set(),
) {
  if (visited.has(packageName)) return new Set();
  const nextVisited = new Set(visited).add(packageName);
  const record = vulnerabilities[packageName];
  if (!record || !Array.isArray(record.via)) {
    return new Set([`unknown:${packageName}`]);
  }

  const roots = new Set();
  for (const via of record.via) {
    if (typeof via === "string") {
      for (const root of collectRootAdvisories(
        via,
        vulnerabilities,
        nextVisited,
      )) {
        roots.add(root);
      }
      continue;
    }
    roots.add(advisoryId(via) || `unknown:${packageName}`);
  }
  return roots;
}

export function findUnapprovedVulnerabilities(
  audit,
  allowed = ALLOWED_DEV_ADVISORIES,
) {
  const vulnerabilities = audit.vulnerabilities || {};
  return Object.keys(vulnerabilities).filter((packageName) => {
    const roots = collectRootAdvisories(packageName, vulnerabilities);
    return roots.size === 0 || [...roots].some((root) => !allowed.has(root));
  });
}

export function isReviewExpired(reviewBy, now = new Date()) {
  return now >= new Date(`${reviewBy}T00:00:00Z`);
}

function runNpmAudit(args) {
  const result = spawnSync("npm", ["audit", "--json", ...args], {
    encoding: "utf8",
  });
  if (!result.stdout.trim()) {
    throw new Error(result.stderr.trim() || "npm audit returned no JSON");
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`npm audit returned invalid JSON: ${error.message}`);
  }
}

function vulnerabilityTotal(audit) {
  return audit.metadata?.vulnerabilities?.total || 0;
}

function usedRootAdvisories(audit) {
  const roots = new Set();
  const vulnerabilities = audit.vulnerabilities || {};
  for (const packageName of Object.keys(vulnerabilities)) {
    for (const root of collectRootAdvisories(packageName, vulnerabilities)) {
      roots.add(root);
    }
  }
  return roots;
}

export function runAuditPolicy() {
  const productionAudit = runNpmAudit(["--omit=dev"]);
  if (vulnerabilityTotal(productionAudit) !== 0) {
    throw new Error("Production dependency audit contains vulnerabilities");
  }

  const fullAudit = runNpmAudit([]);
  const unapproved = findUnapprovedVulnerabilities(fullAudit);
  if (unapproved.length > 0) {
    throw new Error(
      `Unapproved development vulnerabilities: ${unapproved.join(", ")}`,
    );
  }

  for (const advisory of usedRootAdvisories(fullAudit)) {
    const exception = ALLOWED_DEV_ADVISORIES.get(advisory);
    if (exception && isReviewExpired(exception.reviewBy)) {
      throw new Error(
        `Security exception ${advisory} expired on ${exception.reviewBy}`,
      );
    }
  }

  console.log("Production dependency audit: 0 vulnerabilities");
  for (const [advisory, exception] of ALLOWED_DEV_ADVISORIES) {
    if (!usedRootAdvisories(fullAudit).has(advisory)) continue;
    console.warn(
      `Allowed dev advisory ${advisory} until ${exception.reviewBy}: ` +
        exception.reason,
    );
  }
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    runAuditPolicy();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
