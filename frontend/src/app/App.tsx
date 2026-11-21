import { useEffect, useState } from "react";
import { ApprovalsPage } from "../features/approvals/ApprovalsPage";
import { AssetsPage } from "../features/assets/AssetsPage";
import { EvidencePage } from "../features/evidence/EvidencePage";
import { JobsPage } from "../features/jobs/JobsPage";
import { RulesPage } from "../features/rules/RulesPage";
import { fetchSnapshot } from "../shared/api/client";
import { resolveLoopbackAPIBase, resolvePrincipal } from "../shared/api/loopback";
import type { ApprovalView, EvidenceView, HostView, JobView, PageStatus, RuleView } from "../shared/api/types";

export type ConsoleState = {
  status: PageStatus;
  detail: string;
  hosts: HostView[];
  jobs: JobView[];
  evidence: EvidenceView[];
  rules: RuleView[];
  approvals: ApprovalView[];
};

const emptyState: ConsoleState = {
  status: "empty",
  detail: "No data loaded from the local API.",
  hosts: [],
  jobs: [],
  evidence: [],
  rules: [],
  approvals: []
};

function liveStartState(): ConsoleState {
  if (!resolvePrincipal()) {
    return { ...emptyState, status: "forbidden", detail: "principal query is required" };
  }
  try {
    resolveLoopbackAPIBase();
  } catch (error) {
    return { ...emptyState, status: "error", detail: error instanceof Error ? error.message : "invalid api base" };
  }
  return { ...emptyState, status: "loading", detail: "Loading local API." };
}

export function App({ initial, live = false }: { initial?: ConsoleState; live?: boolean }) {
  const [page, setPage] = useState<"assets" | "jobs" | "evidence" | "rules" | "approvals">("assets");
  const [state, setState] = useState<ConsoleState>(initial ?? (live ? liveStartState() : emptyState));
  useEffect(() => {
    if (!live) {
      return;
    }
    const principal = resolvePrincipal();
    if (!principal) {
      return;
    }
    let apiBase: string;
    try {
      apiBase = resolveLoopbackAPIBase();
    } catch {
      return;
    }
    let cancelled = false;
    fetchSnapshot(apiBase, principal)
      .then((snapshot) => {
        if (cancelled) {
          return;
        }
        const liveScan = snapshot.jobs.some((job) => job.scan_ready || job.collector_available);
        const partial = snapshot.jobs.some((job) => job.status === "PARTIAL") || liveScan;
        setState({
          ...snapshot,
          status: liveScan ? "error" : partial ? "partial" : snapshot.hosts.length === 0 ? "empty" : "ready",
          detail: liveScan
            ? "local API claimed scan_ready; treating as error"
            : partial
              ? "fixture inspect is not live scanning"
              : snapshot.hosts.length === 0
                ? "No authorized hosts are visible to this principal."
                : "Local loopback snapshot."
        });
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        const forbidden = error instanceof Error && error.name === "ForbiddenError";
        setState({
          ...emptyState,
          status: forbidden ? "forbidden" : "error",
          detail: forbidden ? "principal cannot see this zone" : "local API unavailable"
        });
      });
    return () => {
      cancelled = true;
    };
  }, [live]);
  return (
    <main>
      <p>Local HostSec console. Authorization stays on the server. This UI does not evaluate rules.</p>
      <nav>
        <button type="button" onClick={() => setPage("assets")}>
          Assets
        </button>
        <button type="button" onClick={() => setPage("jobs")}>
          Jobs
        </button>
        <button type="button" onClick={() => setPage("evidence")}>
          Evidence
        </button>
        <button type="button" onClick={() => setPage("rules")}>
          Rules
        </button>
        <button type="button" onClick={() => setPage("approvals")}>
          Approvals
        </button>
      </nav>
      {page === "assets" ? <AssetsPage status={state.status} hosts={state.hosts} detail={state.detail} /> : null}
      {page === "jobs" ? <JobsPage status={state.status} jobs={state.jobs} detail={state.detail} /> : null}
      {page === "evidence" ? <EvidencePage status={state.status} items={state.evidence} detail={state.detail} /> : null}
      {page === "rules" ? <RulesPage status={state.status} rules={state.rules} detail={state.detail} /> : null}
      {page === "approvals" ? <ApprovalsPage status={state.status} approvals={state.approvals} detail={state.detail} /> : null}
    </main>
  );
}
