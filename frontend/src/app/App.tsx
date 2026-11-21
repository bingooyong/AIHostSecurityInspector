import { useState } from "react";
import { ApprovalsPage } from "../features/approvals/ApprovalsPage";
import { AssetsPage } from "../features/assets/AssetsPage";
import { EvidencePage } from "../features/evidence/EvidencePage";
import { JobsPage } from "../features/jobs/JobsPage";
import { RulesPage } from "../features/rules/RulesPage";
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

export function App({ initial = emptyState }: { initial?: ConsoleState }) {
  const [page, setPage] = useState<"assets" | "jobs" | "evidence" | "rules" | "approvals">("assets");
  const state = initial;
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
