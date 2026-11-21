import type { ApprovalView, EvidenceView, HostView, JobView, RuleView } from "./types";

export type ConsoleSnapshot = {
  hosts: HostView[];
  jobs: JobView[];
  evidence: EvidenceView[];
  rules: RuleView[];
  approvals: ApprovalView[];
};

export async function fetchSnapshot(baseUrl: string, principal: string): Promise<ConsoleSnapshot> {
  const response = await fetch(`${baseUrl}/v1/hosts`, {
    headers: { "X-HostSec-Principal": principal }
  });
  if (response.status === 401 || response.status === 403) {
    const error = new Error("forbidden");
    error.name = "ForbiddenError";
    throw error;
  }
  if (!response.ok) {
    throw new Error("console request failed");
  }
  const payload: unknown = await response.json();
  if (!Array.isArray(payload)) {
    throw new Error("unexpected host payload");
  }
  return {
    hosts: payload as HostView[],
    jobs: [],
    evidence: [],
    rules: [],
    approvals: []
  };
}
