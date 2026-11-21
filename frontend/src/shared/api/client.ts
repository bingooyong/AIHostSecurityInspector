import type { ApprovalView, EvidenceView, HostView, JobView, Page, RuleView } from "./types";

export type ConsoleSnapshot = {
  hosts: HostView[];
  jobs: JobView[];
  evidence: EvidenceView[];
  rules: RuleView[];
  approvals: ApprovalView[];
};

export async function fetchSnapshot(baseUrl: string, principal: string): Promise<ConsoleSnapshot> {
  const hostsPage = await getJSON<Page<HostView>>(baseUrl, "/v1/hosts?limit=20&offset=0", principal);
  const jobsPage = await getJSON<Page<JobView>>(baseUrl, "/v1/scans?limit=20&offset=0", principal);
  const jobs = Array.isArray(jobsPage.items) ? jobsPage.items.map(publicJob) : [];
  const hosts = Array.isArray(hostsPage.items) ? hostsPage.items.map(publicHost) : [];
  const evidence: EvidenceView[] = [];
  const rules: RuleView[] = [];
  for (const job of jobs) {
    const findings = await getJSON<{ findings: Page<FindingRow>; rule_results: RuleView[] }>(
      baseUrl,
      `/v1/scans/${encodeURIComponent(job.scan_id)}/findings?limit=20&offset=0`,
      principal
    );
    for (const finding of findings.findings.items ?? []) {
      for (const ref of finding.evidence_refs ?? []) {
        evidence.push({
          evidence_id: ref,
          scan_id: finding.scan_id,
          host_id: finding.host_id,
          module: "metadata",
          integrity_status: "unknown",
          title: finding.title
        });
      }
    }
    rules.push(...(findings.rule_results ?? []));
  }
  return { hosts, jobs, evidence, rules, approvals: [] as ApprovalView[] };
}

type FindingRow = {
  scan_id: string;
  host_id: string;
  title?: string;
  evidence_refs?: string[];
};

async function getJSON<T>(baseUrl: string, path: string, principal: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
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
  return (await response.json()) as T;
}

function publicHost(host: HostView): HostView {
  return {
    host_id: host.host_id,
    zone: host.zone,
    business_system: host.business_system,
    authorized: Boolean(host.authorized)
  };
}

function publicJob(job: JobView): JobView {
  return {
    scan_id: job.scan_id,
    host_id: job.host_id,
    status: job.status,
    collector_available: Boolean(job.collector_available),
    scan_ready: Boolean(job.scan_ready),
    limitations: job.limitations ?? []
  };
}
