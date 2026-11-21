export type PageStatus = "loading" | "empty" | "error" | "forbidden" | "ready" | "partial";

export type HostView = {
  host_id: string;
  zone: string;
  business_system: string;
  authorized: boolean;
};

export type JobView = {
  scan_id: string;
  host_id: string;
  status: string;
  collector_available: boolean;
  scan_ready: boolean;
  limitations: string[];
};

export type EvidenceView = {
  evidence_id: string;
  scan_id: string;
  host_id: string;
  module: string;
  integrity_status: string;
  title?: string;
};

export type RuleView = {
  rule_id: string;
  outcome: string;
  reason_code: string;
};

export type ApprovalView = {
  request_id: string;
  status: string;
  requester_principal: string;
};
