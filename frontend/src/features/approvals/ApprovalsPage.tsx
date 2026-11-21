import { StatusBanner } from "../../shared/ui/StatusBanner";
import type { ApprovalView, PageStatus } from "../../shared/api/types";

export function ApprovalsPage({ status, approvals, detail }: { status: PageStatus; approvals: ApprovalView[]; detail: string }) {
  return (
    <section>
      <h1>Approvals</h1>
      <StatusBanner status={status} detail={detail} />
      <p>Requesting approval is not a grant. Operators cannot self-approve.</p>
      {approvals.map((item) => (
        <p key={item.request_id}>
          {item.request_id}: {item.status} · requester {item.requester_principal}
        </p>
      ))}
    </section>
  );
}
