import { StatusBanner } from "../../shared/ui/StatusBanner";
import type { EvidenceView, PageStatus } from "../../shared/api/types";

export function EvidencePage({ status, items, detail }: { status: PageStatus; items: EvidenceView[]; detail: string }) {
  return (
    <section>
      <h1>Evidence</h1>
      <StatusBanner status={status} detail={detail} />
      {items.map((item) => (
        <article key={item.evidence_id}>
          <p>{item.evidence_id}</p>
          <p data-testid={`evidence-title-${item.evidence_id}`}>{item.title ?? item.module}</p>
          <p>integrity {item.integrity_status}</p>
        </article>
      ))}
    </section>
  );
}
