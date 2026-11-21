import { StatusBanner } from "../../shared/ui/StatusBanner";
import type { JobView, PageStatus } from "../../shared/api/types";

export function JobsPage({ status, jobs, detail }: { status: PageStatus; jobs: JobView[]; detail: string }) {
  return (
    <section>
      <h1>Jobs</h1>
      <StatusBanner status={status} detail={detail} />
      {jobs.map((job) => (
        <article key={job.scan_id} data-testid={`job-${job.scan_id}`}>
          <p>
            {job.scan_id} · {job.status}
          </p>
          {job.scan_ready || job.collector_available ? (
            <p role="alert">Live scan flags must stay false in this local console.</p>
          ) : null}
          {job.status === "PARTIAL" ? <p>Coverage is partial; this is not a clean bill of health.</p> : null}
          <ul>
            {(job.limitations ?? []).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
      ))}
    </section>
  );
}
