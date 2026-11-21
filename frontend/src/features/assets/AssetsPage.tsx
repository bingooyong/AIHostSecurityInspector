import { StatusBanner } from "../../shared/ui/StatusBanner";
import type { HostView, PageStatus } from "../../shared/api/types";

export function AssetsPage({ status, hosts, detail }: { status: PageStatus; hosts: HostView[]; detail: string }) {
  return (
    <section>
      <h1>Assets</h1>
      <StatusBanner status={status} detail={detail} />
      {hosts.length === 0 ? (
        <p>No authorized hosts are visible to this principal.</p>
      ) : (
        <ul>
          {hosts.map((host) => (
            <li key={host.host_id}>
              {host.host_id} · zone {host.zone} · {host.business_system}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
