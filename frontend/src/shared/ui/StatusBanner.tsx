import type { PageStatus } from "../api/types";

export function StatusBanner({ status, detail }: { status: PageStatus; detail: string }) {
  return (
    <p role="status" data-testid="status-banner">
      {label(status)}: {detail}
    </p>
  );
}

function label(status: PageStatus): string {
  switch (status) {
    case "loading":
      return "Loading";
    case "empty":
      return "Empty";
    case "error":
      return "Error";
    case "forbidden":
      return "Forbidden";
    case "partial":
      return "Partial coverage";
    default:
      return "Ready";
  }
}
