import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "../src/app/App";
import { EvidencePage } from "../src/features/evidence/EvidencePage";
import { JobsPage } from "../src/features/jobs/JobsPage";
import { AssetsPage } from "../src/features/assets/AssetsPage";

describe("HostSec local console pages", () => {
  it("renders empty assets without inventing hosts", () => {
    render(<AssetsPage status="empty" hosts={[]} detail="No authorized hosts." />);
    expect(screen.getByTestId("status-banner")).toHaveTextContent("Empty");
    expect(screen.getByText(/No authorized hosts are visible/)).toBeInTheDocument();
  });

  it("renders forbidden state instead of hiding authorization", () => {
    render(<App initial={{ status: "forbidden", detail: "principal cannot see this zone", hosts: [], jobs: [], evidence: [], rules: [], approvals: [] }} />);
    expect(screen.getByTestId("status-banner")).toHaveTextContent("Forbidden");
  });

  it("renders untrusted evidence title as text rather than HTML", () => {
    render(
      <EvidencePage
        status="ready"
        detail="metadata only"
        items={[{ evidence_id: "ev-1", scan_id: "scan-1", host_id: "linux-test-001", module: "process", integrity_status: "verified", title: "<script>alert(1)</script>" }]}
      />
    );
    expect(screen.getByTestId("evidence-title-ev-1").textContent).toBe("<script>alert(1)</script>");
    expect(document.querySelector("script")).toBeNull();
  });

  it("does not treat a PARTIAL job as a clean bill of health", () => {
    render(
      <JobsPage
        status="partial"
        detail="fixture inspect is not live scanning"
        jobs={[
          {
            scan_id: "scan-local-1",
            host_id: "linux-test-001",
            status: "PARTIAL",
            collector_available: false,
            scan_ready: false,
            limitations: ["fixture inspect is not enterprise host scanning"]
          }
        ]}
      />
    );
    expect(screen.getByText(/not a clean bill of health/)).toBeInTheDocument();
    expect(screen.getByTestId("status-banner")).toHaveTextContent("Partial coverage");
  });

  it("renders an error state", () => {
    render(<App initial={{ status: "error", detail: "local API unavailable", hosts: [], jobs: [], evidence: [], rules: [], approvals: [] }} />);
    expect(screen.getByTestId("status-banner")).toHaveTextContent("Error");
  });
});
