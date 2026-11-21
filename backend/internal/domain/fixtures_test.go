package domain

func sampleHash() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func sampleHashB() string {
	return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

func validIntent() ExecutionIntent {
	return ExecutionIntent{
		SchemaVersion:      IntentSchemaVersion,
		CanonicalVersion:   IntentCanonicalVersion,
		RequesterPrincipal: "operator-alice",
		HostIDs:            []string{"linux-test-001"},
		IdentityRefs:       []string{"identity-linux-test-001"},
		AssetSnapshotHash:  sampleHash(),
		PolicyID:           "hostsec-policy",
		PolicyVersion:      "1.0",
		PolicyHash:         sampleHashB(),
		Profile:            ProfileQuick,
		Modules:            []string{"host_identity", "process_inventory"},
		Tools:              []string{},
		AllowedPaths:       []string{},
		ExcludedPaths:      []string{"/proc", "/sys"},
		ExcludedMountTypes: []string{"nfs", "cifs"},
		Limits: IntentLimits{
			TimeoutSeconds:            900,
			MaxConcurrency:            2,
			MaxFiles:                  10000,
			MaxFileSizeBytes:          32 << 20,
			IOMaxBytesPerSecond:       10 << 20,
			StopOnResourcePressure:    true,
			MaintenanceWindowRequired: false,
		},
		RequiredCapabilities: []string{"linux_proc"},
		ValidFrom:            "2026-11-20T00:00:00Z",
		ValidUntil:           "2026-11-20T04:00:00Z",
		Mode:                 ModeReadOnly,
	}
}

func hashPtr(v string) *string { return &v }

func validEvidence() Evidence {
	return Evidence{
		EvidenceID:       "ev-process-1",
		HostID:           "linux-test-001",
		ScanID:           "scan-demo-1",
		AttemptID:        "attempt-demo-1",
		CollectedAt:      "2026-11-20T00:00:00Z",
		ReceivedAt:       "2026-11-20T00:00:01Z",
		Module:           "process_inventory",
		CollectorVersion: "fixture-only",
		Category:         "process",
		RawSummary:       "synthetic process list",
		RawRef:           nil,
		NormalizedData:   map[string]any{"count": 1},
		SHA256:           hashPtr(sampleHash()),
		NormalizedSHA256: hashPtr(sampleHashB()),
		CollectionStatus: CollectionSuccess,
		IntegrityStatus:  IntegrityVerified,
		Completeness:     CompletenessComplete,
		Warnings:         []string{},
	}
}

func failedEvidence() Evidence {
	ev := validEvidence()
	ev.EvidenceID = "ev-failed-1"
	ev.SHA256 = nil
	ev.NormalizedSHA256 = nil
	ev.CollectionStatus = CollectionFailed
	ev.IntegrityStatus = IntegrityUnavailable
	ev.Completeness = CompletenessUnavailable
	ev.Warnings = []string{"not collected"}
	ev.NormalizedData = map[string]any{}
	return ev
}

func validJob() ScanJob {
	return ScanJob{
		ScanID:             "scan-demo-1",
		RequesterPrincipal: "operator-alice",
		HostIDs:            []string{"linux-test-001"},
		Profile:            ProfileQuick,
		PlanHash:           sampleHash(),
		PolicyVersion:      "1.0",
		RuleBundleVersion:  "1.0",
		CollectorVersion:   "fixture-only",
		Status:             JobCompleted,
		CreatedAt:          "2026-11-20T00:00:00Z",
		StartedAt:          "2026-11-20T00:00:00Z",
		CompletedAt:        "2026-11-20T00:00:05Z",
		AIStatus:           AIDisabled,
	}
}

func validAttempt() ScanAttempt {
	return ScanAttempt{
		AttemptID: "attempt-demo-1",
		ScanID:    "scan-demo-1",
		HostID:    "linux-test-001",
		Status:    AttemptCompleted,
		StartedAt: "2026-11-20T00:00:00Z",
		EndedAt:   "2026-11-20T00:00:05Z",
		Transport: "local",
		Modules:   map[string]string{"process_inventory": CollectionSuccess},
	}
}

func validSnapshot() ScanSnapshot {
	zero := 0.0
	return ScanSnapshot{
		SchemaVersion: SchemaV1,
		Job:           validJob(),
		Attempts:      []ScanAttempt{validAttempt()},
		Evidence:      []Evidence{validEvidence()},
		RuleResults: []RuleResult{{
			RuleID:          "PROC-001",
			RuleVersion:     "1.0",
			ScanID:          "scan-demo-1",
			HostID:          "linux-test-001",
			Outcome:         OutcomePass,
			EvidenceRefs:    []string{"ev-process-1"},
			MissingEvidence: []string{},
			ReasonCode:      "MATCHED",
		}},
		Findings: []Finding{{
			FindingID:           "finding-demo-1",
			ScanID:              "scan-demo-1",
			HostID:              "linux-test-001",
			RuleID:              "PROC-001",
			RuleVersion:         "1.0",
			Category:            "process",
			Severity:            SeverityLow,
			Confidence:          70,
			Title:               "synthetic finding",
			Description:         "fixture only",
			EvidenceRefs:        []string{"ev-process-1"},
			RemediationGuidance: []string{},
			RequiresHumanReview: true,
			ReviewStatus:        ReviewNew,
		}},
		CollectionSummary: Coverage{TotalModules: 1, Succeeded: 1, Failed: 0, Skipped: 0, Coverage: &zero},
		Limitations:       []string{"synthetic domain fixture; no host was scanned"},
		HumanReview:       HumanReview{Status: "pending", Notes: []string{}},
	}
}
