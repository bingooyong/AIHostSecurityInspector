# HostSec fixture inspect report

- scan_id: scan-lab-001
- host_id: linux-box-lab-001
- profile: standard
- integrity: verified (source authenticity unverified)
- coverage: pass=0 fail=0 unknown=9 n/a=0 findings=0

## Limitations
- lab collection on an authorized loopback host only
- not enterprise host scanning
- doctor collector_available and scan_ready remain false
- local identity or local CA is not a platform IdP or production mTLS
- SSH transport was not used; collection was local filesystem

## Rule results
- PROC-001 UNKNOWN evidence_unusable
- PROC-002 UNKNOWN evidence_unusable
- NET-001 UNKNOWN partial_not_enough_for_fail
- IAM-001 UNKNOWN partial_not_enough_for_fail
- PERS-001 UNKNOWN partial_not_enough_for_fail
- PERS-002 UNKNOWN evidence_unusable
- IAM-003 UNKNOWN evidence_unusable
- MAL-005 UNKNOWN missing_trusted_baseline
- CFG-001 UNKNOWN evidence_unusable

