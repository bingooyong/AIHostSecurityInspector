# HostSec fixture inspect report

- scan_id: scan-lab-001
- host_id: linux-box-lab-ssh-001
- profile: quick
- integrity: verified (source authenticity unverified)
- coverage: pass=0 fail=0 unknown=8 n/a=1 findings=0

## Limitations
- lab collection on an authorized loopback host only
- not enterprise host scanning
- doctor collector_available and scan_ready remain false
- local identity or local CA is not a platform IdP or production mTLS
- SSH transport used with strict known_hosts on loopback

## Rule results
- PROC-001 UNKNOWN evidence_unusable
- PROC-002 UNKNOWN evidence_unusable
- NET-001 UNKNOWN partial_not_enough_for_fail
- IAM-001 UNKNOWN partial_not_enough_for_fail
- PERS-001 UNKNOWN partial_not_enough_for_fail
- PERS-002 UNKNOWN evidence_unusable
- IAM-003 UNKNOWN evidence_unusable
- MAL-005 NOT_APPLICABLE profile_not_applicable
- CFG-001 UNKNOWN evidence_unusable

