package domain

import "fmt"

// Stable validation codes. Messages must not echo raw secrets, argv, or host output.
const (
	CodeInvalidID                = "INVALID_ID"
	CodeInvalidStateTransition   = "INVALID_STATE_TRANSITION"
	CodeInvalidTimestamp         = "INVALID_TIMESTAMP"
	CodeUnknownEvidence          = "UNKNOWN_EVIDENCE"
	CodeCrossScopeReference      = "CROSS_SCOPE_REFERENCE"
	CodeEvidenceUnusable         = "EVIDENCE_UNUSABLE"
	CodeSchemaVersionUnsupported = "SCHEMA_VERSION_UNSUPPORTED"
	CodeInvalidEnum              = "INVALID_ENUM"
	CodeInvalidCanonical         = "INVALID_CANONICAL"
	CodeMissingBaseline          = "MISSING_BASELINE"
	CodeDuplicateID              = "DUPLICATE_ID"
	CodeInvalidReference         = "INVALID_REFERENCE"
)

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

func failf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
