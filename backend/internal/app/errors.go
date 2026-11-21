package app

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

const (
	CodeAuthDenied        = "AUTH_DENIED"
	CodeHostNotAuthorized = "HOST_NOT_AUTHORIZED"
	CodeApprovalRequired  = "APPROVAL_REQUIRED"
	CodePlanExpired       = "PLAN_EXPIRED"
	CodeSchema            = "SCHEMA_VALIDATION_FAILED"
	CodeToolNotInstalled  = "TOOL_NOT_INSTALLED"
	CodeCollectionPartial = "COLLECTION_PARTIAL"
	CodeAIProvider        = "AI_PROVIDER_ERROR"
	CodeNotFound          = "NOT_FOUND"
)

func fail(code, message string) *Error {
	return &Error{Code: code, Message: message}
}
