package domain

import "time"

const TimeLayout = time.RFC3339

func ParseUTC(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fail(CodeInvalidTimestamp, "timestamp is required")
	}
	parsed, err := time.Parse(TimeLayout, value)
	if err != nil {
		return time.Time{}, fail(CodeInvalidTimestamp, "timestamp must be RFC3339 UTC")
	}
	if !hasUTCOffsetZ(value) && !hasUTCOffsetZero(value) {
		return time.Time{}, fail(CodeInvalidTimestamp, "timestamp must be UTC")
	}
	return parsed.UTC(), nil
}

func hasUTCOffsetZ(v string) bool {
	return len(v) > 0 && v[len(v)-1] == 'Z'
}

func hasUTCOffsetZero(v string) bool {
	return len(v) >= 6 && (v[len(v)-6:] == "+00:00" || v[len(v)-6:] == "-00:00")
}

func requireOrder(earlier, later string, laterRequired bool) error {
	start, err := ParseUTC(earlier)
	if err != nil {
		return err
	}
	if later == "" {
		if laterRequired {
			return fail(CodeInvalidTimestamp, "end timestamp is required")
		}
		return nil
	}
	end, err := ParseUTC(later)
	if err != nil {
		return err
	}
	if end.Before(start) {
		return fail(CodeInvalidTimestamp, "timestamps are inverted")
	}
	return nil
}
