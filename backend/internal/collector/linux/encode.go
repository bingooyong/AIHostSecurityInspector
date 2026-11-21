package linux

import "encoding/json"

func toRecordMap(v any) (map[string]any, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
