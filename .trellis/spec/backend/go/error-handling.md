# Error handling

Return errors to callers; avoid panic for external input. Do not include raw config values, keys, full host output or process arguments in errors. Missing authorization, missing evidence and unavailable tools fail closed. UNKNOWN never becomes PASS. JSON results use stdout; diagnostics use structured stderr. Context cancellation propagates through module boundaries.
